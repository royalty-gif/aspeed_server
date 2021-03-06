/*
 * Copyright (c) 2004-2012
 * ASPEED Technology Inc. All Rights Reserved
 * Proprietary and Confidential
 *
 * By using this code you acknowledge that you have signed and accepted
 * the terms of the ASPEED SDK license agreement.
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <sched.h>
#include "debug.h"
#include "astnetwork.h"
#include "dev_process.h"
#include <arpa/inet.h>
#include "crc16.h"
#include "md5.h"
#include "head4sock.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include <iostream>
#include <string>
#include <vector>
#include <ctime>

using namespace std;
using namespace rapidjson;

//记录灯的状态变量
static int led_status = 0;

//备份一份发送信息
string m_sdata2Srv_bak;

//md5值
char md5_data[128];

//创建收集服务器信息的容器
vector<string> m_vsrvdata;
vector<int> m_vsrvcode,m_vsrvid;

//发送给服务器的json变量
string m_sdata2Srv;

//UDP连接变量
static int fd = 0;
struct sockaddr_in addr;
static socklen_t addr_len = sizeof(addr);

/* 和校验：接收方调用,将所有的数据累加之后(溢出丢弃) 加一.返回值 */
unsigned char RX_CheckSum(unsigned char *buf, int len) //buf为数组，len为数组长度
{
    int i;
    unsigned char ret = 0;

    for(i=0; i<len; i++)
    {
        ret += *(buf++);
    }
    return ret + 1;
}

/*****************从服务器上获取文件*************/

void do_get(void)
{
	static int package_num = 0;  //每个包编号
	int tmp_packnum = 0;
	
	char tran_status; //记录传输状态
	int time_wait_data;
	struct Transfer_packet Recv_packet;
	struct Transfer_packet Send_packet = {AST_CHECK_CODE,AST_PRO_CODE,0x0000,AST_EX_FILED,};
	
	FILE *get_fp = NULL;
	memcpy(&Recv_packet, &Send_packet, sizeof(struct Transfer_packet));
	int r_size = 0;
	unsigned short data_len = 0;
	unsigned char rcv_crc = 0;
	
	
	get_fp = fopen(AST_FILE_NAME, "w");
	if(get_fp == NULL){
		printf("Create file \"%s\" error.\n", AST_FILE_NAME);
		return;
	}

	while(1){
		
		for(time_wait_data = 0; time_wait_data < PKT_RCV_TIMEOUT * PKT_MAX_RXMT; time_wait_data += 10000){
			r_size = recvfrom(fd, &Recv_packet, sizeof(struct Transfer_packet), MSG_DONTWAIT, (struct sockaddr *)&addr, &addr_len);
		
			if(r_size > 0 && r_size < 12) //数据包不足12
			{
				printf("Bad packet:%d\n",r_size);
				Send_packet.packet_head.ex_data[0] = AST_CHECK_FAILED;
				sendto(fd, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&addr, addr_len);
			}
			
			if(r_size >= 12){
				break;
			}
			
			usleep(10000);
		}
		
		if(time_wait_data >= PKT_RCV_TIMEOUT * PKT_MAX_RXMT)  //超时
		{
			printf("Wait for DATA timeout.\n");
			remove(AST_FILE_NAME);
			goto do_get_error;
		}
		else{
			printf("Recv_packet.packet_head.ex_data[0]:%#x\n",Recv_packet.packet_head.ex_data[0]);
			switch(Recv_packet.packet_head.ex_data[0])
			{
				case AST_START_TRAN:  //文件开始传输指令
					tran_status = 1;

					Send_packet.packet_head.ex_data[0] = AST_REPLY_START_TRAN;
					sendto(fd, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&addr, addr_len);
					break;
					
				case AST_WDATA:  // 写数据指令
					if(tran_status)
					{
						//记录包的编号
						tmp_packnum = (Recv_packet.packet_head.ex_data[1] << 16) +  
											(Recv_packet.packet_head.ex_data[2] << 8) + 
											Recv_packet.packet_head.ex_data[3];
						
						//记录包的大小
						data_len = ntohs(Recv_packet.packet_head.data_len);
						printf("tmp_packnum:%d\n",tmp_packnum);
						printf("data_len:%d\n",(unsigned short)data_len);				
						//数据校验
						rcv_crc = RX_CheckSum(Recv_packet.data, data_len);
						
						printf("rcv_crc:%#x\n",rcv_crc);
						if((unsigned char)(rcv_crc + Recv_packet.packet_head.ex_data[4]) == 0){
						
							if(tmp_packnum != package_num){  //判断是否为同一个包
								fwrite(Recv_packet.data, 1, r_size - 12, get_fp);
								package_num = tmp_packnum;
							}
							
							Send_packet.packet_head.ex_data[0] = AST_REPLY_WDATA;
							sendto(fd, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&addr, addr_len);
							
							
						}
						else{
							perror("checksum error");
							Send_packet.packet_head.ex_data[0] = AST_CHECK_FAILED;
							Send_packet.packet_head.ex_data[1] = package_num >> 16;
							Send_packet.packet_head.ex_data[2] = (package_num >> 8) & 0x00FF;
							Send_packet.packet_head.ex_data[3] = package_num & 0x0000FF;
							sendto(fd, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&addr, addr_len);
						}
					}
					break;
				
				case AST_CANCEL_TRAN: //取消数据传输的指令
					tran_status = 0;
					remove(AST_FILE_NAME);
					Send_packet.packet_head.ex_data[0] = AST_REPLY_CANCEL_TRAN;
					sendto(fd, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&addr, addr_len);
					break;
					
				case AST_END_TRAN:  //完成数据传输
					if(tran_status){
						
						Send_packet.packet_head.ex_data[0] = AST_REPLY_END_TRAN;
						sendto(fd, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&addr, addr_len);
					}
					break;
			
			}
		}
		
		if(Recv_packet.packet_head.ex_data[0] == AST_CANCEL_TRAN || 
				 Recv_packet.packet_head.ex_data[0] == AST_END_TRAN){
			break;
		}
	}
do_get_error:
	fclose(get_fp);
	
}



/************json封装函数发送给server**************
pc_data :PC发送过来的data数据
user_actioncode：命令码
result：返回的结果（成功: 200; 失败: 406）
msg_id： 五位id号

返回：无返回，直接用m_sdata2PC

*************************************************/

void data_packing_toSrv(int user_actioncode, int result, int msg_id)
{
	Document doc;
	unsigned short crc_data = 0;
	Value s;
	string data_log;
	FILE *fp = NULL;
		
	m_sdata2Srv.clear();
	data_log.clear();
	memset(md5_data, 0, sizeof(md5_data));
	s.SetString("");
	
	doc.SetObject();
	Document::AllocatorType &allocator = doc.GetAllocator();  //获取分配器
	
	doc.AddMember("actioncode", user_actioncode, allocator);
	doc.AddMember("device_name", "KVM_TX_9506", allocator);
	switch(user_actioncode)  
	{
		case Dev_reply_md5Value:
			
			doc.AddMember("result", 200, allocator);
			doc.AddMember("return_message", "md5 value", allocator);
			
			fp = popen("astparam g md5", "r");
			if(fp == NULL)
			{
				printf("popen error!\n");
				exit(-1);
			}
			while(fgets(md5_data, sizeof(md5_data), fp) != NULL)
			{
				if(!strncmp(md5_data, "\"md5\"", 5))
					doc.AddMember("data", "", allocator);
				else{
					data_log = md5_data;
					s = StringRef(data_log.c_str());
					doc.AddMember("data", s, allocator);
				}
				break;
			}
			break;
			
		case Dev_ready_filercv:
			if(result == 200)
			{
				doc.AddMember("result", 200, allocator);
				doc.AddMember("return_message", "file receive ready", allocator);
				doc.AddMember("data", "", allocator);
			}

			break;
			
		case Dev_update_start:
			if(result == 200)
			{
				doc.AddMember("result", 200, allocator);
				doc.AddMember("return_message", "device update start", allocator);
				doc.AddMember("data", "", allocator);
			}
			break;
		
		case Dev_update_end:
			doc.AddMember("data", "", allocator);
			break;
			
		case Dev_reply_wmd5Value:
			if(result == 200)
			{
				doc.AddMember("result", 200, allocator);
				doc.AddMember("return_message", "MD5 value write success", allocator);
				doc.AddMember("data", "success", allocator);
			}
			break;
			
		case Dev_online:
			doc.AddMember("data", "", allocator);
			
		case Dev_blink_redled_done:
			if(result == 200)
			{
				doc.AddMember("result", 200, allocator);
				
				if(led_status)
					doc.AddMember("return_message", "blink redled success", allocator);
				else 
					doc.AddMember("return_message", "stop redled success", allocator);
					
				doc.AddMember("data", "", allocator);
			}
			break;
			
		case COMMAND_REFUSE:
			if(result == 400)
				doc.AddMember("result", 400, allocator);
			else
				doc.AddMember("result", 401, allocator);
				
			doc.AddMember("return_message", "command format error,please check it", allocator);
			doc.AddMember("data", "", allocator);
			break;
	}
	doc.AddMember("msg_id", msg_id, allocator);
	
	StringBuffer buffer;
	Writer<StringBuffer> writer(buffer);
	doc.Accept(writer);
	
	m_sdata2Srv = buffer.GetString();
	//添加crc字段
	crc_data =crc16_ccitt((const unsigned char *)m_sdata2Srv.data(), m_sdata2Srv.length());
	m_sdata2Srv += (crc_data >> 8);
	m_sdata2Srv += (crc_data & 0x00FF);
	//添加结束符OxFF
	m_sdata2Srv += 0xFF;

}

/***************对服务器数据进行JSON解析*********************/

void parse_json(char *jsondata) {
	
		//创建解析对象进行解析
		Document doc;
		
		if(!doc.Parse(jsondata).HasParseError())
		{
			//提取命令码
			if(doc.HasMember("actioncode"))
			{
				m_vsrvcode.push_back(doc["actioncode"].GetInt());
			}
					
			//提取数据信息
			if(doc.HasMember("data"))
			{
				m_vsrvdata.push_back(doc["data"].GetString());
			}
			
			//提取信息id
			if(doc.HasMember("msg_id"))
			{
				m_vsrvid.push_back(doc["msg_id"].GetInt());
			}		
		}
}

int main(int argc, char*argv[])
{
	int buf_len = 0;
	unsigned short crc = 0;
	
	char recv_json[512];
	char *parse_json_data;

	//UDP连接
	fd = Socket(AF_INET, SOCK_DGRAM, 0);
	
	bzero(&addr, addr_len);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(AST_DEV_PROCESS_PORT));
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	Bind(fd, (struct sockaddr *)&addr, addr_len);

	while(1)
	{
		memset(md5_data, 0, sizeof(md5_data));
		memset(recv_json, 0, sizeof(recv_json));
		m_vsrvcode.clear();
		m_vsrvid.clear();
		m_vsrvdata.clear();
		
		buf_len = recvfrom(fd, &recv_json, sizeof(recv_json), 0, (struct sockaddr *)&addr, &addr_len);
		printf("buf_len:%d\n",buf_len);
		printf("recv_json:%s\n",recv_json);
		
		if(buf_len == -1 || buf_len == 0)
		{
			perror("recvfrom error!\n");
			sched_yield();
			continue;
		}
		else{
			printf("buf_len:%d\n",buf_len);
			parse_json_data = (char *)malloc(buf_len);
			memset(parse_json_data, 0, buf_len);
			strncpy(parse_json_data, recv_json, buf_len-3);
			parse_json(parse_json_data);
			crc = ((unsigned char)recv_json[buf_len - 3]<<8)+(unsigned char)recv_json[buf_len - 2];
			printf("crc:%d\n",crc);
			if(0xff != (unsigned char)recv_json[buf_len - 1])
			{
				perror("end_mark");
				data_packing_toSrv(COMMAND_REFUSE, 404, m_vsrvid[0]);
				sendto(fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
				continue;
			}
			if(!check(crc, (const unsigned char *)parse_json_data, buf_len-3))
			{
				perror("crc check!");
				data_packing_toSrv(COMMAND_REFUSE, 401, m_vsrvid[0]);
				sendto(fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
				continue;
			}
			
			switch(m_vsrvcode[0])
			{
				//返回MD5值
				case Server_get_md5value:
					data_packing_toSrv(Dev_reply_md5Value, 200, m_vsrvid[0]);
					m_sdata2Srv_bak.assign(m_sdata2Srv);	
					sendto(fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
					break;
				
				//启动接收固件	
				case Server_start_file_tran:
					data_packing_toSrv(Dev_ready_filercv, 200, m_vsrvid[0]);
					m_sdata2Srv_bak.assign(m_sdata2Srv);
					sendto(fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
					system("/usr/local/bin/ast_send_event -1 e_stop_link");
					
					//文件传输操作
					do_get();
					
					break;
					
				//开始设备升级	
				case Server_update_device:
					data_packing_toSrv(Dev_update_start, 200, m_vsrvid[0]);
					m_sdata2Srv_bak.assign(m_sdata2Srv);
					sendto(fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
					
					//升级过程
					system("/update.sh");
					//设备升级完成
					data_packing_toSrv(Dev_update_end, 200, m_vsrvid[0]);
					m_sdata2Srv_bak.assign(m_sdata2Srv);
					sendto(fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
					
					break;
					
				//写入MD5值	
				case Server_write_md5Value:
				{
					string write_str = "astparam s md5 " + m_vsrvdata[0];
					
					write_str.copy(md5_data, write_str.size(), 0);
					system(md5_data);
					system("astparam save");
	
					data_packing_toSrv(Dev_reply_wmd5Value, 200, m_vsrvid[0]);
					m_sdata2Srv_bak.assign(m_sdata2Srv);
					sendto(fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
					break;
				}
				
				//闪烁红灯(√)
				case Server_trigger_redled:
					if(!led_status){
						system("echo timer > /sys/class/leds/led_pwr/trigger");
						led_status = 1;
					}
					else{
						system("echo none > /sys/class/leds/led_pwr/trigger");
						system("echo 1 > /sys/class/leds/led_pwr/brightness");
						led_status = 0;
					}
					data_packing_toSrv(Dev_blink_redled_done, 200, m_vsrvid[0]);
					m_sdata2Srv_bak.assign(m_sdata2Srv);
					sendto(fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
					break;
				
				//接收到错误
				case COMMAND_REFUSE:
					sendto(fd, m_sdata2Srv_bak.data(), m_sdata2Srv_bak.length(), 0, (struct sockaddr *)&addr, addr_len);
			}
		}
		free(parse_json_data);
	}
	close(fd);
	return 0;
}

