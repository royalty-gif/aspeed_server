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
#include <getopt.h>
#include <signal.h>
#include <sched.h>
#include "debug.h"
#include "astnetwork.h"
#include "dev_process.h"
#include <arpa/inet.h>
#include "crc16.h"
#include "md5.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include <iostream>
#include <string>
#include <vector>
#include <ctime>

using namespace std;
using namespace rapidjson;


//创建收集服务器信息的容器
vector<string> m_vsrvdata;
vector<int> m_vsrvcode,m_vsrvid;

//发送给服务器的json变量
string m_sdata2Srv;

//UDP连接变量
static int q_fd, r_fd;
struct sockaddr_in addr;
static socklen_t addr_len = sizeof(addr);

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
		
	m_sdata2Srv.clear();
	s.SetString("");
	
	doc.SetObject();
	Document::AllocatorType &allocator = doc.GetAllocator();  //获取分配器
	
	doc.AddMember("actioncode", user_actioncode, allocator);
	doc.AddMember("device_name", "KVM_TX_9506", allocator);
	switch(user_actioncode)  
	{
		case Dev_reply_md5Value:
			if(result == 200)
			{
				doc.AddMember("result", 200, allocator);
				doc.AddMember("return_message", "md5 value", allocator);
				doc.AddMember("data", "success", allocator);
			}
			else if(result == 100)  //无MD5的情况
			{
				doc.AddMember("result", 100, allocator);
				doc.AddMember("return_message", "md5 value", allocator);
				doc.AddMember("data", "", allocator);
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
				doc.AddMember("return_message", "blink redled success", allocator);
				doc.AddMember("data", "", allocator);
			}
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
	unsigned char crc = 0;
	char grp_addr[] = AST_NAME_SERVICE_GROUP_ADDR;
	
	char recv_json[512];
	char *parse_json_data;
	//UDP连接
	q_fd = udp_create_receiver(grp_addr, AST_DEV_PROCESS_QUERY_PORT);
	if (q_fd == -1) {
		exit(EXIT_FAILURE);
	}
	r_fd = udp_create_sender();
	if (r_fd == -1) {
		close(q_fd);
		exit(EXIT_FAILURE);
	}
	
	addr.sin_port = htons(AST_DEV_PROCESS_REPLY_PORT);
	while(1)
	{
		memset(recv_json, 0, sizeof(recv_json));
		m_vsrvcode.clear();
		m_vsrvid.clear();
		m_vsrvdata.clear();
		
		buf_len = recvfrom(q_fd, &recv_json, sizeof(recv_json), 0, (struct sockaddr *)&addr, &addr_len);
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
			if(0xff != (unsigned char)recv_json[buf_len - 1])
			{
				perror("end_mark");
				data_packing_toSrv(m_vsrvcode[0], 404, m_vsrvid[0]);
				sendto(r_fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
				continue;
			}
			if(!check(crc, (const unsigned char *)parse_json_data, buf_len-3))
			{
				perror("crc check!");
				data_packing_toSrv(m_vsrvcode[0], 401, m_vsrvid[0]);
				sendto(r_fd, m_sdata2Srv.data(), m_sdata2Srv.length(), 0, (struct sockaddr *)&addr, addr_len);
				continue;
			}
			
			switch(m_vsrvcode[0])
			{
				//返回MD5值
				case Server_get_md5value:
					
					break;
				
				//启动接收固件	
				case Server_start_file_tran:
				
					break;
					
				//开始设备升级	
				case Server_update_device:
				
					break;
					
				//写入MD5值	
				case Server_write_md5Value:
				
					break;
					
				//闪烁红灯	
				case Server_trigger_redled:
					break;
				
			}
		}
	}
	
	close(r_fd);
	close(q_fd);
	return 0;
}

