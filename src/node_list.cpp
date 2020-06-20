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
#include <pthread.h>
#include "debug.h"
#include "astnetwork.h"
#include "name_service.h"
#include "head4sock.h"
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

//备份信息的变量
static string m_sdata2PC_bak,m_sdata2dev_bak;

//创建容器收集设备信息
vector<string> vdata_list;

//创建MAC-IP关系容器
vector<vector<string> > vmac_ip;

//创建收集PC信息的容器
vector<string> m_vpcdata;
vector<int> m_vpccode,m_vpcid;

//创建收集设备响应信息的容器
vector<string> m_vdevdata;
vector<int> m_vdevcode,m_vdevid,m_vdevres;

//发送给PC的json变量
static string m_sdata2PC;

//发送/接收设备的json变量
static string m_sdata2dev;
static string m_sdata_rcv;

//服务器与PC UDP连接的变量
static int fd_udp, on=1;
static struct sockaddr_in srvaddr;
static socklen_t len = sizeof(srvaddr);

//服务器与设备name_service UDP连接的变量
static int q_fd, r_fd;
struct sockaddr_in ndev_addr;
static socklen_t devaddr_len = sizeof(ndev_addr);

//服务器与设备dev_process UDP连接的变量
static int dev_fd;
struct sockaddr_in pdev_addr;
static socklen_t pdevaddr_len = sizeof(pdev_addr);

/***************时间函数***********************/

int message_timeid(void)
{
	static int time_id = 0;    //用于记录id前四位
	static int time_count = 0; //用于记录id最后一位，也是相同时间内信息条数
	
	int temp_id;
	
	time_t now = time(0);  //基于当前系统的当前时间
	tm *ltm = localtime(&now);
	temp_id = ltm->tm_min * 1000 + ltm->tm_sec * 10;
	
	if(temp_id == time_id)
	{
		++time_count;
		if(time_count > 10)
			time_count = 0;
	}
	else 
	{
		time_id = temp_id;
	}
	
	return (temp_id + time_count);
}


/*********设备信息结构体处理***********
顺序：
	device_name
	device_version
	device_mac
	ip_addr
	device_type
	
返回值：无
**************************************/
void _device_msg_deal(reply_struct * _reply, vector<string>& _vdata_deal, char *ip_addr)
{
	vector<string> msg;
	msg.clear();
	
	_vdata_deal.push_back(_reply->device_name);
	_vdata_deal.push_back(",");
	_vdata_deal.push_back(_reply->device_version);
	_vdata_deal.push_back(",");
	_vdata_deal.push_back(_reply->device_mac);
	_vdata_deal.push_back(",");
	msg.push_back(_reply->device_mac);
	_vdata_deal.push_back(ip_addr);
	_vdata_deal.push_back(",");
	msg.push_back(ip_addr);
	
	vmac_ip.push_back(msg);

	if(_reply->device_type == Type_Host)
		_vdata_deal.push_back("TX");
	else if(_reply->device_type == Type_Client)
		_vdata_deal.push_back("RX");
	else{
		perror("_device_msg_deal:");
		exit(1);
	}
	_vdata_deal.push_back(";");
	
}

/***************对设备返回数据进行JSON解析*********************/

void devparse_json(char *jsondata) {
	
		//创建解析对象进行解析
		Document doc;
		int tmp;
		
		if(!doc.Parse(jsondata).HasParseError())
		{
			//提取命令码
			if(doc.HasMember("actioncode"))
			{
				m_vdevcode.push_back(doc["actioncode"].GetInt());
			}
				
			//提取result
			if(doc.HasMember("result"))
			{
				m_vdevres.push_back(doc["result"].GetInt());
			}	
			
			//提取数据信息
			if(doc.HasMember("data"))
			{
				m_vdevdata.push_back(doc["data"].GetString());
			}
			
			//提取信息id
			if(doc.HasMember("msg_id"))
			{
				m_vdevid.push_back(doc["msg_id"].GetInt());
			}		
		}
}

/************服务器json封装函数响应设备*************
Srv_actioncode：命令码
data：携带的数据
msg_id： 五位id号

返回：无返回，直接用m_sdata2dev

***************************************************/
void data_packing_todev(int Srv_actioncode, int result, string data, int msg_id)
{
	Document doc;
	unsigned short crc_data = 0;
	Value s;
	
	m_sdata2dev.clear();
	s.SetString("");
	
	doc.SetObject();
	Document::AllocatorType &allocator = doc.GetAllocator();  //获取分配器
	
	doc.AddMember("actioncode", Srv_actioncode, allocator);
	doc.AddMember("device_name", "KVM_SERVER_9500", allocator);
	
	if(Srv_actioncode == COMMAND_REFUSE)
	{
		if(result == 400)
			doc.AddMember("result", 400, allocator);
		else
			doc.AddMember("result", 401, allocator);
			
		doc.AddMember("return_message", "command format error,please check it", allocator);
		doc.AddMember("data", "", allocator);
	}
	else
	{
		s = StringRef(data.c_str());
		doc.AddMember("data", s, allocator);   //需要将字符串另外处理，不然出问题
		doc.AddMember("msg_id", msg_id, allocator);
	}
	StringBuffer buffer;
	Writer<StringBuffer> writer(buffer);
	doc.Accept(writer);
	
	m_sdata2dev = buffer.GetString();
	//添加crc字段
	crc_data =crc16_ccitt((const unsigned char *)m_sdata2dev.data(), m_sdata2dev.length());
	m_sdata2dev += (crc_data >> 8);
	m_sdata2dev += (crc_data & 0x00FF);
	//添加结束符OxFF
	m_sdata2dev += 0xFF;
	
}

/******************dev_process请求***********************/

void Srv2dev_query(int Server_actioncode)
{
	int rcv_len = -1;
	int cycle;
	char json_data[512];
	char *parse_json_data;
	
	unsigned char crc = 0;

	//UDP连接
	dev_fd = Socket(AF_INET, SOCK_DGRAM, 0);
	
	bzero(&pdev_addr, pdevaddr_len);

	pdev_addr.sin_family = AF_INET;
	pdev_addr.sin_port = htons(atoi(AST_DEV_PROCESS_PORT));
	
	switch(Server_actioncode)
	{
		case Server_get_md5value:
			
			break;
		case Server_start_file_tran:
		
			break;
		case Server_update_device:
		
			break;
		case Server_write_md5Value:
		
			break;
		case Server_trigger_redled:
			memset(json_data, 0, sizeof(json_data));
			for(cycle = 0; cycle < vmac_ip.size(); cycle++)
			{
				if(m_vpcdata[0] == vmac_ip[cycle][0]){
					inet_pton(AF_INET, vmac_ip[cycle][1].data(), &pdev_addr.sin_addr);
					break;
				}
			}
			data_packing_todev(Server_trigger_redled, 0, m_vpcdata[0], message_timeid());
		
			sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
			while(1)
			{
				rcv_len = recvfrom(dev_fd, json_data, sizeof(json_data), 0, (struct sockaddr *)&pdev_addr, &pdevaddr_len);	
				if(rcv_len > 0)
				{
					printf("rcv_len:%d\n",rcv_len);
					parse_json_data = (char *)malloc(rcv_len);
					memset(parse_json_data, 0, rcv_len);
					strncpy(parse_json_data, json_data, rcv_len-3);
					devparse_json(parse_json_data);
					crc = ((unsigned char)json_data[rcv_len - 3]<<8)+(unsigned char)json_data[rcv_len - 2];
					if(0xff != (unsigned char)json_data[rcv_len - 1])
					{
						perror("end_mark");
						data_packing_todev(COMMAND_REFUSE, 404, "", message_timeid());
						sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
						continue;
					}
					if(!check(crc, (const unsigned char *)parse_json_data, rcv_len-3))
					{
						perror("crc check!");
						data_packing_todev(COMMAND_REFUSE, 401, "", message_timeid());
						sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
						continue;
					}
					if(m_vdevres[0] == 200)
						break;
						
					if(m_vdevres[0] == 400 || m_vdevres[0] == 401)
					{
						
					}
				}
				
			}
			break;
	}
	free(parse_json_data);
	close(dev_fd);	
}


/******************name_service请求（普通格式）*********************/

#define WAIT_REPLY_TIMEOUT 3
void do_query(AST_Device_Type device_type, AST_Device_Function device_function)
{
	struct timeval timeout;
	int ret = -1;
	fd_set	fds;
	
	query_struct query;
	reply_struct reply;
	
	char grp_addr[] = AST_NAME_SERVICE_GROUP_ADDR;
	
	q_fd = udp_create_sender();
	if (q_fd == -1) {
		exit(EXIT_FAILURE);
	}
	r_fd = udp_create_receiver(NULL, AST_NAME_SERVICE_REPLY_PORT);
	if (r_fd == -1) {
		close(q_fd);
		exit(EXIT_FAILURE);
	}
	//send out query
	memset(&ndev_addr, 0, sizeof(ndev_addr));
	ndev_addr.sin_family = AF_INET;
	ndev_addr.sin_addr.s_addr = inet_addr(grp_addr);
	ndev_addr.sin_port = htons(AST_NAME_SERVICE_QUERY_PORT);
	query.device_type = device_type;
	query.device_function = device_function;
	sendto(q_fd, &query, sizeof(query), 0, (struct sockaddr *)&ndev_addr, devaddr_len);
	FD_ZERO(&fds);
	FD_SET(r_fd, &fds);
	//receive until timeout & prepare list
	timeout.tv_usec = 0;
	timeout.tv_sec = WAIT_REPLY_TIMEOUT;
	info("IP\tHostname\tStatus\n");
	info(">>>>>\n");
	
	while (select(r_fd + 1, &fds, NULL, NULL, &timeout) > 0)
	{
		reply.device_mac[0] = '\0'; //fix rechive empty bug
		ret = recvfrom(r_fd, &reply, sizeof(reply), 0, (struct sockaddr *)&ndev_addr, &devaddr_len);
		printf("ret：%d\n",ret);
		if (ret == -1) {
			err("recvfrom error (%d)\n", errno);
			close(r_fd);
			close(q_fd);
			exit(EXIT_FAILURE);
		} else if (ret == 0) {
			err("peer shutdowned");
			break;
		} else {
			_device_msg_deal(&reply, vdata_list, inet_ntoa(ndev_addr.sin_addr));
			info("%s\t", inet_ntoa(ndev_addr.sin_addr));
			info("%s\t", reply.device_name);

//			info("device status: %d\n", reply.device_status);
			info("%s\t", reply.device_status);
			
			if (strlen(reply.device_mac) > 0)  
			{
				info("%s\t",reply.device_mac);
				info("%s",reply.device_version);
			} else {
				info("%s\t","Unknown");
				info("%s","Unknown");
			}
			info("\n");
			//info("--------------------------------------------------\n");
		}
	}
	if(vdata_list.size())
		vdata_list.pop_back();
	info("<<<<<\n");
	close(r_fd);
	close(q_fd);
	
}

/******************name_service请求（json格式）*********************/

static void do_query_json(AST_Device_Type device_type, AST_Device_Function device_function)
{
	struct timeval timeout;
	int ret = -1;
	fd_set	fds;
	
	query_struct query;
	reply_struct reply;
	char grp_addr[] = AST_NAME_SERVICE_GROUP_ADDR;
	int node_cnt = 0;
	
	q_fd = udp_create_sender();
	if (q_fd == -1) {
		exit(EXIT_FAILURE);
	}
	r_fd = udp_create_receiver(NULL, AST_NAME_SERVICE_REPLY_PORT);
	if (r_fd == -1) {
		close(q_fd);
		exit(EXIT_FAILURE);
	}
	//send out query
	memset(&ndev_addr, 0, sizeof(ndev_addr));
	ndev_addr.sin_family = AF_INET;
	ndev_addr.sin_addr.s_addr = inet_addr(grp_addr);
	ndev_addr.sin_port = htons(AST_NAME_SERVICE_QUERY_PORT);
	query.device_type = device_type;
	query.device_function = device_function;
	sendto(q_fd, &query, sizeof(query), 0, (struct sockaddr *)&ndev_addr, devaddr_len);
	FD_ZERO(&fds);
	FD_SET(r_fd, &fds);
	//receive until timeout & prepare list
	timeout.tv_usec = 0;
	timeout.tv_sec = WAIT_REPLY_TIMEOUT;
	info("{\n");
	while (select(r_fd + 1, &fds, NULL, NULL, &timeout) > 0)
	{
		reply.device_mac[0] = '\0';  //fix rechive empty bug
		ret = recvfrom(r_fd, &reply, sizeof(reply), 0, (struct sockaddr *)&ndev_addr, &devaddr_len);
		if (ret == -1) {
			err("recvfrom error (%d)\n", errno);
			close(r_fd);
			close(q_fd);
			exit(EXIT_FAILURE);
		} else if (ret == 0) {
			err("peer shutdowned");
			break;
		} else {
			if (node_cnt > 0) {
				info(",\n");
			}
			node_cnt++;
			
			_device_msg_deal(&reply, vdata_list, inet_ntoa(ndev_addr.sin_addr));
			// item name: == ip
			info("\"%s\":\n{\n", reply.device_name);
			// Start of data
			info("\t\"ip\":\"%s\",\n", inet_ntoa(ndev_addr.sin_addr));
			info("\t\"host_name\":\"%s\",\n", reply.device_name);
			info("\t\"status\":\"%s\",\n", reply.device_status);
			if (strlen(reply.device_mac) > 0) { 
			    info("\t\"is_host\":\"%s\",\n", (reply.device_type == Type_Host)?("y"):("n"));
				info("\t\"mac\":\"%s\",\n",reply.device_mac);
				info("\t\"version\":\"%s\"\n",reply.device_version);
			}
			info("\t\"is_host\":\"%s\"\n", (reply.device_type == Type_Host)?("y"):("n"));
			// End of data
			info("}");
			//info("--------------------------------------------------\n");
		}
	}
	if(vdata_list.size())
		vdata_list.pop_back();
	info("\n}\n");
	close(r_fd);
	close(q_fd);
	
}

void node_list(int argc, char *argv[])
{
	/*
	参数：
	-t host/client  类型

	-f usb/digital/analog

	-j json格式

	*/
	AST_Device_Type device_type = Type_Any;
	AST_Device_Function device_function = Function_Any;
	char *device_name;
	struct option longopts[] = {
		{"type",	required_argument,	NULL, 't'},
		{"function",	required_argument,	NULL, 'f'},
		{"json",	no_argument,	NULL, 'j'},
		{NULL,		0,		NULL,  0}
	};
	enum {
		cmd_query,
		cmd_query_json,
		cmd_help
	} cmd = cmd_query;

	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, "t:f:j", longopts, &index);

		if (c == -1)
			break;

		switch (c) {
			case 't':
				dbg("-t%s\n", optarg);
				if (strncmp(optarg, "host", 4) == 0)
					device_type = Type_Host;
				else if (strncmp(optarg, "client", 6) == 0)
					device_type = Type_Client;
				break;
			case 'f':
				dbg("-f%s\n", optarg);
				if (strncmp(optarg, "usb", 3) == 0)
					device_function = Function_USB;
				else if (strncmp(optarg, "digital", 7) == 0)
					device_function = Function_Digital;
				else if (strncmp(optarg, "analog", 6) == 0)
					device_function = Function_Analog;
				break;
			case 'j':
				cmd = cmd_query_json;
				break;
			case '?':
				cmd = cmd_help;
				break;
			default:
				err("getopt error (%d)\n", c);
		}
	}
	if (cmd == cmd_query || cmd == cmd_query_json)
	{
		dbg("device_type = %d\n", device_type);
		dbg("device_function = %d\n", device_function);
	}

#if 0
	set_signal();
#endif
	
	switch (cmd) {
		case cmd_query:
			do_query(device_type, device_function);
			break;
		case cmd_query_json:
			do_query_json(device_type, device_function);
			break;
		case cmd_help:
			break;
		default:
			err("unknown cmd\n");
	}
}

/***************对PC数据进行JSON解析*********************/

void parse_json(char *jsondata) {
	
		//创建解析对象进行解析
		Document doc;
		
		if(!doc.Parse(jsondata).HasParseError())
		{
			//提取命令码
			if(doc.HasMember("actioncode"))
			{
				m_vpccode.push_back(doc["actioncode"].GetInt());
			}
					
			//提取数据信息
			if(doc.HasMember("data"))
			{
				m_vpcdata.push_back(doc["data"].GetString());
			}
			
			//提取信息id
			if(doc.HasMember("msg_id"))
			{
				m_vpcid.push_back(doc["msg_id"].GetInt());
			}		
		}
}



/***************分割string字符串函数***********************/

void SplitString(const string& s, vector<string>& v, const string& c)
{
    string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while(string::npos != pos2)
    {
        v.push_back(s.substr(pos1, pos2-pos1));
         
        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if(pos1 != s.length())
        v.push_back(s.substr(pos1));
}


/************json封装函数发送给PC**************
pc_data :PC发送过来的data数据
user_actioncode：命令码
result：返回的结果（成功: 200; 失败: 406）
msg_id： 五位id号

返回：无返回，直接用m_sdata2PC

***********************************************/

void data_packing_toPC(string pc_data, int user_actioncode, int result, int msg_id)
{
	string data_log;
	Document doc;
	unsigned short crc_data = 0;
	Value s;
		
	m_sdata2PC.clear();
	data_log.clear();
	s.SetString("");
	
	doc.SetObject();
	Document::AllocatorType &allocator = doc.GetAllocator();  //获取分配器
	
	doc.AddMember("actioncode", user_actioncode, allocator);
	doc.AddMember("device_name", "KVM_SERVER_9500", allocator);
	switch(user_actioncode)  
	{
		case Server_return_login:
			if(result == 200)
			{
				doc.AddMember("result", 200, allocator);
				doc.AddMember("return_message", "pc login status message", allocator);
				doc.AddMember("data", "success", allocator);
			}
			else if(result == 406)
			{
				doc.AddMember("result", 406, allocator);
				doc.AddMember("return_message", "pc login status message", allocator);
				doc.AddMember("data", "failed", allocator);
			}
			break;
			
		case Server_return_logout:
			if(result == 200)
			{
				doc.AddMember("result", 200, allocator);
				doc.AddMember("return_message", "pc logout status message", allocator);
				doc.AddMember("data", "success", allocator);
			}
			else if(result == 406)
			{
				doc.AddMember("result", 406, allocator);
				doc.AddMember("return_message", "pc logout status message", allocator);
				doc.AddMember("data", "failed", allocator);
			}
			break;
			
		case Server_return_device_list:
			if(result == 200)
			{
				doc.AddMember("result", 200, allocator);
			}
			else if(result == 201)
			{
				doc.AddMember("result", 201, allocator);
			}
			doc.AddMember("return_message", "device list", allocator);
			for(int i = 0; i<vdata_list.size(); i++)
			{
				data_log += vdata_list[i];
			}
			data_log += '\0';
			s = StringRef(data_log.c_str());   //需要将字符串另外处理，不然出问题
			doc.AddMember("data", s, allocator);
			break;
		
		case Server_return_upload:
			doc.AddMember("result", 200, allocator);
			doc.AddMember("return_message", "firmware upload start", allocator);
			doc.AddMember("data", "", allocator);
			break;
			
		case Server_return_update:
			doc.AddMember("result", 200, allocator);
			doc.AddMember("return_message", "device update start", allocator);
			
			s = StringRef(pc_data.c_str());
			doc.AddMember("data", s, allocator);
			break;
			
		case Server_return_cancel_update:
			doc.AddMember("result", 200, allocator);
			doc.AddMember("return_message", "device update cancel", allocator);
			
			s = StringRef(pc_data.c_str());
			doc.AddMember("data", s, allocator);
			break;
			
		case Server_return_redled_reply:
			doc.AddMember("result", 200, allocator);
			doc.AddMember("return_message", "blink start/stop", allocator);

			s = StringRef(pc_data.c_str());
			doc.AddMember("data", s, allocator);
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
	
	m_sdata2PC = buffer.GetString();
	//添加crc字段
	crc_data =crc16_ccitt((const unsigned char *)m_sdata2PC.data(), m_sdata2PC.length());
	m_sdata2PC += (crc_data >> 8);
	m_sdata2PC += (crc_data & 0x00FF);
	//添加结束符OxFF
	m_sdata2PC += 0xFF;

}

/************获取文件*************/

void do_get(int fd_udp, struct sockaddr *sender, socklen_t *len, char *local_file)
{

	struct Transfer_packet tran_packet;
	int r_size = 0;
	
	memset(&tran_packet, 0, sizeof(tran_packet));
	FILE *fp = fopen(local_file, "w");
	if(fp == NULL){
		printf("Create file \"%s\" error.\n", local_file);
		return;
	}
	
	do{
		r_size = recvfrom(fd_udp, &tran_packet, sizeof(struct Transfer_packet), MSG_DONTWAIT, sender, len);
		
		if(r_size > 0 && r_size < 7){
			perror("do_get:");
			data_packing_toPC("", Server_return_upload, 404, m_vpcid[1]);
			sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, sender, *len);
		}
		else{
			fwrite(tran_packet.data, 1, r_size - 7, fp);
		}
	}while(r_size != -1);
	
	
}

/***********等待取消指令的线程****************/

void catch_sig(int sig)
{
	int sig_len,ret;
	char sig_json[512];
	char *sig_parse;
	
	printf("catch_sig\n");
	while(1)
	{
		memset(sig_json, 0, 512);
		m_vpccode.clear();
		m_vpcid.clear();
		m_vpcdata.clear();	
		sig_len = recvfrom(fd_udp, sig_json, sizeof(sig_json), 0, (struct sockaddr *)&srvaddr, &len);	

		printf("sig_len:%d\n",sig_len);
	
		sig_parse = (char *)malloc(sig_len);
		memset(sig_parse, 0, sig_len);
		strncpy(sig_parse, sig_json, sig_len-3);
		parse_json(sig_parse);
		
		if(m_vpccode[0] == PC_cancel_update)
		{
			on = 0;
			ret = ioctl(fd_udp, FIOASYNC, &on);  //工作在异步模式
			if(ret < 0)
			{
				perror("ioctl error\n");
				exit(-1);
			}
			break;
		}
		else
			continue;
	}
	free(sig_parse);
}

int main(int argc, char *argv[])
{
	/*
	步骤：
	1. 创建套接字，进行监听

	2. 判断最后一位是否为OxFF，是则crc校验数据包

	3. 通过自定义的数据包命令码执行不同操作

	*/
	int ret = -1;
	// 创建一个UDP套接字
	fd_udp = Socket(AF_INET, SOCK_DGRAM, 0);

	char recv_json[512];
	char *parse_json_data;
	int buf_len = 0,login_status = 0;
	unsigned short crc = 0;
	//md5检验储存
	char md5_str[MD5_STR_LEN + 1];
	
	//定义一个vector存储每个分割的字符串
	vector<string> v_Splitstr;

	// 绑定地址（IP:PORT）
	bzero(&srvaddr, len);

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(atoi(AST_CONNECT_PORT));
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//绑定本地IP和端口
	Bind(fd_udp, (struct sockaddr *)&srvaddr, len);

	//信号相关操作
	signal(SIGIO, catch_sig);   //注册信号
	ret = fcntl(fd_udp, F_SETOWN, getpid()); //设置SIGIO的属主
	if(ret < 0)  
	{
		perror("fcntl error!\n");
		exit(-1);
	}
	
	while(1)
	{
		memset(recv_json, 0, sizeof(recv_json));
		memset(md5_str, 0, MD5_STR_LEN + 1);
		
		v_Splitstr.clear();
		m_vpccode.clear();
		m_vpcid.clear();
		m_vpcdata.clear();

		buf_len = recvfrom(fd_udp, recv_json, sizeof(recv_json), 0, (struct sockaddr *)&srvaddr, &len);		
		printf("*********************************\n");
		printf("recv_json:%s\n",recv_json);
		if(buf_len > 0)
		{
			printf("buf_len:%d\n",buf_len);
			parse_json_data = (char *)malloc(buf_len);
			memset(parse_json_data, 0, buf_len);
			strncpy(parse_json_data, recv_json, buf_len-3);
			parse_json(parse_json_data);
			crc = ((unsigned char)recv_json[buf_len - 3]<<8)+(unsigned char)recv_json[buf_len - 2];
			if(0xff != (unsigned char)recv_json[buf_len - 1])
			{
				perror("end_mark");
				data_packing_toPC("", COMMAND_REFUSE, 404, m_vpcid[0]);
				sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
				continue;
			}
			if(!check(crc, (const unsigned char *)parse_json_data, buf_len-3))
			{
				perror("crc check!");
				data_packing_toPC("", COMMAND_REFUSE, 401, m_vpcid[0]);
				sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
				continue;
			}
			SplitString(m_vpcdata[0], v_Splitstr, ","); //按逗号来分割字符串
			switch(m_vpccode[0])
			{
				//登录服务器
				case  PC_login:
					if((AST_SERVER_UASE_NAME == v_Splitstr[0])  && (v_Splitstr[1] == AST_SERVER_PASSWORD)){
							login_status = 1;
							data_packing_toPC("", Server_return_login, 200, m_vpcid[0]);										
					}
					else{
							data_packing_toPC("", Server_return_login, 406, m_vpcid[0]);					
					}	
					printf("m_sdata2PC.data():%s\n",m_sdata2PC.data());
					m_sdata2PC_bak.assign(m_sdata2PC);
					sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
					break;
					
				//注销登录
				case PC_logout:
					if((AST_SERVER_UASE_NAME == v_Splitstr[0])  && (v_Splitstr[1] == AST_SERVER_PASSWORD))
					{
							login_status = 0;
							data_packing_toPC("", Server_return_logout, 200, m_vpcid[0]);					
					}
					else{
							data_packing_toPC("", Server_return_logout, 406, m_vpcid[0]);				
					}		
					m_sdata2PC_bak.assign(m_sdata2PC);
					sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
					break;
					
				//获取设备信息
				case PC_device_list:
					if(login_status){
						vdata_list.clear();
						vmac_ip.clear();
						//先请求获得长时间
						data_packing_toPC("", Server_return_device_list, 201, m_vpcid[0]);
						m_sdata2PC_bak.assign(m_sdata2PC);
						sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
						//接收获取设备信息的命令，执行node_list
						node_list(argc, argv);
						
						data_packing_toPC("", Server_return_device_list, 200, m_vpcid[0]);
						m_sdata2PC_bak.assign(m_sdata2PC);
						sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
					}
					break;

				//更新设备
				case PC_update_device:
				
					if(login_status && !vdata_list.empty()){
						ret = ioctl(fd_udp, FIOASYNC, &on);  //工作在异步模式
						if(ret < 0)
						{
							perror("ioctl error\n");
							exit(-1);
						}
						
						while(on)
						{
							//检验文件MD5
							ret = Compute_file_md5(AST_FILE_NAME, md5_str);
							if (0 == ret)
							{
								printf("[file - %s] md5 value:\n", AST_FILE_NAME);
								printf("%s\n", md5_str);
							}
							//向设备获取MD5值
							//data_packing_todev(Server_get_md5value, (const char *)"", message_timeid());
							//sendto(qdev_fd, &m_sdata2dev, sizeof(m_sdata2dev), 0, (struct sockaddr *)&ndev_addr, devaddr_len);
							
							//等待接收
							//recvfrom(rdev_fd, &m_sdata_rcv, sizeof(m_sdata_rcv), 0, (struct sockaddr *)&ndev_addr, &devaddr_len);
							//devparse_json();
							//比较后一致，不升级，反之发送指令升级
						}	
					}
					break;
				//取消更新
				case PC_cancel_update:
					if(login_status && !vdata_list.empty()){
					
					}
					break;
				//固件上传
				case PC_firmware_upload:	
					if(login_status && !vdata_list.empty()){
						data_packing_toPC(m_vpcdata[0], Server_return_upload, 200, m_vpcid[0]);
						m_sdata2PC_bak.assign(m_sdata2PC);
						sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
								
						do_get(fd_udp, (struct sockaddr *)&srvaddr, &len, AST_FILE_NAME);
							
					}
					break;
				//触发灯操作
				case PC_redled_blink_trigger:
					if(login_status && !vdata_list.empty()){
						Srv2dev_query(Server_trigger_redled);
						
						data_packing_toPC(m_vpcdata[0], Server_return_redled_reply, 200, m_vpcid[1]);
						m_sdata2PC_bak.assign(m_sdata2PC);	
						sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
					}
					break;
				
				//接收到错误
				case COMMAND_REFUSE:
					sendto(fd_udp, m_sdata2PC_bak.data(), m_sdata2PC_bak.length(), 0, (struct sockaddr *)&srvaddr, len);
					break;
			}
			
			free(parse_json_data);
		}		
	}

	close(fd_udp);

	return 0;
}

