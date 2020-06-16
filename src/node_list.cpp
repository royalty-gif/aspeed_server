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


//创建一个容器收集设备信息
vector<string> vdata_list;

static string tmp_data;

#if 0
static void signal_handler(int i)
{
	dbg("signal catched, code %d", i);
}

static void set_signal(void)
{
	struct sigaction act;

	bzero(&act, sizeof(act));
	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
}
#endif

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
	_vdata_deal.push_back(_reply->device_name);
	_vdata_deal.push_back(_reply->device_version);
	_vdata_deal.push_back(_reply->device_mac);
	_vdata_deal.push_back(ip_addr);

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

#define WAIT_REPLY_TIMEOUT 3
void do_query(AST_Device_Type device_type, AST_Device_Function device_function)
{
	int q_fd, r_fd;
	struct timeval timeout;
	int ret = -1;
	fd_set	fds;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
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
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(grp_addr);
	addr.sin_port = htons(AST_NAME_SERVICE_QUERY_PORT);
	query.device_type = device_type;
	query.device_function = device_function;
	sendto(q_fd, &query, sizeof(query), 0, (struct sockaddr *)&addr, addr_len);
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
		ret = recvfrom(r_fd, &reply, sizeof(reply), 0, (struct sockaddr *)&addr, &addr_len);
		if (ret == -1) {
			err("recvfrom error (%d)\n", errno);
			close(r_fd);
			close(q_fd);
			exit(EXIT_FAILURE);
		} else if (ret == 0) {
			err("peer shutdowned");
			break;
		} else {
		
			_device_msg_deal(&reply, vdata_list, inet_ntoa(addr.sin_addr));
			info("%s\t", inet_ntoa(addr.sin_addr));
			info("%s\t", reply.device_name);
#if 0
			dbg("device_type = %d\n", reply.device_type);
			switch (reply.device_type)
			{
			case Type_Host:
				info("type:H\n");
				break;
			case Type_Client:
				info("type:C\n");
				break;
			default:
				info("type:X\n");
			}
#endif
#if 0
			dbg("device_function = %d\n", reply.device_function);
			switch (reply.device_function)
			{
			case Function_USB:
				info("function:U\n");
				break;
			case Function_Digital:
				info("function:D\n");
				break;
			case Function_Analog:
				info("function:A\n");
				break;
			default:
				info("function:X\n");
			}
#endif
//			info("device status: %d\n", reply.device_status);
			info("%s", reply.device_status);
			
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
	
	vdata_list.pop_back();
	info("<<<<<\n");
	close(r_fd);
	close(q_fd);
	exit(EXIT_SUCCESS);
}


static void do_query_json(AST_Device_Type device_type, AST_Device_Function device_function)
{
	int q_fd, r_fd;
	struct timeval timeout;
	int ret = -1;
	fd_set	fds;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
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
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(grp_addr);
	addr.sin_port = htons(AST_NAME_SERVICE_QUERY_PORT);
	query.device_type = device_type;
	query.device_function = device_function;
	sendto(q_fd, &query, sizeof(query), 0, (struct sockaddr *)&addr, addr_len);
	FD_ZERO(&fds);
	FD_SET(r_fd, &fds);
	//receive until timeout & prepare list
	timeout.tv_usec = 0;
	timeout.tv_sec = WAIT_REPLY_TIMEOUT;
	info("{\n");
	while (select(r_fd + 1, &fds, NULL, NULL, &timeout) > 0)
	{
		reply.device_mac[0] = '\0';  //fix rechive empty bug
		ret = recvfrom(r_fd, &reply, sizeof(reply), 0, (struct sockaddr *)&addr, &addr_len);
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
			
			_device_msg_deal(&reply, vdata_list, inet_ntoa(addr.sin_addr));
			// item name: == ip
			info("\"%s\":\n{\n", reply.device_name);
			// Start of data
			info("\t\"ip\":\"%s\",\n", inet_ntoa(addr.sin_addr));
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
	vdata_list.pop_back();
	info("\n}\n");
	close(r_fd);
	close(q_fd);
	exit(EXIT_SUCCESS);
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

/***************JSON解析***********************/

PC_data_struct parse_json(char *jsondata) {
	PC_data_struct ret;
	
	//创建解析对象进行解析
	Document doc;
	if(!doc.Parse(jsondata).HasParseError())
	
	{
	
		//json格式内容
		if(doc.HasMember("_json"))
		{
			const rapidjson::Value& object = doc["_json"];
			
			//提取命令码
			if(object.HasMember("user_actioncode"))
			{
				ret._json.user_actioncode = object["user_actioncode"].GetInt();
			}
			
			//提取设备名
			if(object.HasMember("device_name"))
			{
				ret._json.device_name = object["device_name"].GetString();
			}
			
			//提取数据信息
			if(doc.HasMember("data_log"))
			{
				ret._json.data_log = object["data_log"].GetString();
			}
			
			//提取信息id
			if(object.HasMember("msg_id"))
			{
				ret._json.msg_id = object["msg_id"].GetInt();
			}
		}
	}

	return ret;
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

/***************时间函数***********************/

int message_timeid(void)
{
	static int time_id = 0;    //用于记录id前四位
	static int time_count = 0; //用于记录id最后一位，也是相同时间内信息条数
	
	int temp_id = 0;
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
	
	return (temp_id * 10 + time_count);
}

/************json封装函数响应PC*************
user_actioncode：命令码
result：返回的结果（成功: 200; 失败: 406）

返回：无返回，直接用tmp_data

*******************************************/

void data_packing_toPC(PC_data_struct *pc_data, int user_actioncode, int result)
{

	PC_resdata_struct data_package; 
	string data_log;
	Document doc;
	unsigned short crc_data = 0;
	Value s;
		
	memset(&data_package, 0, sizeof(data_package));
	tmp_data.clear();
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
			doc.AddMember("result", 200, allocator);
			doc.AddMember("return_message", "device list", allocator);
			for(int i = 0; i<vdata_list.size(); i++)
			{
				data_log += vdata_list[i];
			}
			data_log += '\0';
			s = StringRef(data_log.c_str());
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
			
			data_log = pc_data->_json.data_log;
			s = StringRef(data_log.c_str());
			doc.AddMember("data", s, allocator);
			break;
			
		case Server_return_cancel_update:
			doc.AddMember("result", 200, allocator);
			doc.AddMember("return_message", "device update cancel", allocator);
			
			data_log = pc_data->_json.data_log;
			s = StringRef(data_log.c_str());
			doc.AddMember("data", s, allocator);
			break;
			
		case Server_return_redled_reply:
			doc.AddMember("result", 200, allocator);
			doc.AddMember("return_message", "blink start/stop", allocator);
			
			data_log = pc_data->_json.data_log;
			s = StringRef(data_log.c_str());
			doc.AddMember("data", s, allocator);
			break;
	}
	doc.AddMember("msg_id", message_timeid(), allocator);
	
	StringBuffer buffer;
	Writer<StringBuffer> writer(buffer);
	doc.Accept(writer);
	
	tmp_data = buffer.GetString();
	//添加crc字段
	crc_data =crc16_ccitt((const unsigned char *)tmp_data.data(), tmp_data.length());
	tmp_data += (crc_data >> 8);
	tmp_data += (crc_data & 0x00FF);
	//添加结束符OxFF
	tmp_data += 0xFF;

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
			data_packing_toPC(NULL, Server_return_upload, 404);
			sendto(fd_udp, tmp_data.data(), tmp_data.length(), 0, sender, *len);
		}
		else{
			fwrite(tran_packet.data, 1, r_size - 7, fp);
		}
	}while(r_size != -1);
	
	
}


int main(int argc, char *argv[])
{
	/*
	步骤：
	1. 创建套接字，进行监听

	2. 判断最后一位是否为OxFF，是则crc校验数据包

	3. 通过自定义的数据包命令码执行不同操作

	*/

	// 创建一个UDP套接字
	int fd_udp = Socket(AF_INET, SOCK_DGRAM, 0);

	//创建一个接收信息的节点
	PC_data_struct buf_json ;

	char recv_json[AST_JSON_MAX_SIZE];
	char *parse_json_data;
	int buf_len = 0,login_status = 0;
	unsigned short crc = 0;
	//md5检验储存
	char md5_str[MD5_STR_LEN + 1];
	
	//定义一个vector存储每个分割的字符串
	vector<string> v;

	// 绑定地址（IP:PORT）
	struct sockaddr_in srvaddr;
	socklen_t len = sizeof(srvaddr);
	bzero(&srvaddr, len);

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(atoi(AST_CONNECT_PORT));
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//绑定本地IP和端口
	Bind(fd_udp, (struct sockaddr *)&srvaddr, len);

	while(1)
	{
		memset(&buf_json, 0, sizeof(buf_json));
		memset(recv_json, 0, sizeof(recv_json));
		memset(md5_str, 0, MD5_STR_LEN + 1);
		v.clear();
		
		buf_len = recvfrom(fd_udp, recv_json, sizeof(recv_json), 0, (struct sockaddr *)&srvaddr, &len);
		if(buf_len > 0)
		{
			parse_json_data = (char *)malloc(buf_len-3);
			strncpy(parse_json_data, recv_json, buf_len-3);
			buf_json = parse_json(parse_json_data);
			crc = (recv_json[buf_len - 3]<<8)+recv_json[buf_len - 2];
			if(recv_json[buf_len - 1] != 0xFF );
			{
				perror("end_mark");
				data_packing_toPC(NULL, Server_return_login, 404);
				sendto(fd_udp, tmp_data.data(), tmp_data.length(), 0, (struct sockaddr *)&srvaddr, len);
				continue;
			}
			if(!check(crc, (const unsigned char *)parse_json_data, buf_len-3))
			{
				perror("crc check!");
				data_packing_toPC(NULL, Server_return_login, 401);
				sendto(fd_udp, tmp_data.data(), tmp_data.length(), 0, (struct sockaddr *)&srvaddr, len);
				continue;
			}
			SplitString(buf_json._json.data_log, v, ","); //按逗号来分割字符串
			switch(buf_json._json.user_actioncode)
			{
				//登录服务器
				case  PC_login:
					Compute_string_md5((unsigned char *)AST_SERVER_PASSWORD, strlen(AST_SERVER_PASSWORD), md5_str);
					
					if((AST_SERVER_UASE_NAME == v[0])  && (v[1] == md5_str)){
							login_status = 1;
							data_packing_toPC(NULL, Server_return_login, 200);											
					}
					else{
							data_packing_toPC(NULL, Server_return_login, 406);				
					}	
					sendto(fd_udp, tmp_data.data(), tmp_data.length(), 0, (struct sockaddr *)&srvaddr, len);
					break;
					
				//注销登录
				case PC_logout:
					Compute_string_md5((unsigned char *)AST_SERVER_PASSWORD, strlen(AST_SERVER_PASSWORD), md5_str);
					
					if((AST_SERVER_UASE_NAME == v[0])  && (v[1] == md5_str))
					{
							login_status = 0;
							data_packing_toPC(NULL, Server_return_logout, 200);					
					}
					else{
							data_packing_toPC(NULL, Server_return_logout, 406);				
					}		
					
					sendto(fd_udp, tmp_data.data(), tmp_data.length(), 0, (struct sockaddr *)&srvaddr, len);
					break;
					
				//获取设备信息
				case PC_device_list:
					if(login_status){
						vdata_list.clear();
						//接收获取设备信息的命令，执行node_list
						node_list(argc, argv);

						data_packing_toPC(NULL, Server_return_device_list, 200);
						//返回数据给PC端软件
						sendto(fd_udp, tmp_data.data(), tmp_data.length(), 0, (struct sockaddr *)&srvaddr, len);
					}
					break;

				//更新设备
				case PC_update_device:
					if(login_status && !vdata_list.empty()){
						
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
						data_packing_toPC(&buf_json, Server_return_upload, 200);

						sendto(fd_udp, tmp_data.data(), tmp_data.length(), 0, (struct sockaddr *)&srvaddr, len);
								
						do_get(fd_udp, (struct sockaddr *)&srvaddr, &len, AST_FILE_NAME);
						
						//检验文件MD5
						
						//向设备获取MD5值
						
						//比较后一致，不升级，反之发送指令升级		
					}
					break;
				//触发灯操作
				case PC_redled_blink_trigger:
					if(login_status && !vdata_list.empty()){
						data_packing_toPC(&buf_json, Server_return_redled_reply, 200);	
						sendto(fd_udp, tmp_data.data(), tmp_data.length(), 0, (struct sockaddr *)&srvaddr, len);
					}
					break;
			}
			
			free(parse_json_data);
		}
		
	}

	close(fd_udp);

	return 0;
}

