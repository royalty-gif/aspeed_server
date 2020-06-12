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

extern "C"{
//创建设备信息结构体数组指针
preply_struct reply_list;

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

#define WAIT_REPLY_TIMEOUT 3
static void do_query(AST_Device_Type device_type, AST_Device_Function device_function)
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
}
//JSON解析

PC_data_struct parse_json(string jsondata) {
	PC_data_struct ret;
	
	//创建解析对象进行解析
	rapidjson::Document doc;
	if(!doc.Parse(jsondata.data()).HasParseError())
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
		//crc校验码
		if(doc.HasMember("crc_data"))
		{
			ret.crc_data = doc["crc_data"].GetInt();
		}
		//结束符0xFF
		if(doc.HasMember("end_mark"))
		{
			ret.end_mark = *doc["end_mark"].GetString();
		}
	}

	return ret;
}
//分割string字符串函数
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

//时间函数
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

//封装函数响应PC
PC_data_struct data_packing_toPC(int user_actioncode, string result, int crc, const unsigned char *buf, int size)
{
	PC_data_struct data_package; 	
	memset(&data_package, 0, sizeof(data_package));
	
	data_package._json.user_actioncode = user_actioncode;
	data_package._json.device_name = "KVM_SERVER_9500";
	data_package._json.msg_id = message_timeid();
	switch(user_actioncode)  //封装data_log
	{
		case Server_return_login:
			if(result == "200")
			{
				data_package._json.data_log = "success";
			}
			else if(result == "406")
			{
				data_package._json.data_log = "failed";
			}
			break;
			
		case Server_return_logout:
			if(result == "200")
			{
				data_package._json.data_log = "success";
			}
			else if(result == "406")
			{
				data_package._json.data_log = "failed";
			}
			break;
			
		case Server_return_device_list:
			break;
			
		case Server_return_update:
			break;
			
		case Server_return_cancel_update:
			break;
			
		case Server_return_upload:
			break;
			
		case Server_return_redled_reply:
			break;
	}
	
	//添加crc字段
	data_package.crc_data = check(crc, buf, size);
	//添加结束符OxFF
	data_package.end_mark = 0xFF;
	
	return data_package;
}
int main(int argc, char *argv[])
{
	/*
	步骤：
	1. 创建套接字，进行监听

	2. 判断最后一位是否为OxFF，是则crc校验数据包

	3. 通过自定义的数据包命令码执行不同操作

	*/
	if(argc != 2)
	{
		printf("Usage: %s <PORT>\n", argv[0]);
		exit(0);
	}

	// 创建一个UDP套接字
	int fd_udp = Socket(AF_INET, SOCK_DGRAM, 0);

	//创建一个发送/接收信息的节点
	PC_data_struct buf_json, send_data;
	string recv_json;
	int buf_len = 0,login_status = 0;
	
	//md5检验储存
	char md5_str[MD5_STR_LEN + 1];
	
	//定义一个vector存储每个分割的字符串
	vector<string> v;

	// 绑定地址（IP:PORT）
	struct sockaddr_in srvaddr;
	socklen_t len = sizeof(srvaddr);
	bzero(&srvaddr, len);

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(atoi(argv[1]));
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//绑定本地IP和端口
	Bind(fd_udp, (struct sockaddr *)&srvaddr, len);

	while(1)
	{
		memset(&buf_json, 0, sizeof(buf_json));
		memset(&send_data, 0, sizeof(send_data));
		memset(md5_str, 0, MD5_STR_LEN + 1);
		v.clear();
		buf_len = recvfrom(fd_udp, &recv_json, sizeof(recv_json), 0, (struct sockaddr *)&srvaddr, &len);
		if(buf_len > 0)
		{
			buf_json = parse_json(recv_json);
			
			if(buf_json.end_mark != 0xFF)
			{
				perror("end_mark");
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
							send_data =data_packing_toPC(Server_return_login, "200", 
													buf_json.crc_data, (const unsigned char *)&(buf_json._json), sizeof(buf_json._json));
											
							if(sendto(fd_udp, &send_data, sizeof(send_data), 0, (struct sockaddr *)&srvaddr, len) < 0)
									perror("PC_login_sendto");
					}
					else{
							send_data = data_packing_toPC(Server_return_login, "406", 
													buf_json.crc_data, (const unsigned char *)&(buf_json._json), sizeof(buf_json._json));
													
							if(sendto(fd_udp, &send_data, sizeof(send_data), 0, (struct sockaddr *)&srvaddr, len) < 0)
									perror("PC_login_sendto");					
					}	
						
					break;
					
				//注销登录
				case PC_logout:
					Compute_string_md5((unsigned char *)AST_SERVER_PASSWORD, strlen(AST_SERVER_PASSWORD), md5_str);
					
					if((AST_SERVER_UASE_NAME == v[0])  && (v[1] == md5_str))
					{
							login_status = 0;
							send_data = data_packing_toPC(Server_return_login, "200", 
													buf_json.crc_data, (const unsigned char *)&(buf_json._json), sizeof(buf_json._json));
													
							if(sendto(fd_udp, &send_data, sizeof(send_data), 0, (struct sockaddr *)&srvaddr, len) < 0)
									perror("PC_logout_sendto");						
					}
					else{
							send_data = data_packing_toPC(Server_return_login, "406", 
													buf_json.crc_data, (const unsigned char *)&(buf_json._json), sizeof(buf_json._json));
													
							if(sendto(fd_udp, &send_data, sizeof(send_data), 0, (struct sockaddr *)&srvaddr, len) < 0)
									perror("PC_logout_sendto");						
					}		
					break;
					
				//获取设备信息
				case PC_device_list:
					if(login_status){
						//接收获取设备信息的命令，执行node_list
						node_list(argc, argv);

						//返回数据给PC端软件
						if(sendto(fd_udp, &reply_list, sizeof(reply_list), 0, (struct sockaddr *)&srvaddr, len) < 0)
								perror("PC_device_list_sendto");	
					}
					break;

				//更新设备
				case PC_update_device:
					if(login_status){
						
					}
					break;
				//取消更新
				case PC_cancel_update:
					if(login_status){
					
					}
					break;
				//固件上传
				case PC_firmware_upload:	
					if(login_status){
					
					}
					break;
				//触发灯操作
				case PC_redled_blink_trigger:
					if(login_status){
					
					}
					break;
			}
		}
	}

	close(fd_udp);

	return 0;
}

