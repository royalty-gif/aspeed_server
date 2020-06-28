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
#include <arpa/inet.h> 
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

//定义一个vector存储每个分割的字符串
vector<string> v_Splitstr;

//备份信息的变量
static string m_sdata2PC_bak,m_sdata2dev_bak;

//存储md5值
string md5_str; 

//创建容器收集设备信息
vector<string> vdata_list;

//创建MAC-IP关系容器
vector<vector<string> > vmac_ip;

//创建收集PC信息的容器
vector<string> m_vpcdata;
vector<int> m_vpccode,m_vpcid;

//创建收集设备响应信息的容器
vector<string> m_vdevdata,m_vdevmeg;
vector<int> m_vdevcode,m_vdevid,m_vdevres;

//发送给PC的json变量
static string m_sdata2PC;

//发送给设备的json变量
static string m_sdata2dev;

//服务器与PC UDP连接的变量
static int fd_udp, on=0;
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

/* 和校验：发送方调用,将所有的数据累加之后(溢出丢弃) 取反.返回值 */

unsigned char TX_CheckSum(unsigned char *buf, unsigned char len) //buf为数组，len为数组长度
{
    unsigned char i, ret = 0;

    for(i=0; i<len; i++)
    {
        ret += *(buf++);
    }
    ret = ~ret;
    return ret;
}

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
			
			//提取return_message
			if(doc.HasMember("return_message"))
			{
				m_vdevmeg.push_back(doc["return_message"].GetString());
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

/***************设备的信息接收解析和crc/OxFF检验******************/

void dev2srv_json_check(void)
{
	int rcv_len = -1;
	char dev_json[512];
	char *dev_parse; //数据解析存储
	unsigned short  dev_crc = 0;

	while(1)
	{
		m_vdevdata.clear();
		m_vdevcode.clear();
		m_vdevid.clear();
		m_vdevres.clear();
		m_vdevmeg.clear();
		memset(dev_json, 0, sizeof(dev_json));
		rcv_len = recvfrom(dev_fd, dev_json, sizeof(dev_json), 0, (struct sockaddr *)&pdev_addr, &pdevaddr_len);	
		printf("rcv_len:%d\n",rcv_len);
		if(rcv_len == -1 || rcv_len == 0)
		{
			perror("recvfrom error!\n");
			sched_yield();
			continue;
		}
		else
		{
			dev_parse = (char *)malloc(rcv_len);
			memset(dev_parse, 0, rcv_len);
			strncpy(dev_parse, dev_json, rcv_len-3);
			devparse_json(dev_parse);
			dev_crc = ((unsigned char)dev_json[rcv_len - 3]<<8)+(unsigned char)dev_json[rcv_len - 2];
			printf("dev_crc:%d\n",dev_crc);
			if(0xff != (unsigned char)dev_json[rcv_len - 1])
			{
				perror("end_mark");
				data_packing_todev(COMMAND_REFUSE, 404, "", message_timeid());
				sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
				continue;
			}
			if(!check(dev_crc, (const unsigned char *)dev_parse, rcv_len-3))
			{
				perror("dev_crc check!");
				data_packing_todev(COMMAND_REFUSE, 401, "", message_timeid());
				sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
				continue;
			}
				
			if(m_vdevres[0] == 200)
				break;
		}	
	}	
	free(dev_parse);
}

/******************dev_process请求***********************/

void Srv2dev_query(int Server_actioncode)
{
	
	int cycle; //用于循环连接设备
	string dev_data; //用于对数据进行处理
	static vector<string> v_deal_mac;  //储存需要升级的设备mac地址
	static vector<string> v_deal_ip;  //储存需要升级的设备mac地址对应的ip
	int ret = -1;
	
	//UDP连接
	dev_fd = Socket(AF_INET, SOCK_DGRAM, 0);
	
	bzero(&pdev_addr, pdevaddr_len);

	pdev_addr.sin_family = AF_INET;
	pdev_addr.sin_port = htons(atoi(AST_DEV_PROCESS_PORT));
	
	switch(Server_actioncode)
	{
		case Server_get_md5value:  //服务器获取md5值
			//操作：向设备获取MD5值,比较后一致，不升级，反之发送指令升级
			//建立每台设备的连接,并获取md5值
			m_vpcdata.clear();
			md5_str.clear();
			ret = Compute_file_md5(AST_TX_FILE, (char *)md5_str.c_str());
			if (0 == ret)
			{
				printf("[file - %s] md5 value:\n", AST_TX_FILE);
				printf("%s\n", md5_str.c_str());
			}
			
			for(cycle = 0; cycle < vmac_ip.size(); cycle++)
			{
				inet_pton(AF_INET, vmac_ip[cycle][1].data(), &pdev_addr.sin_addr); //循环连接
				data_packing_todev(Server_get_md5value, 0, "", message_timeid());
				m_sdata2dev_bak.assign(m_sdata2dev);
				sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
				dev2srv_json_check();
				if(m_vdevdata[0] == md5_str)
				{
					dev_data += "N" + vmac_ip[cycle][0] + ",";
				}
				else
				{
					dev_data += "Y" + vmac_ip[cycle][0] + ",";
					v_deal_mac.push_back(vmac_ip[cycle][0]); //将信息存储
					v_deal_ip.push_back(vmac_ip[cycle][1]);
				}
			}
			m_vpcdata[0] = dev_data;
			printf("%s",dev_data);
			break;
			
		case Server_start_file_tran:  //服务器开始固件传输
		
			for(cycle = 0; cycle < v_deal_mac.size(); cycle++)
			{
				inet_pton(AF_INET, v_deal_ip[cycle].data(), &pdev_addr.sin_addr); //循环连接
				data_packing_todev(Server_start_file_tran, 0, "", message_timeid());
				m_sdata2dev_bak.assign(m_sdata2dev);
				sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
				dev2srv_json_check();	
				
				//开始设备传输
				//do_put();
			}
			
			
			break;
		case Server_update_device:  //发送开始升级设备命令（固件传输结束后）
		
			break;
		case Server_write_md5Value:  //发送写md5的命令
			data_packing_todev(Server_write_md5Value, 0, m_vpcdata[0], message_timeid());
			m_sdata2dev_bak.assign(m_sdata2dev);
			sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
			dev2srv_json_check();
		
			break;
		case Server_trigger_redled:  //发送灯命令
			
			for(cycle = 0; cycle < vmac_ip.size(); cycle++) //匹配PC发到srv的mac对应的ip
			{
				if(m_vpcdata[0] == vmac_ip[cycle][0]){
					inet_pton(AF_INET, vmac_ip[cycle][1].data(), &pdev_addr.sin_addr);  //通过ip来确定连接
					break;
				}
			}
			data_packing_todev(Server_trigger_redled, 0, m_vpcdata[0], message_timeid());
			m_sdata2dev_bak.assign(m_sdata2dev);
			sendto(dev_fd, m_sdata2dev.data(), m_sdata2dev.length(), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
			dev2srv_json_check();
			break;
	}
	
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
			
			s = StringRef(pc_data.c_str());
			doc.AddMember("data", s, allocator);
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
			if(!m_vdevmeg[0].compare(0,5,"blink")){
				doc.AddMember("return_message", "blink start", allocator);
			}
			
			if(!m_vdevmeg[0].compare(0,4,"stop")){
				doc.AddMember("return_message", "blink stop", allocator);
			}
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

/************获取文件大小*************/
int get_file_size(FILE * file_handle)
{
	//获取当前读取文件的位置 进行保存
	unsigned int current_read_position=ftell( file_handle );
	int file_size;
	fseek( file_handle,0,SEEK_END );
	//获取文件的大小
	file_size=ftell( file_handle );
	//恢复文件原来读取的位置
	fseek( file_handle,current_read_position,SEEK_SET );

	return file_size;
}

/************从服务端给设备传输文件*************/

void do_put(void)
{
	static int package_number = 0;  //每个包编号
	unsigned int size = 0; //记录文件大小
	
	int r_size = 0;
	unsigned char start_status = 0;
	
	struct Transfer_packet Send_packet,Recv_packet; 
	
	FILE *put_fp = fopen(AST_TX_FILE, "r");
	if(put_fp == NULL){
		printf("File not exists!\n");
		return;
	}
	
	size = get_file_size(put_fp);
	if(size % 512)   //查看是否整除
		size = (size >> 9) + 1;
	else
		size = (size >> 9);
	
	//发送 文件开始传输包
	Send_packet.packet_head.ex_data[0] = AST_START_TRAN;  
	Send_packet.packet_head.ex_data[1] = size >> 16;
	Send_packet.packet_head.ex_data[2] = (size >> 8) && 0x00FF;
	Send_packet.packet_head.ex_data[3] = size && 0x0000FF;
	sendto(dev_fd, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
	
	while(1)
	{
		r_size = recvfrom(dev_fd, &Recv_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&pdev_addr, &pdevaddr_len);
		printf("recvfrom r_size:%d\n",r_size);
		printf("crc:%#x\n",Recv_packet.packet_head.ex_data[4]);
		
		if(r_size > 0 && r_size < 12) //数据包不足12
		{
			printf("Bad packet:%d\n",r_size);
			Send_packet.packet_head.ex_data[0] = AST_CHECK_FAILED;
			sendto(dev_fd, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&pdev_addr, pdevaddr_len);
		}
		else{
			switch(Recv_packet.packet_head.ex_data[0])
			{
				case AST_REPLY_START_TRAN:
					start_status = 1;
					break;
					
				case AST_REPLY_WDATA:
					if(start_status)
					{
						memset(Send_packet.data, 0, TRAN_SIZE); //清空数据
						
						package_number ++;
						//Send_packet.packet_head.data_len = ; 
						Send_packet.packet_head.ex_data[0] = AST_WDATA;
						Send_packet.packet_head.ex_data[1] = package_number >> 16;
						Send_packet.packet_head.ex_data[2] = (package_number >> 8) && 0x00FF;
						Send_packet.packet_head.ex_data[3] = package_number && 0x0000FF;
						
					}
					break;
					
				case AST_REPLY_END_TRAN:
					if(start_status)
					{
						
					}
					break;
					
				case AST_REPLY_CANCEL_TRAN:
				
					break;
					
				case AST_CHECK_FAILED:
				
					break;

			}
		
		}
	}
}

/************从PC端获取文件*************/

void do_get(char *file_name)
{
	static int package_num = 0;  //每个包编号
	char tran_status; //记录传输状态
	struct Transfer_packet Send_packet,Recv_packet; 
	int r_size = 0;
	unsigned short data_len = 0;
	unsigned char rcv_crc = 0;
	
	FILE *get_fp = fopen(file_name, "w");
	if(get_fp == NULL){
		printf("Create file \"%s\" error.\n", file_name);
		return;
	}
	
	while(1){
		r_size = recvfrom(fd_udp, &Recv_packet, sizeof(struct Transfer_packet), 0, (struct sockaddr *)&srvaddr, &len);
		printf("\n");
		printf("recvfrom r_size:%d\n",r_size);
		
		if(r_size > 0 && r_size < 12) //数据包不足12
		{
			printf("Bad packet:%d\n",r_size);
			Send_packet.packet_head.ex_data[0] = AST_CHECK_FAILED;
			sendto(fd_udp, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&srvaddr, len);
		}
		else{
			printf("Recv_packet.packet_head.ex_data[0]:%#x\n",Recv_packet.packet_head.ex_data[0]);
			switch(Recv_packet.packet_head.ex_data[0])
			{
				case AST_START_TRAN:  //文件开始传输指令
					tran_status = 1;

					Send_packet.packet_head.ex_data[0] = AST_REPLY_START_TRAN;
					sendto(fd_udp, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&srvaddr, len);
					break;
					
				case AST_WDATA:  // 写数据指令
					if(tran_status)
					{
						//记录包的编号
						package_num = (Recv_packet.packet_head.ex_data[1] << 16) +  
											(Recv_packet.packet_head.ex_data[2] << 8) + 
											Recv_packet.packet_head.ex_data[3];
						
						//记录包的大小
						data_len = ntohs(Recv_packet.packet_head.data_len);
						printf("package_num:%d\n",package_num);
						printf("data_len:%d\n",(unsigned short)data_len);				
						//数据校验
						rcv_crc = RX_CheckSum(Recv_packet.data, data_len);
						
						printf("rcv_crc:%#x\n",rcv_crc);
						if((unsigned char)(rcv_crc + Recv_packet.packet_head.ex_data[4]) == 0){
							Send_packet.packet_head.ex_data[0] = AST_REPLY_WDATA;
							sendto(fd_udp, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&srvaddr, len);
							fwrite(Recv_packet.data, 1, r_size - 12, get_fp);
						}
						else{
							perror("checksum error");
							Send_packet.packet_head.ex_data[0] = AST_CHECK_FAILED;
							Send_packet.packet_head.ex_data[1] = package_num >> 16;
							Send_packet.packet_head.ex_data[2] = (package_num >> 8) && 0x00FF;
							Send_packet.packet_head.ex_data[3] = package_num && 0x0000FF;
							sendto(fd_udp, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&srvaddr, len);
						}
					}
					break;
				
				case AST_CANCEL_TRAN: //取消数据传输的指令
					tran_status = 0;
					Send_packet.packet_head.ex_data[0] = AST_REPLY_CANCEL_TRAN;
					sendto(fd_udp, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&srvaddr, len);
					break;
					
				case AST_END_TRAN:  //完成数据传输
					if(tran_status){
						
						Send_packet.packet_head.ex_data[0] = AST_REPLY_END_TRAN;
						sendto(fd_udp, &Send_packet, sizeof(struct Transfer_packet_head), 0, (struct sockaddr *)&srvaddr, len);
					}
					break;
			
			}
		}
		
		if(Recv_packet.packet_head.ex_data[0] == AST_CANCEL_TRAN || 
				 Recv_packet.packet_head.ex_data[0] == AST_END_TRAN){
			fclose(get_fp);
			break;
		}
	}
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
		
		v_Splitstr.clear();
		m_vpccode.clear();
		m_vpcid.clear();
		m_vpcdata.clear();

		buf_len = recvfrom(fd_udp, recv_json, sizeof(recv_json), 0, (struct sockaddr *)&srvaddr, &len);		
		printf("******************************************\n");
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
				//登录服务器(√)
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
					
				//注销登录(√)
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
					
				//获取设备信息(√)
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
						on = 1;  //开启信号机制
						ret = ioctl(fd_udp, FIOASYNC, &on);  //工作在异步模式
						if(ret < 0)
						{
							perror("ioctl error\n");
							exit(-1);
						}
						
						while(on)
						{
							//操作1：校验文件的MD5值，向设备获取MD5值,比较后一致，不升级，反之发送指令升级
							Srv2dev_query(Server_get_md5value);
						
							//发送给PC需要升级的设备MAC地址
							data_packing_toPC(m_vpcdata[0], Server_return_update, 200, m_vpcid[0]);
							m_sdata2PC_bak.assign(m_sdata2PC);
							sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
							
							//操作2：开始文件传输 PC ← Server ↔ Dev
							Srv2dev_query(Server_start_file_tran);
						}	
					}
					break;
			
				//固件上传(✔)
				case PC_firmware_upload:	
					if(login_status && !vdata_list.empty()){
						data_packing_toPC(m_vpcdata[0], Server_return_upload, 200, m_vpcid[0]);
						m_sdata2PC_bak.assign(m_sdata2PC);
						sendto(fd_udp, m_sdata2PC.data(), m_sdata2PC.length(), 0, (struct sockaddr *)&srvaddr, len);
						
						if(v_Splitstr[0] == "TX" && v_Splitstr.size() == 1)	//PC发送的数据为“TX”		
							do_get(AST_TX_FILE); 
						else if(v_Splitstr[0] == "RX" && v_Splitstr.size() == 1)  //PC发送的数据为“RX”
							do_get(AST_RX_FILE); 
						else{                        //PC发送的数据为“TX,RX”
							do_get(AST_TX_FILE);
							do_get(AST_RX_FILE);
						}
					}
					break;
					
				//触发灯操作(√)
				case PC_redled_blink_trigger:
					if(login_status && !vdata_list.empty()){
						Srv2dev_query(Server_trigger_redled);
						
						data_packing_toPC(m_vpcdata[0], Server_return_redled_reply, 200, m_vpcid[0]);
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

