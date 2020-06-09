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
#include <string.h>
#include "debug.h"
#include "astnetwork.h"
#include "name_service.h"
#include "head4sock.h"
#include <arpa/inet.h>

//接收回应信息
reply_struct reply;

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
//	reply_struct reply;
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
//	reply_struct reply;
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

int main(int argc, char *argv[])
{
	/*
	步骤：
	1. 创建套接字，进行监听

	2. 执行node_list操作，获取设备情况并返回

	3. 等待接收文件（tftp）

	4. 接收文件后，运行MD5校验，将md5的值发送给设备
	*/
	if(argc != 2)
	{
		printf("Usage: %s <PORT>\n", argv[0]);
		exit(0);
	}

	// 创建一个UDP套接字
	int fd_udp = Socket(AF_INET, SOCK_DGRAM, 0);

	//创建一个接收信息的节点
	user_json_struct buf_json;
	int buf_len = 0;

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
		memset(&buf_json, 0, SIZE);
		buf_len = recvfrom(fd_udp, &buf_json, sizeof(buf_json), 0, NULL, NULL);
		if(buf_len > 0)
		{
			switch(buf_json.user_actioncode)
			{
				//登录服务器
				case PC_login:

				//注销登录
				case PC_logout:

				//获取设备信息
				case PC_device_list:
						//接收获取设备信息的命令，执行node_list
						node_list(argc, argv);

						//返回数据给PC端软件
						while(!write(fd_udp, &reply, sizeof(reply)));
						break;

				//更新设备
				case PC_update_device:

				//取消更新
				case PC_cancel_update:

				//固件上传
				case PC_firmware_upload:	
					break;
			}
		}
	}

	close(fd_udp);

	return 0;
}

