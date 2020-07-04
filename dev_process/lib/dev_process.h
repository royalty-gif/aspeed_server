/*
 * Copyright (c) 2004-2012
 * ASPEED Technology Inc. All Rights Reserved
 * Proprietary and Confidential
 *
 * By using this code you acknowledge that you have signed and accepted
 * the terms of the ASPEED SDK license agreement.
 */

#ifndef _DEV_PROCESS_
#define _DEV_PROCESS_

#define AST_DEV_PROCESS_PORT "50020"
#define AST_JSON_MAX_SIZE 1024

#define AST_FILE_NAME (char *)"/dev/shm/fw.tar.gz"

#define AST_CHECK_CODE 0x4c42  //ASCII码 BL
#define AST_PRO_CODE 0x8d13    //项目代号 5005
#define AST_EX_FILED 0x05      //扩展字段，此处扩展5字节

//文件传输操作码定义
#define AST_START_TRAN 0x01
#define AST_REPLY_START_TRAN 0x10
#define AST_WDATA 0x02
#define AST_REPLY_WDATA 0x20
#define AST_CHECK_FAILED 0x2F
#define AST_END_TRAN 0x04
#define AST_REPLY_END_TRAN 0x40
#define AST_CANCEL_TRAN 0x05
#define AST_REPLY_CANCEL_TRAN 0x50

#define EX_SIZE 5
#define TRAN_SIZE 512

// Max packet retransmission.
#define PKT_MAX_RXMT 3

//usecond
#define PKT_RCV_TIMEOUT 3*1000*1000
// usecond
#define PKT_TIME_INTERVAL 5*1000

#include <iostream>
#include <string>

using namespace std;

/************文件传输结构体***************/
#pragma pack(1)
struct Transfer_packet_head{
	unsigned short check_codeE;
	unsigned short pro_code;
	unsigned short data_len;
	unsigned char ex_field;
	unsigned char ex_data[EX_SIZE]; //操作码（1）+ 块编号（3）+和校验（1）
};

#pragma pack(1)
struct Transfer_packet{
	Transfer_packet_head packet_head;
	unsigned char data[TRAN_SIZE];
};


/************服务器对设备的操作码***************/

typedef enum _Server_todev_ActionCode_
{
	Server_get_md5value = 5200,
	Server_start_file_tran,
	Server_update_device,
	Server_write_md5Value,
	Server_trigger_redled,
}Server_todev_ActionCode;

/************设备对服务器的响应操作码***************/

typedef enum _Dev_toSrv_ActionCode_
{
	Dev_reply_md5Value = 5300,
	Dev_ready_filercv,
	Dev_update_start,
	Dev_update_end,
	Dev_reply_wmd5Value,
	Dev_online,
	Dev_blink_redled_done,
}Dev_toSrv_ActionCode;

/************接收出错的操作码***************/

typedef enum _Res_error_ActionCode_
{
	COMMAND_REFUSE = 5555,
}Res_error_ActionCode;



//AST_Device_Status device_status = Status_Unknown;
#define AST_NAME_SERVICE_GROUP_ADDR "169.254.255.255";

#endif
