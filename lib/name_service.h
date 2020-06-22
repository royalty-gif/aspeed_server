/*
 * Copyright (c) 2004-2012
 * ASPEED Technology Inc. All Rights Reserved
 * Proprietary and Confidential
 *
 * By using this code you acknowledge that you have signed and accepted
 * the terms of the ASPEED SDK license agreement.
 */

#ifndef _NAME_SERVICE_
#define _NAME_SERVICE_

#define AST_CONNECT_PORT "50010"
#define AST_DEV_PROCESS_PORT "50020"
#define AST_NAME_SERVICE_QUERY_PORT 3333
#define AST_NAME_SERVICE_REPLY_PORT 3334
#define AST_JSON_MAX_SIZE 1024
#define AST_SERVER_UASE_NAME "aspeed"
#define AST_SERVER_PASSWORD "123456"
#define AST_FILE_NAME (char *)"file.tar.gz"

#define AST_CHECK_CODE 0x424c  //ASCII码 BL
#define AST_PRO_CODE 0x138d    //项目代号 5005
#define AST_EX_FILED 0x05      //扩展字段，此处扩展5字节

//文件传输操作码定义
#define AST_START_TRAN 0x01
#define AST_REPLY_START_TRAN 0x10
#define AST_WDATA 0x02
#define AST_REPLY_WDATA 0x20
#define AST_CHECK_FAILED 0x2F
#define AST_CANCEL_TRAN 0x05
#define AST_REPLY_CANCEL_TRAN 0x50

#define AST_DATE_SIZE 512
#define EX_SIZE 5
#define TRAN_SIZE 512

#include <iostream>
#include <string>

using namespace std;

/************文件传输结构体***************/
struct Transfer_packet_head{
	short check_code = AST_CHECK_CODE;
	short pro_code = AST_PRO_CODE;
	short data_len = 0x00;
	char ex_field = AST_EX_FILED;
	char ex_data[EX_SIZE]; //操作码（1）+ 块编号（3）+和校验（1）
};

struct Transfer_packet{
	Transfer_packet_head packet_head;
	char data[TRAN_SIZE];
};

/************设备类型***************/

typedef enum _AST_Device_Type_
{
	Type_Any = 0,
	Type_Host,
	Type_Client,
	Type_Unknown,
} AST_Device_Type ;

/************设备函数***************/

typedef enum _AST_Device_Function_
{
	Function_Any = 0,
	Function_USB,
	Function_Digital,
	Function_Analog,
	Function_Unknown,
} AST_Device_Function ;

/************设备状态***************/

typedef enum _AST_Device_Status_
{
	Status_Any = 0,
	Status_Available,
	Status_Busy,
	Status_Idle,
	Status_Unknown,
} AST_Device_Status ;

/************PC对服务器的操作码***************/

typedef enum _PC_toSer_ActionCode_
{
	PC_login = 5000,
	PC_logout,
	PC_device_list,
	PC_update_device,
	PC_cancel_update,
	PC_firmware_upload,
	PC_redled_blink_trigger,
	PC_reply_update_status,
}PC_toSer_ActionCode;

/************服务器对PC的响应操作码***************/

typedef enum _Server_toPC_ActionCode_
{
	Server_return_login = 5100,
	Server_return_logout,
	Server_return_device_list,
	Server_return_update,
	Server_return_cancel_update,
	Server_return_upload,
	Server_return_redled_reply,
	Server_return_update_end,
	Server_return_update_status,
}Server_toPC_ActionCode;

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

/************请求***************/

typedef struct _query_struct_
{
	AST_Device_Type	device_type;
	AST_Device_Function	device_function;
//	AST_Device_Status	device_status;
}query_struct, *pquery_struct;

#define MAX_STATUS_LENGTH 32
#define MAX_NAME_LENGTH 256
#define MAX_VERSION_LENGTH 32
#define MAX_MAC_ADDRESS 16

/************设备返回的信息结构体***************/

typedef struct _reply_struct_
{
	AST_Device_Type	device_type;
	AST_Device_Function	device_function;
//	AST_Device_Status	device_status;
//	unsigned int	device_status_length;
	char device_status[MAX_STATUS_LENGTH];
//	unsigned int	device_name_length;
	char device_name[MAX_NAME_LENGTH];
	char device_mac[MAX_MAC_ADDRESS];
	char device_version[MAX_VERSION_LENGTH];
}reply_struct, *preply_struct;


//AST_Device_Status device_status = Status_Unknown;
#define AST_NAME_SERVICE_GROUP_ADDR "169.254.255.255";

#endif
