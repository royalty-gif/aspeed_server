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

#define AST_NAME_SERVICE_QUERY_PORT 3333
#define AST_NAME_SERVICE_REPLY_PORT 3334
#define AST_SERVER_UASE_NAME "aspeed"
#define AST_SERVER_PASSWORD 123456

#include <iostream>
#include <string>

using namespace std;
 
typedef enum _AST_Device_Type_
{
	Type_Any = 0,
	Type_Host,
	Type_Client,
	Type_Unknown,
} AST_Device_Type ;

typedef enum _AST_Device_Function_
{
	Function_Any = 0,
	Function_USB,
	Function_Digital,
	Function_Analog,
	Function_Unknown,
} AST_Device_Function ;

typedef enum _AST_Device_Status_
{
	Status_Any = 0,
	Status_Available,
	Status_Busy,
	Status_Idle,
	Status_Unknown,
} AST_Device_Status ;

enum
{
	PC_login = 5000,
	PC_logout,
	PC_device_list,
	PC_update_device,
	PC_cancel_update,
	PC_firmware_upload,
};


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

//  收到设备的信息结构体
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

//  json内容的一部分：数据信息部分
typedef struct _data_log_struct_
{
	string data_user;
	int data_passwd;
} data_log_struct;

//  json格式的内容
typedef struct _json_struct_
{
	int user_actioncode;
	string device_name;
	data_log_struct data_log;
	int msg_id;
} json_struct,*pjson_struct;

//  发送/接收数据包格式：json + crc + OxFF
typedef struct _PC_data_struct_
{
	json_struct _json;
	short int crc_data;
	char end_mark;
}PC_data_struct, *pPC_data_struct;

//AST_Device_Status device_status = Status_Unknown;
#define AST_NAME_SERVICE_GROUP_ADDR "225.1.0.0";

#endif
