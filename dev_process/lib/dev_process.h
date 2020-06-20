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

#define AST_FILE_NAME (char *)"file.tar.gz"

#define AST_DATE_SIZE 512

#include <iostream>
#include <string>

using namespace std;

/************文件传输结构体***************/
struct Transfer_packet{
	short check_code;
	short pro_code;
	short data_len;
	char ex_field;
	char data[AST_DATE_SIZE];
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
