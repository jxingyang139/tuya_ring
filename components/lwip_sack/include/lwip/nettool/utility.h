/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: common define of shell cmds
 * Author: none
 * Create: 2020
 */

#ifndef LWIP_UTILITY_H
#define LWIP_UTILITY_H

#include "arch/cc.h"
#include "lwip/opt.h"

#ifdef CUSTOM_AT_COMMAND
#include "hi_at.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MACADDR_BUF_LEN 32
#define TYPE_VAL_ARGS 2
  
#ifndef PRINT_USE_CRLF
#define PRINT_USE_CRLF 1
#endif
  
#if PRINT_USE_CRLF
#define CRLF "\r\n"
#else
#define CRLF "\n"
#endif

#ifdef LWIP_DEBUG_OPEN
#undef PRINTK
#define PRINTK (void)hi_at_printf
#endif

#ifndef LWIP_STATIC
#define LWIP_STATIC static
#endif

#define API_SHELL_ERRCODE_USAGE 201U
#define API_SHELL_ERRCODE_TCPIP_UNINTED 202U
#define API_SHELL_ERRCODE_MEM_ERR 203U
#define API_SHELL_ERRCODE_SEM_ERR 204U
#define API_SHELL_ERRCODE_DEV_NOT_FOUND 205U
#define API_SHELL_ERRCODE_DEV_NOT_READY 206U
#define API_SHELL_ERRCODE_INVALID 207U
#define API_SHELL_ERRCODE_SERVICE_FAILURE 208U
#define API_SHELL_ERRCODE_IP_CONFLICT 209U
#define API_SHELL_ERRCODE_DUPLICATE_NETWORK 210U
#define API_SHELL_ERRCODE_NO_ROUTE 211U

#ifndef PRINT_ERRCODE
#define PRINT_ERRCODE(x) LWIP_PLATFORM_PRINT("ERR:%u"CRLF, (x))
#endif

#define PRINT_BUF_LEN   1024
#define MAX_MACADDR_STRING_LENGTH    18 /* including NULL */

void convert_string_to_hex(const char *src, unsigned char *dest);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_UTILITY_H */
