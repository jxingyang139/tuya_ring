/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
 * Description: shell cmds APIs implementation about ping and ping6
 * Author: none
 * Create: 2020
 */

#ifndef LWIP_PING_H
#define LWIP_PING_H
#include "lwip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

u32_t os_shell_ping(int argc, const char **argv);
u32_t os_shell_ping6(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_PING_H */
