/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mesh networking api for lwip.
 * Author: wangwenjie
 * Create: 2020-08-06
 */

#ifndef _MESH_ROUTE_API_H_
#define _MESH_ROUTE_API_H_
#include <hi_types_base.h>
typedef hi_void(*hi_lwip_msg_handle_call)(const hi_u8* data, size_t data_lenth);
hi_u32 mesh_lwip_send_msg(hi_u32 ip_addr, hi_u8* data, hi_u8 data_lenth);
hi_void mesh_set_lwip_msg_call_back(hi_lwip_msg_handle_call func);
hi_u32 mesh_get_mbr_ip(rpl_mnode_id_t mnid, hi_u32* mbr_ip);
#endif
