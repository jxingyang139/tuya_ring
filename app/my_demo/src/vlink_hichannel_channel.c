/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: app channel demo
 * Author: Hisilicon
 * Create: 2020-09-17
 */

#include <hi_stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include "lwip/netifapi.h"
#include "hi_channel_dev.h"
#include "hi_repeater_api.h"
#include "hi_config.h"
#include "hi_wifi_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#include <hi_at.h>

/* 宏定义 */
#define DEMO_LENGTH                 10
#define MAX_CMD_LEN                 20
#define MAX_IPV4_LEN                13
#define WIFI_NETIF_NAME             "wlan0"

enum {
    HOST_CMD_GET_MAC,
    HOST_CMD_GET_IP,
    HOST_CMD_SET_FILTER,
    HOST_CMD_TBTT
};

char cmd[][MAX_CMD_LEN] = {
    "cmd_get_mac",
    "cmd_get_ip",
    "cmd_set_filter"};

int hi_channel_set_default_filter(void)
{
    int ret = hi_wifi_set_default_filter(WIFI_FILTER_VLWIP);
    printf("set all net packets foward to camera default.\n");

    hi_wifi_ipv4_filter_stru filter_ipv4 = {0};
    hi_wifi_ipv6_filter_stru filter_ipv6 = {0};
    filter_ipv4.local_port = 68;             /* 68 DHCP port */
    filter_ipv4.packet_type = IP6_NEXTH_UDP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_LOCAL_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to 3861L */
    ret = hi_wifi_add_filter((hi_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 68 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.local_port = 67;             /* 67 DHCP port */
    filter_ipv4.packet_type = IP6_NEXTH_UDP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_LOCAL_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to 3861L */
    ret = hi_wifi_add_filter((hi_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 67 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.remote_port = 6001;          /* 6001 TCP port */
    filter_ipv4.packet_type = IP6_NEXTH_TCP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_PROTOCOL | WIFI_FILTER_MASK_LOCAL_PORT;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to 3861L */
    ret = hi_wifi_add_filter((hi_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 6001 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.remote_port = 6002;          /* 6002 TCP port */
    filter_ipv4.packet_type = IP6_NEXTH_TCP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_PROTOCOL | WIFI_FILTER_MASK_REMOTE_PORT;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to 3861L */
    ret = hi_wifi_add_filter((hi_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 6002 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.local_port = 7001;           /* 7001 TCP port */
    filter_ipv4.packet_type = IP6_NEXTH_UDP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_LOCAL_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to 3861L */
    ret = hi_wifi_add_filter((hi_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 7001 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.local_port = 7002;           /* 7002 TCP port */
    filter_ipv4.packet_type = IP6_NEXTH_UDP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_REMOTE_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to 3861L */
    ret = hi_wifi_add_filter((hi_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 7002 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv6, sizeof(filter_ipv6), 0, sizeof(filter_ipv6));
    filter_ipv6.local_port = 68;             /* 68 DHCP port */
    filter_ipv6.packet_type = IP6_NEXTH_UDP; /* UDP 17, TCP 6 */
    filter_ipv6.match_mask = WIFI_FILTER_MASK_LOCAL_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv6.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to 3861L */
    ret = hi_wifi_add_filter((hi_char*)&filter_ipv6, sizeof(filter_ipv6), WIFI_FILTER_TYPE_IPV6);
    printf("add mcu dhcp filter6 ret %d\n", ret);

    return ret;

    return ret;
}

int hi_channel_set_default_wifi_filter(void)
{
    int ret = hi_wifi_set_default_filter(WIFI_FILTER_LWIP);
    printf("set all net packets foward to wifi default.\n");

    return ret;
}

hi_void hi_channel_send_ip(hi_void *dev_if)
{
    hi_u8 i = 0;
    ip4_addr_t loop_ipaddr;
    ip4_addr_t loop_netmask;
    ip4_addr_t loop_gw;
    struct netif *netif = (struct netif *)dev_if;
    hi_char ip_str[MAX_IPV4_LEN + 1] = {0};

    if (netif == HI_NULL) {
        return;
    }

    err_t ret = netifapi_netif_get_addr(netif, &loop_ipaddr, &loop_netmask, &loop_gw);
    if (ret != ERR_OK) {
        return;
    }

    ip_str[i++] = HOST_CMD_GET_IP;
    ip_str[i++] = (((u8_t*)(&loop_ipaddr.addr))[0]);  /* ip addr 0 byte */
    ip_str[i++] = (((u8_t*)(&loop_ipaddr.addr))[1]);  /* ip addr 1 byte */
    ip_str[i++] = (((u8_t*)(&loop_ipaddr.addr))[2]);  /* ip addr 2 byte */
    ip_str[i++] = (((u8_t*)(&loop_ipaddr.addr))[3]);  /* ip addr 3 byte */

    ip_str[i++] = (((u8_t*)(&loop_netmask.addr))[0]);  /* ip addr 0 byte */
    ip_str[i++] = (((u8_t*)(&loop_netmask.addr))[1]);  /* ip addr 1 byte */
    ip_str[i++] = (((u8_t*)(&loop_netmask.addr))[2]);  /* ip addr 2 byte */
    ip_str[i++] = (((u8_t*)(&loop_netmask.addr))[3]);  /* ip addr 3 byte */

    ip_str[i++] = (((u8_t*)(&loop_gw.addr))[0]);  /* ip addr 0 byte */
    ip_str[i++] = (((u8_t*)(&loop_gw.addr))[1]);  /* ip addr 1 byte */
    ip_str[i++] = (((u8_t*)(&loop_gw.addr))[2]);  /* ip addr 2 byte */
    ip_str[i++] = (((u8_t*)(&loop_gw.addr))[3]);  /* ip addr 3 byte */

    if (i != MAX_IPV4_LEN) {
        printf("ip len = %d\n", i);
        return;
    }

    hi_channel_send_to_host(ip_str, MAX_IPV4_LEN + 1);
}

/*****************************************************************************
 功能描述  : 客户发送消息给host侧示例
 函数参数  : buf: 信息缓存区 (用户负责申请和释放)
             length: 信息长度
*****************************************************************************/
unsigned int hi_channel_tx_msg(hi_void)
{
    char *buf = (char *)malloc(sizeof(char) * DEMO_LENGTH);
    if (buf == HI_NULL) {
        printf("hi_channel_tx_msg:: malloc failed");
        return HI_ERR_FAILURE;
    }

    for (int i = 0; i < DEMO_LENGTH; i++) {
        buf[i] = i;
    }

    hi_channel_send_to_host(buf, sizeof(char) * DEMO_LENGTH);
    free(buf);
    return HI_ERR_SUCCESS;
}
#if 0
/*****************************************************************************
 功能描述  : 提供给客户获取host侧传送的信息
 函数参数  : buf: 信息缓存区 (注: 该内存用户不可free，只可读)
             length: 信息长度
*****************************************************************************/
unsigned int hi_channel_rx_callback(char *buf, int length)
{
    hi_u8 index;

    if ((buf == HI_NULL) || (length == 0)) {
        return HI_ERR_FAILURE;
    }

    for(index = HOST_CMD_GET_MAC; index < HOST_CMD_TBTT; index ++) {
        if (memcmp(buf, cmd[index], strlen(cmd[index])) == 0) {
            break;
        }
    }

    printf("Type:%d\n", index);
    if (index == HOST_CMD_GET_MAC) {
        hi_u8 *addr = HI_NULL;
        hi_char mac_addr[HI_MAC_ADDR_LEN + 1] = {0};
        if (hi_wifi_get_macaddr(&mac_addr[1], HI_MAC_ADDR_LEN) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }

        addr = (hi_u8 *)&mac_addr[0];
        mac_addr[0] = HOST_CMD_GET_MAC;
        printf("TYPE:%d, MAC:%02X:%02X:%02X:%02X:%02X:%02X\n", addr[0], addr[1], addr[2],
            addr[3], addr[4], addr[5], addr[6]);
        hi_channel_send_to_host(mac_addr, HI_MAC_ADDR_LEN + 1);
    } else if (index == HOST_CMD_GET_IP) {
        struct netif *netif = netifapi_netif_find(WIFI_NETIF_NAME);
        if (netif == HI_NULL) {
            return HI_ERR_FAILURE;
        }

        hi_channel_send_ip(netif);
    } else if (index == HOST_CMD_SET_FILTER) {
        hi_channel_set_default_filter();
    }
    return HI_ERR_SUCCESS;
}
#endif
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
