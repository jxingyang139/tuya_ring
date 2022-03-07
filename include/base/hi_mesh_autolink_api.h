/*
 * Copyright (c) 2020 HiSilicon (Shanghai) Technologies CO., LIMITED.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @defgroup hi_mesh_autolink WiFi Mesh Autolink Settings
 * @ingroup hi_wifi
 */

#ifndef __HI_MESH_AUTOLINK_API_H__
#define __HI_MESH_AUTOLINK_API_H__

#include "hi_wifi_mesh_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define MAX_IPV6ADDR_LEN 16
#define MAX_MAC_ADDR_LEN 6

/**
 * @ingroup hi_mesh_autolink
 *
 * Auth type of mesh autolink.CNcomment: Mesh自动组网的认证类型.CNend
 */
typedef enum {
    HI_MESH_OPEN,                       /* Auth Type:Open. CNcomment:认证类型:开放.CNend */
    HI_MESH_AUTH,                       /* Auth Type:Auth. CNcomment:认证类型:加密.CNend */

    HI_MESH_AUTH_TYPE_BUTT              /* Boundary of hi_mesh_autolink_auth_type. */
                                        /* CNcomment:hi_mesh_autolink_auth_type枚举定界.CNend */
}hi_mesh_autolink_auth_type;


/**
 * @ingroup hi_mesh_autolink
 *
 * Node type that usr config of mesh autolink.CNcomment: Mesh自动组网的用户输入节点类型.CNend
 */
typedef enum {
    HI_MESH_USRCONFIG_MBR,                  /* User Config:MBR Role. CNcomment: 用户指定MBR节点角色.CNend */
    HI_MESH_USRCONFIG_MR,                   /* User Config:MR Role. CNcomment: 用户指定MR节点角色.CNend */
    HI_MESH_USRCONFIG_MSTA,                 /* User Config:MSTA Role. CNcomment: 用户指定MSTA节点角色.CNend */
    HI_MESH_USRCONFIG_AUTO,                 /* User Config:Auto Role(Result:MBR/MR). */
                                            /* CNcomment: 自动竞选节点角色(MBR/MR中选择).CNend */
    /* Role of node which cannot join in Mesh.(Not User Config). CNcomment: 未加入组网的返回结果(非用户配置).CNend */
    HI_MESH_AUTOLINK_ROUTER_MSTA,
    /* Boundary of hi_mesh_autolink_usrcfg_node_type. CNcomment:hi_mesh_autolink_usrcfg_node_type枚举定界.CNend */
    HI_MESH_USRCONFIG_BUTT
}hi_mesh_autolink_usrcfg_node_type;

/**
 * @ingroup hi_mesh_autolink
 *
 * The result of nodes joining the mesh network.CNcomment: 节点加入mesh网络的结果.CNend
 */
typedef enum {
    HI_MESH_JOIN_SUCCESS,                  /* Join Success. CNcomment: 加入网络成功.CNend */
    HI_MESH_JOIN_TIMEOUT,                  /* Join Timeout. CNcomment: 加入网络超时.CNend */
    HI_MESH_ROUTER_IP_FULL,                /* Get IP from Router Fail. CNcomment: 从路由器获取IP地址失败.CNend */
    HI_MESH_MBR_EXCEED,                    /* The Num of MBR Exceed. CNcomment: MBR的个数达到满.CNend */
    /* Boundary of hi_mesh_autolink_join_fail_reason. CNcomment:hi_mesh_autolink_join_fail_reason枚举定界.CNend */
    HI_MESH_JOIN_RESULT_BUTT
}hi_mesh_autolink_join_result;

/**
 * @ingroup hi_mesh_autolink
 *
 * Node type information.CNcomment: Mesh自动组网的节点信息体.CNend
 */
typedef struct {
    char ifname_first[WIFI_IFNAME_MAX_SIZE + 1];     /* First Interface name. CNcomment: 第一个接口名称.CNend */
    /* First Interface name length. CNcomment: 第一个接口名称的长度.CNend */
    int len_first;
    char ifname_second[WIFI_IFNAME_MAX_SIZE + 1];    /* Second Interface name. CNcomment: 第二个接口名称.CNend */
    /* Second Interface name length. CNcomment: 第二个接口名称的长度.CNend */
    int len_second;
}hi_mesh_autolink_role_if;

/**
 * @ingroup hi_mesh_autolink
 *
 * Struct of mesh autolink config.CNcomment:mesh自动组网配置参数CNend
 *
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];                   /* SSID. CNcomment: SSID.CNend */
    /* Auth type of Autolink. CNcomment: Autolink认证类型.CNend */
    hi_mesh_autolink_auth_type auth;
    char key[HI_WIFI_MESH_KEY_LEN_MAX + 1];                /* Password. CNcomment: 密码.CNend */
    hi_mesh_autolink_usrcfg_node_type usr_cfg_role;        /* Node type that usr config of mesh autolink. */
                                                           /* CNcomment: 用户设置的节点角色.CNend */
}hi_mesh_autolink_config;

/**
 * @ingroup hi_mesh_autolink
 *
 * Struct of autolink role callback.CNcomment:Mesh自动组网角色回调结构体.CNend
 *
 */
typedef struct {
/* Node type that usr config of mesh autolink. CNcomment: 用户设置的节点角色.CNend */
    hi_mesh_autolink_usrcfg_node_type role;
    hi_mesh_autolink_role_if info;               /* The Interface of node. CNcomment: 节点接口.CNend */
    hi_mesh_autolink_join_result result_code;    /* Join Result Code. CNcomment: 节点加入网络的结果.CNend */
} hi_mesh_autolink_role_cb;

/**
 * @ingroup hi_mesh_autolink
 *
 * Struct of autolink node ip address.CNcomment:设备ip地址结构体.CNend
 *
 */

typedef struct node_ip_addr {
    unsigned int ipv4_addr;
    unsigned char ipv6_addr[MAX_IPV6ADDR_LEN];
} node_ip_addr;

/**
 * @ingroup hi_mesh_autolink
 *
 * Struct of autolink node ip address.CNcomment:设备mac地址.CNend
 *
 */

struct mesh_device_mac_info {
    unsigned char mac[MAX_MAC_ADDR_LEN];
    unsigned char mac_len;
};

/**
 * @ingroup hi_mesh_autolink
 *
 * Struct of autolink node ip address.CNcomment:多个设备mac地址.CNend
 *
 */

struct mesh_all_device_mac_info {
    unsigned short num;
    struct mesh_device_mac_info node[0];
};


/**
 * @ingroup hi_mesh_autolink
 *
 * callback function definition of mesh autolink result.CNcommment:mesh自动组网结果回调接口定义.CNend
 */
typedef void (* hi_mesh_autolink_cb)(const hi_mesh_autolink_role_cb *role);

/**
* @ingroup  hi_mesh_autolink
* @brief  Mesh start autolink network.CNcomment:mesh启动自动组网。CNend
*
* @par Description:
*          Mesh start autolink network.CNcomment:mesh启动自动组网。CNend
*
* @attention  1. SSID only supports ASCII characters.
*                CNcomment:1. SSID 只支持ASCII字符.CNend
*             2. Not Support WEP auth type.
*                CNcomment:1. 涓嶆敮鎸佽矾鐢卞櫒WEP璁よ瘉绫诲瀷.CNend
* @param  config [IN]  Type  #hi_mesh_autolink_config * mesh's autolink configuration.CNcomment:mesh自动入网配置。CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_mesh_start_autolink(hi_mesh_autolink_config *config);

/**
* @ingroup  hi_mesh_autolink
* @brief  Close mesh autolink.CNcomment:停止mesh自动组网模块。CNend
*
* @par Description:
*           Close mesh autolink.CNcomment:停止mesh自动组网模块。CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_mesh_exit_autolink(void);

/**
* @ingroup  hi_mesh_autolink
* @brief  Set the rssi threshold of the router when MBR node connect.
*           CNcomment:设置MBR节点关联路由器的RSSI阈值。CNend
*
* @par Description:
*           Set the router rssi threshold.CNcomment:设置路由器的RSSI阈值。CNend
*
* @attention  1. The valid range of RSSI threshold is -127 ~ 127.
*                CNcomment:1. RSSI阈值的有效范围是-127         ~ 127.CNend
* @param  router_rssi [IN]  Type  #int mesh's rssi threshold of mbr connecting to router.
*           CNcomment:MBR关联到路由器的RSSI阈值CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_mesh_autolink_set_router_rssi_threshold(int router_rssi);

/**
* @ingroup  hi_mesh_autolink
* @brief  Get the rssi threshold of the router when MBR node connect.
*           CNcomment:获取MBR节点关联路由器的RSSI阈值。CNend
*
* @par Description:
*           Get the router rssi threshold.CNcomment:获取路由器的RSSI阈值。CNend
*
* @attention 1. The memories of <router_rssi> memories are requested by the caller.
*               CNcomment:1. <router_rssi>由调用者申请内存CNend
* @param  router_rssi [OUT]  Type  #int * mesh's rssi threshold of mbr connecting to router.
*           CNcomment:MBR关联到路由器的RSSI阈值CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_mesh_autolink_get_router_rssi_threshold(int *router_rssi);

/**
* @ingroup  hi_mesh_autolink
* @brief  Set the bandwidth value of the mesh network. CNcomment:设置Mesh网络的带宽。CNend
*
* @par Description:
*           Set the bandwidth value of the mesh network. CNcomment:设置Mesh网络的带宽。CNend
*
* @attention 1. Should be called before calling hi_mesh_start_autolink api to establish mesh network.
*            CNcomment:1. 需要在调用hi_mesh_start_autolink接口组建网络前调用CNend
* @param  bw [IN]  Type  #hi_wifi_bw The bandwidth value of mesh network.
*           CNcomment:Mesh网络的带宽值CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_mesh_autolink_set_bw(hi_wifi_bw bw);

/**
* @ingroup  hi_mesh_autolink
* @brief  Get the bandwidth value of the mesh network. CNcomment:获取Mesh网络的带宽。CNend
*
* @par Description:
*           Get the bandwidth value of the mesh network. CNcomment:获取Mesh网络的带宽。CNend
*
* @attention 1. The memories of <bw> memories are requested by the caller.
*               CNcomment:1. <bw>由调用者申请内存CNend
* @param  bw [OUT]  Type  #hi_wifi_bw * The bandwidth value of mesh network.
*           CNcomment:Mesh网络的带宽值CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_mesh_autolink_get_bw(hi_wifi_bw *bw);

/**
* @ingroup  hi_mesh_autolink
* @brief  register mesh autolink user callback interface.CNcomment:注册Mesh自动组网回调函数接口.CNend
*
* @par Description:
*           register mesh autolink user callback interface.CNcomment:注册Mesh自动组网回调函数接口.CNend
*
* @attention  NULL
* @param  role_cb  [OUT]    Type #hi_mesh_autolink_cb, role callback .CNcomment:回调函数.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_mesh_autolink_register_event_callback(hi_mesh_autolink_cb role_cb);

/**
* @ingroup  hi_mesh_autolink
* @brief  set device oui interface.CNcomment:设置产品的厂家oui编码.CNend
*
* @par Description:
*           set device ou interface.CNcomment:设置产品的厂家oui编码.CNend
*
* @attention  NULL
* @param  oui      [IN]    Type #unsigned char *, oui code .CNcomment:产品厂家编码，为3个字节无符号数，范围0-0XFF.CNend
* @param  oui_len  [IN]    Type #unsigned char, oui code lenth .CNcomment:厂家编码长度,长度为3个字节.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_mesh_set_oui(const unsigned char *oui, unsigned char oui_len);

/**
* @ingroup  hi_mesh_autolink
* @brief  get device ipv4 and ipv6 address interface.CNcomment:获取设备的ipv4和ipv6地址.CNend
*
* @par Description:
*           get device ipv4 and ipv6 address interface.CNcomment:获取设备的ipv4和ipv6地址.CNend
*
* @attention  NULL
* @param  mac_addr   [IN]    Type #char *, mac address .CNcomment:MAC地址，范围0-0XFF.CNend
* @param  mac_lenth  [IN]    Type #unsigned char, mac code lenth .CNcomment:MAC地址长度,长度为6个字节.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/

int hi_mesh_get_device_ip(const char* mac_addr, unsigned char mac_lenth, node_ip_addr *node);

/**
* @ingroup  hi_mesh_autolink
* @brief  get all devices mac address interface.CNcomment:获取设备所有设备的mac地址.CNend
*
* @par Description:
*           get all devices mac address interface.CNcomment:获取所有设备的mac地址.CNend
*
* @attention  NULL
* @param  devices   [IN]    Type #char *, mac mesh_all_device_mac_info .CNcomment:保存列表的指针.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/

int hi_mesh_get_devices_macs(struct mesh_all_device_mac_info **devices);

/**
* @ingroup  hi_mesh_autolink
* @brief  free memery for mac address interface.CNcomment:释放mac地址列表内存.CNend
*
* @par Description:
*           free memery for devices mac address interface.CNcomment:释放hi_mesh_get_devices_macs返回的地址devices.CNend
*
* @attention  NULL
* @param  devices   [IN]    Type #mesh_all_device_mac_info *, devices .CNcomment:保存mac列表的指针.CNend
*

* @par Dependency: NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/

void hi_mesh_free_devices_macs_mem(struct mesh_all_device_mac_info *devices);


#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of hi_mesh_autolink_api.h */
