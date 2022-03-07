/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for repeater
 * Author: IoT software develop group
 * Create: 2020-10-20
 */

#ifndef HI_REPEATER_API_H
#define HI_REPEATER_API_H
#include "hi_types.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define IP6_HLEN                40
#define IP6_NEXTH_HOPBYHOP      0
#define IP6_NEXTH_TCP           6
#define IP6_NEXTH_UDP           17
#define IP6_NEXTH_ENCAPS        41
#define IP6_NEXTH_ROUTING       43
#define IP6_NEXTH_FRAGMENT      44
#define IP6_NEXTH_ICMP6         58
#define IP6_NEXTH_NONE          59
#define IP6_NEXTH_DESTOPTS      60
#define IP6_NEXTH_UDPLITE       136
#define ETHER_TYPE_RARP         0x8035
#define ETHER_TYPE_IP           0x0800  /* IP protocol */
#define ETHER_TYPE_ARP          0x0806  /* ARP protocol */
#define ETHER_TYPE_IPV6         0x86dd  /* IPv6 */
#define ETHER_TYPE_6LO          0xa0ed  /* 6lowpan包头压缩 */
#define IP4_FILTER_KEY_LEN      17
#define IP6_FILTER_KEY_LEN      29
#define WIFI_FILTER_TYPE_IPV4   0
#define WIFI_FILTER_TYPE_IPV6   1

typedef enum {
    WIFI_FILTER_MASK_IP                = 0x01,
    WIFI_FILTER_MASK_PROTOCOL          = 0x02,
    WIFI_FILTER_MASK_LOCAL_PORT        = 0x04,
    WIFI_FILTER_MASK_LOCAL_PORT_RANGE  = 0x08,
    WIFI_FILTER_MASK_REMOTE_PORT       = 0x10,
    WIFI_FILTER_MASK_REMOTE_PORT_RANGE = 0x20,
    WIFI_FILTER_MASK_BUTT
} wifi_filter_field_enum;

typedef enum {
    WIFI_IP_NO_FRAG              = 0x00,
    WIFI_IP_FIRST_FRAG           = 0x01,
    WIFI_IP_MIDDLE_FRAG          = 0x02,
    WIFI_IP_LAST_FRAG            = 0x03,
    WIFI_IP_FRAG_BUTT
} wifi_ip_frag_enum;

typedef enum {
    WIFI_FILTER_LWIP             = 0,
    WIFI_FILTER_VLWIP            = 1,
    WIFI_FILTER_BOTH             = 2,
    WIFI_FILTER_BUTT
} wifi_filter_enum;

typedef struct hi_wifi_ipv4_filter {
    unsigned int   remote_ip;
    unsigned short local_port;
    unsigned short localp_min;
    unsigned short localp_max;
    unsigned short remote_port;
    unsigned short remotep_min;
    unsigned short remotep_max;
    unsigned char  packet_type;
    unsigned char  config_type;
    unsigned char  match_mask;
    unsigned char  resv;
}hi_wifi_ipv4_filter_stru;

#define WIFI_IPV6_ADDR_LEN   16
typedef struct hi_wifi_ipv6_filter {
    unsigned char  remote_ip[WIFI_IPV6_ADDR_LEN];
    unsigned short local_port;
    unsigned short localp_min;
    unsigned short localp_max;
    unsigned short remote_port;
    unsigned short remotep_min;
    unsigned short remotep_max;
    unsigned char  packet_type;
    unsigned char  config_type;
    unsigned char  match_mask;
    unsigned char  resv;
}hi_wifi_ipv6_filter_stru;

typedef struct oal_ipv4_frag {
    unsigned int   ip;
    unsigned short id;
    unsigned short us_dir;
}oal_ipv4_frag_info;

typedef struct oal_ipv6_frag {
    unsigned char  auc_ip[WIFI_IPV6_ADDR_LEN];
    unsigned int   id;
    unsigned short us_dir;
}oal_ipv6_frag_info;

#define WIFI_FILTER_MAX_NUM   20
#define WIFI_FRAG_MAX_NUM     10
typedef struct hi_wifi_filter_list {
    hi_wifi_ipv4_filter_stru ipv4_filters[WIFI_FILTER_MAX_NUM];
    hi_wifi_ipv6_filter_stru ipv6_filters[WIFI_FILTER_MAX_NUM];
    oal_ipv4_frag_info ipv4_frag_cache;
    oal_ipv4_frag_info ipv4_frags[WIFI_FRAG_MAX_NUM];
    oal_ipv6_frag_info ipv6_frag_cache;
    oal_ipv6_frag_info ipv6_frags[WIFI_FRAG_MAX_NUM];
    unsigned char ipv4_frag_pos;
    unsigned char ipv4_frag_num;
    unsigned char ipv6_frag_pos;
    unsigned char ipv6_frag_num;
    unsigned char ipv4_filter_cache;
    unsigned char ipv4_filter_num;
    unsigned char ipv6_filter_cache;
    unsigned char ipv6_filter_num;
    unsigned char default_netif;
}hi_wifi_filter_list_stru;

typedef struct hi_ip6_hdr {
    union {
        struct ip6_hdrctl {
            unsigned int ip6_un1_flow;         /* 20 bits of flow-ID */
            unsigned short ip6_un1_plen;       /* payload length */
            unsigned char ip6_un1_nxt;         /* next header */
            unsigned char ip6_un1_hlim;        /* hop limit */
        } ip6_un1;
        unsigned char ip6_un2_vfc;  /* 4 bits version, top 4 bits class */
    } ip6_ctlun;
    unsigned char ip6_src[WIFI_IPV6_ADDR_LEN]; /* source address */
    unsigned char ip6_dst[WIFI_IPV6_ADDR_LEN]; /* destination address */
}hi_ipv6_hdr_stru;
#define IPV6_NEXT_HDR      ip6_ctlun.ip6_un1.ip6_un1_nxt

typedef struct ipv6_frag_hdr {
    unsigned char nexth;
    unsigned char resv;
    unsigned short offset;
    unsigned int id;
} ipv6_frag_hdr_stru;
/**
* @ingroup
* @brief Interface to configure default filter rule to filter table.CNcomment:设置默认过滤方向.CNend
*
* @par Description:
*        Interface to configure default filter rule to filter table.CNcomment:设置默认过滤方向.CNend
*
* @attention  NULL
* @param uc_type [IN] Type #unsigned char Direction of forwarding data.CNcomment:转发数据方向.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_repeater_api.h: WiFi Channel API
* @see  NULL
*/
int hi_wifi_set_default_filter(unsigned char uc_type);
/**
* @ingroup
* @brief Interface to add specific filter rule to filter table.CNcomment:添加repeater过滤规则.CNend
*
* @par Description:
*        Interface to add specific filter rule to filter table.CNcomment:添加repeater过滤规则.CNend
*
* @attention  NULL
* @param filter [IN] Type #char filter data see hi_wifi_ipv4_filter_stru.CNcomment:过滤数据.CNend
* @param len [IN] Type #int the length of filter data.CNcomment:过滤数据的长度.CNend
* @param type [IN] Type #unsigned char the type of filter data.CNcomment:过滤数据的类型.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_repeater_api.h: WiFi Channel API
* @see  NULL
*/
int hi_wifi_add_filter(char *filter, int len, unsigned char type);
/**
* @ingroup
* @brief Interface to delete specific filter rule from filter table.CNcomment:删除过滤表.CNend
*
* @par Description:
*        Interface to delete specific filter rule from filter table.CNcomment:删除过滤表.CNend
*
* @attention  NULL
* @param filter [IN] Type #char filter data see hi_wifi_ipv4_filter_stru.CNcomment:过滤数据.CNend
* @param len [IN] Type #int the length of filter data.CNcomment:过滤数据的长度.CNend
* @param type [IN] Type #unsigned char the type of filter data.CNcomment:过滤数据的类型.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_repeater_api.h: WiFi Channel API
* @see  NULL
*/
int hi_wifi_del_filter(char *filter, int len, unsigned char type);
/**
* @ingroup
* @brief Interface to query filter rules from filter table.CNcomment:查询过滤表.CNend
*
* @par Description:
*        Interface to query filter rules from filter table.CNcomment:查询过滤表.CNend
*
* @attention  NULL
* @param filter [OUT] Type #char filter data see hi_wifi_ipv4_filter_stru.CNcomment:过滤数据.CNend
* @param num [OUT] Type #int the length of filter data.CNcomment:过滤数据的长度.CNend
* @param type [IN] Type #unsigned char WIFI_FILTER_TYPE_IPV4
*        the type of filter data.CNcomment:过滤数据的类型.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_repeater_api.h: WiFi Channel API
* @see  NULL
*/
int hi_wifi_query_filter(char **filter, int *num, unsigned char type);
/**
* @ingroup
* @brief Init repeater resource.CNcomment:初始化repeater资源.CNend
*
* @par Description:
*        Init repeater resource.CNcomment:初始化repeater资源.CNend
*
* @attention  NULL
* @param ifname [IN] Type #char the name of interface.CNcomment:网络接口的名字.CNend
*
* @retval #HISI_OK       Execute successfully.
* @retval #Other         Error code.
* @par Dependency:
*            @li hi_repeater_api.h: WiFi Channel API
* @see  NULL
*/
int hi_vlwip_netif_init(const char *ifname);
/**
* @ingroup
* @brief Release repeater resource.CNcomment:释放repeater资源.CNend
*
* @par Description:
*        Release repeater resource.CNcomment:释放repeater资源.CNend
*
* @attention  NULL
* @param ifname [IN] Type #char the name of interface.CNcomment:网络接口的名字.CNend
*
* @retval NULL.
* @par Dependency:
*            @li hi_repeater_api.h: WiFi Channel API
* @see  NULL
*/
void hi_vlwip_netif_deinit(const char *ifname);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif
