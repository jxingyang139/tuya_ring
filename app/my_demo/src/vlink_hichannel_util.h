
#include <hi_task.h>
#include "hi_types_base.h"
#include "securec.h"
#include "hi_wifi_api.h"
#include "wifi_sta.h"
#include "lwip/ip_addr.h"
#include "lwip/netifapi.h"
#include <hi_nv.h>
#include <hi_time.h>
#include "hi_timer.h"

#include "hi_channel_dev.h"

#include "cJSON.h"

#define SAMPLE_SYSLINK_DEF_HEARTBEAT_TIMEOUT 10000


#define VLINK_CFG_DEBUG_LOG_ON 1

#define VLINK_WAKEUP_GPIO_7    1
#define VLINK_WAKEUP_GPIO_14   0


//#define VLINK_TASK_STAK_SIZE 4096
//#define VLINK_TASK_PRIORITY  25

#define APP_INIT_VAP_NUM    1
#define APP_INIT_USR_NUM    1
#define DHCP_CHECK_CNT      30
#define DHCP_CHECK_TIME     2000

#define HI_NV_NORMAL_SYS_VERSION                 0x51
#define HI_NV_NORMAL_SYSTEM_PARAM                0x52
#define HI_NV_NORMAL_KEEPALIVE_PARAM             0x53
#define HI_NV_NORMAL_WIFI_RECOVER_PARAM          0x54

#define HI_NV_NORMAL_WIFI_PARAM                  0x83
#define HI_NV_NORMAL_ALI_PARAM                   0x84


#define ALI_PRODUCT_KEY_LEN           32
#define ALI_PRODUCT_SECRET_LEN        64
#define ALI_DEVICE_NAME_LEN           32
#define ALI_DEVICE_SECRET_LEN         64

#define WIFI_NETIF_NAME                  "wlan0"
#define WIFI_AP_NETIF_NAME               "ap0"


#define HI_APPCOMM_U32_INVALID_VAL	0xffffffff
#define HI_APPCOMM_U8_INVALID_VAL	0xff

#define KEEPALIVE_TASK_PRIO           20
#define KEEPALIVE_STACK_SIZE (10 * 1024)

#define KEEPALIVE_CREATE_LISTEN_PORT_MAX 3
#define KEEPALIVE_MAGIC_DEFAULT 0xf
#define KEEPALIVE_CAPACITY_DEFAULT 0x1
#define KEEPALIVE_WAKEUP_PACKET_LEN 0x80
#define KEEPALIVE_SEND_PACKET_TIMEOUT 30
#define KEEPALIVE_CONNECT_TIME  3
#define KEEPALIVE_CONNECT_TIMEOUT  (3 * 1000) /* 3S */

#define KEEPALIVE_INVALID_EVENT_ID 0xFFFFFFFF
#define KEEPALIVE_SEND_EVENT 0x1
#define KEEPALIVE_DEINIT_EVENT 0x2
#define HI_KEEPALIVE_FILTER_LEN_MAX      32
#define LOAD_SLEEP_TIME_DEFAULT   30

#define KEEPLIVE_SEND_EVENT_INTERNAL   30

#define VLINK_WIFI_CMD_SENDMSG_NETCFG		"1"
#define VLINK_WIFI_CMD_SENDMSG_GETMAC		"2"
#define VLINK_WIFI_CMD_SENDMSG_GETIP		"3"
#define VLINK_WIFI_CMD_SENDMSG_SETFILTER	"4"	
#define VLINK_WIFI_CMD_SENDMSG_KEEPLIVE		"5"
#define VLINK_WIFI_CMD_SENDMSG_STANDBY		"6"
#define VLINK_WIFI_CMD_SENDMSG_DEEPSLEEP	"7"
#define VLINK_WIFI_CMD_SENDMSG_STARTAP		"8"
#define VLINK_WIFI_CMD_SENDMSG_STARTOTA		"9"
#define VLINK_WIFI_CMD_SENDMSG_OTADATA		"10"
#define VLINK_WIFI_CMD_SENDMSG_OTAWRITERET	"11"
#define VLINK_WIFI_CMD_SENDMSG_OTARET		"12"
/*for tuya lowpoer protocal*/
#define VLINK_WIFI_CMD_SENDMSG_TUYA_LINK	"19"
#define VLINK_WIFI_CMD_SENDMSG_UTC_LINK		"20"
/*device messge to host*/
#define VLINK_WIFI_CMD_NOTIFI_MESSAGE		"21"


typedef enum {
    /*for device and host trans signal*/
    CMD_SENDMSG_TEST                = 30,
    CMD_SENDMSG_NETCFG              = 1,
    CMD_SENDMSG_GETMAC              = 2,
    CMD_SENDMSG_GETIP               = 3,
    CMD_SENDMSG_SETFILTER           = 4,
    CMD_SENDMSG_KEEPLIVE            = 5,
    CMD_SENDMSG_STANDBY             = 6,
    CMD_SENDMSG_DEEPSLEEP           = 7,
    CMD_SENDMSG_STARTAP             = 8,
    CMD_SENDMSG_STARTOTA            = 9,
    CMD_SENDMSG_OTADATA             = 10,
    CMD_SENDMSG_OTAWRITERET         = 11,
    CMD_SENDMSG_OTARET              = 12,
    CMD_SENDMSG_GET_RSSI            = 13,
    CMD_SENDMSG_GET_VERSION         = 14,
    CMD_SENDMSG_GET_WAKECODE        = 15,
    CMD_SENDMSG_FACTORY_RESET       = 16,
    CMD_SENDMSG_PIR_SET             = 17,
    CMD_SENDMSG_PIR_GET             = 18,
    CMD_SENDMSG_TUYA_SERVER_LINK    = 19,
    CMD_SENDMSG_GET_UTC_TIME        = 20,
    /*this messgae will be generate from device, send to host*/
    CMD_NOTIFI_MESSAGE              = 21,
}VLINK_CMD_MSG_NAME_e;;


/*message come from device*/
#define    NOTIFICATION_NAME_MOTION             "0"     /* 移动侦测 */
#define    NOTIFICATION_NAME_DOORBELL           "1"     /* 门铃按下 */
#define    NOTIFICATION_NAME_DEV_LINK           "2"     /* IOT设备联动触发 */
#define    NOTIFICATION_NAME_PASSBY             "3"     /* 正常经过 */
#define    NOTIFICATION_NAME_LINGER             "4"     /* 异常逗留 */
#define    NOTIFICATION_NAME_MESSAGE            "5"     /* 留言信息 */
#define    NOTIFICATION_NAME_CALL_ACCEPT        "6"     /* 门铃接听 */
#define    NOTIFICATION_NAME_CALL_NOT_ACCEPT    "7"     /* 门铃未接听 */
#define    NOTIFICATION_NAME_CALL_REFUSE        "8"     /* 门铃拒绝接听 */
#define    NOTIFICATION_NAME_HUMAN              "9"     /* 人形检测 */
#define    NOTIFICATION_NAME_PCD                "10"    /* 宠物检测 */
#define    NOTIFICATION_NAME_CAR                "11"    /* 车辆检测 */
#define    NOTIFICATION_NAME_BABY_CRY           "12"    /* 婴儿哭声 */
#define    NOTIFICATION_NAME_ABNORMAL_SOUND     "13"    /* 声音异响 */
#define    NOTIFICATION_NAME_FACE               "14"    /* 人脸检测 */
#define    NOTIFICATION_NAME_ANTIBREAK          "15"    /* 强拆告警 */
#define    NOTIFICATION_NAME_RECORD_ONLY        "16"    /* 占位，无意义 */
#define    NOTIFICATION_NAME_IO_ALARM           "17"    /* 本地IO设备触发 */
#define    NOTIFICATION_NAME_LOW_BATTERY        "18"    /* 低电量*/
#define    NOTIFICATION_NAME_NOUSE              "19"    /* 忽略*/
#define    NOTIFICATION_NAME_COVER              "20"    /* 封面 */
#define    NOTIFICATION_NAME_FULL_BATTERY       "21"    /* 电量满 */
#define    NOTIFICATION_NAME_USER_IO            "22"    /* 本地IO设备触发-2 */
#define    NOTIFY_TYPE_MAX


/* note:must add packed attribute for nv param struct */
typedef struct {
    hi_u8 majorVersion;
    hi_u8 minorVersion;
}__attribute__((packed)) HI_PARAM_SysVersion;

typedef struct {
    hi_u8 isWifiConnected;
    hi_u8 isEnablePir;
    hi_u8 pirThreshold;
    hi_u8 workstatus;
}__attribute__((packed)) vlink_HI_PARAM_System;

typedef struct {
    hi_u8 ssid[HI_WIFI_MAX_SSID_LEN + 1];
    hi_u8 key[HI_WIFI_MAX_KEY_LEN + 1];
    hi_u8 protocolMode;
    hi_u8 auth;
    hi_u8 pairwise;
    hi_u8 openDHCP;
} __attribute__((packed)) vlink_HI_PDT_WIFI_Param;

typedef struct {
    hi_u8 product_key[ALI_PRODUCT_KEY_LEN + 1];
    hi_u8 product_secret[ALI_PRODUCT_SECRET_LEN + 1];
    hi_u8 device_name[ALI_DEVICE_NAME_LEN + 1];
    hi_u8 device_secret[ALI_DEVICE_SECRET_LEN + 1];
} __attribute__((packed)) HI_PDT_ALI_DEVICE_Param;

typedef enum hiLOG_LEVEL_E
{
    HI_LOG_LEVEL_FATAL = 0,  /**<action must be taken immediately */
    HI_LOG_LEVEL_ERROR,      /**<error conditions                 */
    HI_LOG_LEVEL_WARNING,    /**<warning conditions               */
    HI_LOG_LEVEL_INFO,       /**<informational                    */
    HI_LOG_LEVEL_DEBUG,      /**<debug-level                      */
    HI_LOG_LEVEL_BUTT
} HI_LOG_LEVEL_E;

typedef enum
{
    VLINK_WIFI_WORK_NETCFG = 0,
    VLINK_WIFI_WORK_WAKEUP,
    VLINK_WIFI_WORK_KEEPLIVE,	
    VLINK_WIFI_WORK_DEEPSLEEP,
    VLINK_WIFI_WORK_MAX
} VLINK_WIFI_WORK_STATUS;

/*
typedef struct {
    hi_u8 cmdTitle[PDT_SYSTEM_SYSLINK_MSG_LEN];
    hi_s32 (*cmdFunc)(HI_U32 argc, HI_CHAR **argv);
} PDT_SYSTEM_SYSLINK_CmdAttr;
*/
#if VLINK_CFG_DEBUG_LOG_ON
#define HI_LOG_LEVEL HI_LOG_LEVEL_DEBUG
#else
#define HI_LOG_LEVEL HI_LOG_LEVEL_ERROR
#endif

#define HI_MODULE ""

/* color log macro define */
#define NONE         "\033[m"
#define RED          "\033[0;32;31m"
#define LIGHT_RED    "\033[1;31m"
#define GREEN        "\033[0;32;32m"
#define LIGHT_GREEN  "\033[1;32m"
#define BLUE         "\033[0;32;34m"
#define LIGHT_BLUE   "\033[1;34m"
#define DARY_GRAY    "\033[1;30m"
#define CYAN         "\033[0;36m"
#define LIGHT_CYAN   "\033[1;36m"
#define PURPLE       "\033[0;35m"
#define LIGHT_PURPLE "\033[1;35m"
#define BROWN        "\033[0;33m"
#define YELLOW       "\033[1;33m"
#define LIGHT_GRAY   "\033[0;37m"
#define WHITE        "\033[1;37m"

hi_void HI_LOG_Print(HI_LOG_LEVEL_E enLevel, const hi_char* pszModule, const hi_char* pszFunc, hi_u32 u32Line, hi_char* pszFmt, ...) __attribute__((format(printf,5,6)));
#define MLOGF(fmt, args...)  HI_LOG_Print(HI_LOG_LEVEL_FATAL,  HI_MODULE, __FUNCTION__, __LINE__,fmt, ##args)
#define MLOGE(fmt, args...)  HI_LOG_Print(HI_LOG_LEVEL_ERROR,  HI_MODULE, __FUNCTION__, __LINE__,fmt, ##args)
#define MLOGW(fmt, args...)  HI_LOG_Print(HI_LOG_LEVEL_WARNING,HI_MODULE, __FUNCTION__, __LINE__,fmt, ##args)
#define MLOGI(fmt, args...)  HI_LOG_Print(HI_LOG_LEVEL_INFO,   HI_MODULE, __FUNCTION__, __LINE__,fmt, ##args)
#if VLINK_CFG_DEBUG_LOG_ON
#define MLOGD(fmt, args...) HI_LOG_Print(HI_LOG_LEVEL_DEBUG, HI_MODULE, __FUNCTION__, __LINE__, fmt, ##args)
#else
#define MLOGD(fmt, args...)
#endif


/** Memory Safe Free */
#define HI_APPCOMM_SAFE_FREE(p)    do { if (NULL != (p)){ free(p); (p) = NULL; } }while(0)

#define HI_APPCOMM_LOG_AND_RETURN_IF_FAIL(ret, errcode, errstring) \
    do {                                                           \
        if ((ret) != HI_ERR_SUCCESS) {                                 \
            MLOGE("[%s] failed[0x%08X]\n", (errstring), (ret));    \
            return (errcode);                                      \
        }                                                          \
    } while (0)

/* Return Result Check */
#define HI_APPCOMM_RETURN_IF_FAIL(ret, errcode)       \
    do {                                              \
        if ((ret) != HI_ERR_SUCCESS) {                    \
            MLOGE("Error Code: [0x%08X]\n\n", (ret)); \
            return (errcode);                         \
        }                                             \
    } while (0)

/* Expression Check Without Return */
#define HI_APPCOMM_LOG_IF_EXPR_FALSE(expr, errstring) \
    do {                                              \
        if ((expr) == HI_FALSE) {                     \
            MLOGE("[%s] failed\n", (errstring));      \
        }                                             \
    } while (0)

#define HI_APPCOMM_RETURN_IF_PTR_NULL(p, errcode)    \
    do {                                             \
        if ((p) == HI_NULL) {                        \
            MLOGE("pointer[%s] is HI_NULL\n", #p);   \
            return (errcode);                        \
        }                                            \
    } while (0)

/* Expression Check */
#define HI_APPCOMM_RETURN_IF_EXPR_FALSE(expr, errcode) \
    do {                                               \
        if ((expr) == HI_FALSE) {                      \
            MLOGE("expr[%s] false\n", #expr);          \
            return (errcode);                          \
        }                                              \
    } while (0)


hi_u32 vlink_hichannel_sdio_reinit(hi_void);
hi_void hichannel_vlink_main(hi_void);
int hi_channel_set_default_wifi_filter(void);
hi_s32 vlink_fota_send_ok_msg_to_camera(hi_char * isOk);

hi_u32 vlink_network_wake_up_proc(hi_void);
hi_u32 vlink_wifi_deep_sleep(hi_void);
hi_u32 vlink_wifi_exit_deep_sleep(hi_void);

hi_u32 vlink_gpio_power_off(hi_void);

unsigned int hi_channel_rx_callback(char *buf, int length);
void hi_channel_send_ip(void *dev_if);
int hi_channel_set_default_filter(void);

hi_u32 at_send_to_host_cmd(hi_s32 argc, const hi_char **argv);


hi_void error_and_fail_reset(hi_void);
hi_s32 vlink_HI_PDT_PARAM_SetWifiParam(vlink_HI_PDT_WIFI_Param *wifiParam);
hi_s32 vlink_HI_PDT_PARAM_GetWifiParam(vlink_HI_PDT_WIFI_Param *wifiParam);
hi_s32 vlink_HI_PDT_PARAM_SetSysVersion(HI_PARAM_SysVersion *version);
hi_s32 vlink_HI_PDT_PARAM_GetSysVersion(HI_PARAM_SysVersion *version);
hi_s32 vlink_HI_PDT_PARAM_SetSystemStatus(vlink_HI_PARAM_System *status);
hi_s32 vlink_HI_PDT_PARAM_GetSystemStatus(vlink_HI_PARAM_System *status);
hi_s32 vlink_HI_PDT_PARAM_SetAliDevParam(HI_PDT_ALI_DEVICE_Param *aliDevParam);
hi_s32 vlink_HI_PDT_PARAM_GetAliDevParam(HI_PDT_ALI_DEVICE_Param *aliDevParam);

hi_s32 vlink_test_function_main(hi_void);
hi_void vlink_test_function_stop_event(hi_void);
hi_void vlink_test_function_start_event(hi_void);

hi_s32 HI_KEEPALIVE_StartKeepAlive(hi_char *serverip, hi_char *port, hi_u32 expire);









