
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

#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

#include "vlink_hichannel_util.h"
#include <hi_reset.h>
#include <hi_time.h>
#include <hi_watchdog.h>


static hi_bool s_bLogOn = HI_TRUE;
static hi_bool s_bLogTime = HI_TRUE;
/** product log level */
static HI_LOG_LEVEL_E s_enLogLevel = HI_LOG_LEVEL;
static const hi_char* s_apszLOGLevel[HI_LOG_LEVEL_BUTT] = {LIGHT_PURPLE"FATAL"NONE, LIGHT_RED"ERROR"NONE, YELLOW"WARN"NONE, LIGHT_GREEN"INFO"NONE, "DEBUG"};

hi_void HI_LOG_Print(HI_LOG_LEVEL_E enLevel, const hi_char* pszModule, const hi_char* pszFunc, hi_u32 u32Line, hi_char* pszFmt, ...)
{
    if ((s_enLogLevel >= enLevel) && (s_bLogOn))
    {
        pszModule = (NULL == pszModule) ? "" : pszModule;
        pszFmt = (NULL == pszFmt) ? "" : pszFmt;
        va_list args;
        if (s_bLogTime)
        {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            struct tm tm;
            localtime_r(&tv.tv_sec, &tm);
            dprintf("[%02d:%02d:%02d:%03ld %s-%s]:%s[%d]:", tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec / 1000, s_apszLOGLevel[enLevel], pszModule, pszFunc, u32Line);
        }
        else
        {
            dprintf("[%s-%s]:%s[%d]:", s_apszLOGLevel[enLevel], pszModule, pszFunc, u32Line);
        }
        va_start(args, pszFmt);
        vprintf(pszFmt, args);
        va_end(args );
    }

    return;
}

hi_void error_and_fail_reset(hi_void)
{
    hi_watchdog_disable();
    vlink_gpio_power_off();
    hi_udelay(3000);
    hi_soft_reboot(HI_SYS_REBOOT_CAUSE_CMD);
}

static hi_s32 vlink_PDT_PARAM_GetParam(hi_u8 id, hi_void *data, hi_u8 len, hi_u32 flag)
{
    hi_s32 ret;
    hi_u32 result;

    result = hi_nv_read(id, data, len, flag);
    if (result != HI_ERR_SUCCESS) {
        MLOGE("hi_nv_read 0x%x failed(0x%x).\n", id, result);
        ret = HI_ERR_FAILURE;
    } else {
        MLOGD("hi_nv_read 0x%x success.\n", id);
        ret = HI_ERR_SUCCESS;
    }

    return ret;
}

static hi_s32 vlink_PDT_PARAM_SetParam(hi_u8 id, hi_void *data, hi_u8 len, hi_u32 flag)
{
    hi_s32 ret;
    hi_u32 result;

    result = hi_nv_write(id, data, len, flag);
    if (result != HI_ERR_SUCCESS) {
        MLOGE("[jiaxing]hi_nv_write 0x%x failed.\n", id);
        ret = HI_ERR_FAILURE;
    } else {
        MLOGD("[jiaxing]hi_nv_write 0x%x success.\n", id);
        ret = HI_ERR_SUCCESS;
    }

    return ret;
}


hi_s32 vlink_HI_PDT_PARAM_SetWifiParam(vlink_HI_PDT_WIFI_Param *wifiParam)
{
    HI_APPCOMM_RETURN_IF_PTR_NULL(wifiParam, HI_ERR_FAILURE);
    hi_s32 ret = vlink_PDT_PARAM_SetParam(HI_NV_NORMAL_WIFI_PARAM, wifiParam, sizeof(vlink_HI_PDT_WIFI_Param), 0);
    return ret;
}

hi_s32 vlink_HI_PDT_PARAM_GetWifiParam(vlink_HI_PDT_WIFI_Param *wifiParam)
{
    HI_APPCOMM_RETURN_IF_PTR_NULL(wifiParam, HI_ERR_FAILURE);
    hi_s32 ret = vlink_PDT_PARAM_GetParam(HI_NV_NORMAL_WIFI_PARAM, wifiParam, sizeof(vlink_HI_PDT_WIFI_Param), 0);
    return ret;
}

hi_s32 vlink_HI_PDT_PARAM_SetSysVersion(HI_PARAM_SysVersion *version)
{
    hi_s32 ret;
    ret = vlink_PDT_PARAM_SetParam(HI_NV_NORMAL_SYS_VERSION, version, sizeof(HI_PARAM_SysVersion), 0);
    return ret;
}

hi_s32 vlink_HI_PDT_PARAM_GetSysVersion(HI_PARAM_SysVersion *version)
{
    hi_s32 ret;
    ret = vlink_PDT_PARAM_GetParam(HI_NV_NORMAL_SYS_VERSION, version, sizeof(HI_PARAM_SysVersion), 0);
    return ret;
}

hi_s32 vlink_HI_PDT_PARAM_SetSystemStatus(vlink_HI_PARAM_System *status)
{
    hi_s32 ret;
    ret = vlink_PDT_PARAM_SetParam(HI_NV_NORMAL_SYSTEM_PARAM, status, sizeof(vlink_HI_PARAM_System), 0);
    return ret;
}

hi_s32 vlink_HI_PDT_PARAM_GetSystemStatus(vlink_HI_PARAM_System *status)
{
    hi_s32 ret;
    ret = vlink_PDT_PARAM_GetParam(HI_NV_NORMAL_SYSTEM_PARAM, status, sizeof(vlink_HI_PARAM_System), 0);

    switch(status->workstatus)
    {
	case 0:
		MLOGD("workstatus============[NETCFG]=success.\n");
	break;
	case 1:
		MLOGD("workstatus============[WAKEUP]=success.\n");
	break;
	case 2:
		MLOGD("workstatus============[KEEPLIVE]=success.\n");
	break;
	case 3:
		MLOGD("workstatus============[DEEPSLEEP]=success.\n");
	break;
	default:
		MLOGD("workstatus============[default]=success.\n");
	break;
    }

    return ret;
}

hi_s32 vlink_HI_PDT_PARAM_SetAliDevParam(HI_PDT_ALI_DEVICE_Param *aliDevParam)
{
    HI_APPCOMM_RETURN_IF_PTR_NULL(aliDevParam, HI_ERR_FAILURE);

    hi_s32 ret;
    ret = vlink_PDT_PARAM_SetParam(HI_NV_NORMAL_ALI_PARAM, aliDevParam, sizeof(HI_PDT_ALI_DEVICE_Param), 0);
    return ret;
}

hi_s32 vlink_HI_PDT_PARAM_GetAliDevParam(HI_PDT_ALI_DEVICE_Param *aliDevParam)
{
    HI_APPCOMM_RETURN_IF_PTR_NULL(aliDevParam, HI_ERR_FAILURE);

    hi_s32 ret;
    ret = vlink_PDT_PARAM_GetParam(HI_NV_NORMAL_ALI_PARAM, aliDevParam, sizeof(HI_PDT_ALI_DEVICE_Param), 0);
    return ret;
}

