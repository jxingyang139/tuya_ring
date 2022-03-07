/*
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <hi_task.h>
#include <hi_types.h>
#include <hi_types_base.h>

#include <hi_reset.h>
#include <hi_time.h>
#include <hi_watchdog.h>

#include "vlink_hichannel_util.h"
#include "hi_event.h"

#include "sys/time.h"
#include "lwip/netifapi.h"
#include "lwip/tcpip.h"
#include "lwip/sockets.h"
#include "hi_cipher.h"
#include "hi_hwtimer.h"
#include "hi_cpu.h"


hi_s32 g_main_function_Eventid = 0;
hi_u32 g_main_function_task_id = HI_APPCOMM_U32_INVALID_VAL;
hi_u32 g_main_func_event_timeout = HI_SYS_WAIT_FOREVER;

#define MAIN_FUNC_START_EVENT 	(1 << 0)
#define MAIN_FUNC_STOP_EVENT 	(1 << 1)

hi_void vlink_test_function_start_event(hi_void)
{
    hi_event_send(g_main_function_Eventid, MAIN_FUNC_START_EVENT);
}

hi_void vlink_test_function_stop_event(hi_void)
{
    hi_event_send(g_main_function_Eventid, MAIN_FUNC_STOP_EVENT);
}

static hi_void vlink_test_function_timeout_proc(hi_void)
{
    printf("AP RSSI:[%d]\r\n", hi_wifi_sta_get_ap_rssi());
}


static hi_void *vlink_test_function_main_proc(hi_void *arg)
{
    hi_s32 i, ret;
    hi_u32 eventRet;
    hi_u32 eventBit;
    //hi_u32 mask = MAIN_FUNC_START_EVENT | MAIN_FUNC_STOP_EVENT;

#define TEST_TIMEOUT	(10 * 1000)

    while (1) {
 
        eventRet = hi_event_wait(g_main_function_Eventid, MAIN_FUNC_START_EVENT | MAIN_FUNC_STOP_EVENT, &eventBit, g_main_func_event_timeout, HI_EVENT_WAITMODE_OR | HI_EVENT_WAITMODE_CLR);
        if (eventRet == HI_ERR_EVENT_WAIT_TIME_OUT) {
            //MLOGD("function event timeout\r\n");
	    vlink_test_function_timeout_proc();
        }
        else if (eventBit & MAIN_FUNC_START_EVENT) {
            MLOGD("start\r\n");
	    g_main_func_event_timeout = 10000;
        } else if (eventBit & MAIN_FUNC_STOP_EVENT) {
            MLOGD("stop\r\n");
	    g_main_func_event_timeout = HI_SYS_WAIT_FOREVER;
        }
    }
    return HI_ERR_SUCCESS;
}


hi_s32 vlink_test_function_main(hi_void)
{
    hi_s32 ret;
    hi_task_attr attr = { 0 };

    hi_event_create(&g_main_function_Eventid);

    attr.task_prio = 25;
    attr.task_name = "functest";
    attr.stack_size = 4096;
    if (hi_task_create(&g_main_function_task_id, &attr, vlink_test_function_main_proc, NULL) != HI_ERR_SUCCESS) {
        MLOGE(RED "hi_task_create failed \n" NONE);
        return ret;
    }
    MLOGI(RED "task ok \n" NONE);
    return HI_ERR_SUCCESS;
}
