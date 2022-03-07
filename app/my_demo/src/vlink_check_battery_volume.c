
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

#include <hi_adc.h>
#include <hi_stdlib.h>
#include <hi_early_debug.h>
/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define ADC_TEST_LENGTH  3
#define VLT_MIN 100



#define BATTERY_TASK_STAK_SIZE (1024*2)
#define BATTERY_TASK_PRIORITY  25

hi_u16 g_adc_buf[ADC_TEST_LENGTH] = { 0 };



hi_void convert_to_voltage(hi_u32 data_len)
{
    hi_u32 i;
    float vlt_max = 0;
    float vlt_min = VLT_MIN;
    hi_u16 vlt;
    for (i = 0; i < data_len; i++) {
        vlt = g_adc_buf[i];
        float voltage = (float)vlt * 1.8 * 4 / 4096.0; 
        vlt_max = (voltage > vlt_max) ? voltage : vlt_max;
        vlt_min = (voltage < vlt_min) ? voltage : vlt_min;
    }
    printf("vlt_min:%.3f, vlt_max:%.3f \n", vlt_min, vlt_max);
}


static hi_u32 HAL_ADC_GetVal(hi_void)
{
    hi_adc_channel_index channel = HI_ADC_CHANNEL_4;
    hi_adc_equ_model_sel equModel = HI_ADC_EQU_MODEL_8;//HI_ADC_EQU_MODEL_1;
    hi_adc_cur_bais curBais = HI_ADC_CUR_BAIS_DEFAULT;
    const hi_u16 rstCnt = 0x0; /* (0x0 + 0xF)*334ns = actual time */
    hi_u16 adcValue;
    hi_u32 val;
    hi_u32 ret;

    hi_s32 i;
    hi_u32 value = 0;
    for (i = 0; i < ADC_TEST_LENGTH; i++) {
        ret = hi_adc_read(channel, &adcValue, equModel, curBais, rstCnt);
        if (ret != HI_ERR_SUCCESS) {
            printf("hi_adc_set_basic_info error %u\n", ret);
            return ret;
        }
        value += (adcValue & 0xFFF);
	printf("cur value:[%d]===\n", value);
    }

    val = value / ADC_TEST_LENGTH;
    printf("cur adc value:[%d]===vlt:[%.3f]\n", val, hi_adc_convert_to_voltage(val) * 2.6);


    return HI_ERR_SUCCESS;
}

static hi_void *vlink_battery_main_task_process(hi_void *param)
{
    hi_u32 ret, i;
    hi_u16 data;  /* 10 */

    while (1)
    {
	    HAL_ADC_GetVal();
    	    sleep(20);
	    
    }

}

hi_void vlink_check_battery_vol_main(hi_void)
{
	hi_u32 ret;
	hi_u32 battery_main_task_id = 0;

	/* Create a task to handle uart communication */
	hi_task_attr batteryattr = {0};
	batteryattr.stack_size = BATTERY_TASK_STAK_SIZE;
	batteryattr.task_prio = BATTERY_TASK_PRIORITY;
	batteryattr.task_name = (hi_char*)"battery_main";
	ret = hi_task_create(&battery_main_task_id, &batteryattr, vlink_battery_main_task_process, HI_NULL);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("Falied to create vlink_check_battery_vol_main task!\n");
	}
}
