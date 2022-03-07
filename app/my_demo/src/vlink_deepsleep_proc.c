
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

#include "hi_lowpower.h"

#ifdef CONFIG_AT_COMMAND
#include <hi_at.h>
#endif



#define PDT_STANDBY_SLEEP_TIME_TMP      1000 /* 33~4000, if is 0,time is beacon*interval, need same with PDT_WIFICTRL_PM_SLEEP_TIME */
#define PDT_STANDBY_PM_TIMEER           50
#define PDT_STANDBY_PM_TIMEE_CNT        1
#define PDT_STANDBY_PM_BCN_TIMEOUT      10
#define PDT_STANDBY_PM_MCAST_TIMEOUT    30


static hi_u8 g_soc_poweronoff_status = 0; //0:off,1:on

static int vlink_wifi_ud_sleep(hi_void)
{
	hi_u32 ret;
	hi_udsleep_src wake_gpio;

	MLOGD("vlink_wifi_ud_sleep===============start.\n"); 
        /* 系统休眠… */
        /* 唤醒后重新执行初始化流程，打印唤醒源，具体值参考hi_udsleep_src */
        (hi_void)hi_lpc_init();
        ret = hi_lpc_get_udsleep_wakeup_src(&wake_gpio);
        if (ret == HI_ERR_SUCCESS) {
            MLOGD("vlink_wifi_ud_sleep====udsleep wakeup src: %x\r\n", wake_gpio);
        } else {
            /* 异常处理略 */
	    MLOGE("vlink_wifi_ud_sleep====udsleep wakeup fail\r\n");
        }
	/* 设置GPIO5和GPIO7为唤醒源 */
	hi_lpc_enable_udsleep(HI_UDS_GPIO5 | HI_UDS_GPIO7);

        if (ret == HI_ERR_SUCCESS) {
            MLOGD("vlink_wifi_ud_sleep====hi_lpc_enable_udsleep ok\r\n");
        } else {
            /* 异常处理略 */
	    MLOGE("vlink_wifi_ud_sleep====hi_lpc_enable_udsleep fail\r\n");
        }
}

/* 入睡判断前执行 */ 
static hi_u32 vlink_wifi_sw_prepare(hi_void)  
{     
	if (hi_lpc_get_type() == HI_DEEP_SLEEP) {   
		/* 用户可根据实际情况，关闭影响系统休眠的部分timer */ 
		//MLOGD("vlink_wifi_sw_prepare====\r\n");  
	}    
	return HI_ERR_SUCCESS;   
} 

/* idle任务退出时执行 */   
static hi_u32 vlink_wifi_sw_resume(hi_void)   
{   
	if (hi_lpc_get_type() == HI_DEEP_SLEEP) {    
		/* 用户根据实际情况，恢复对应timer，或增加维测信息的获取 */ 
		//MLOGD("vlink_wifi_sw_resume====\r\n");    
	}    
	return HI_ERR_SUCCESS;   
}  

/* 入睡前执行 */   
static hi_u32 vlink_wifi_hw_prepare(hi_void)  
{       
	if (hi_lpc_get_type() == HI_DEEP_SLEEP) {  
		/* 用户根据实际IO设计配置，防止深睡阶段漏电流 */ 
		//MLOGD("vlink_wifi_hw_prepare====\r\n");  
	}
	return HI_ERR_SUCCESS; 
}

/* 唤醒后执行 */  
static hi_u32 vlink_wifi_hw_resume(hi_void)  
{   
	if (hi_lpc_get_type() == HI_DEEP_SLEEP) {  
		/* 用户根据实际IO设计恢复配置 */ 
		//MLOGD("vlink_wifi_hw_resume====\r\n"); 
	}   
	return HI_ERR_SUCCESS;  
}  

static hi_void vlink_wifi_gpio7_wkup(hi_void *arg)
{
	hi_unref_param(arg);
	MLOGE("vlink_wifi_gpio7_wkup====\r\n"); 

	vlink_network_wake_up_proc();

	//sleep(2);

	//vlink_wifi_deep_sleep();
}

static hi_void vlink_wifi_gpio14_wkup(hi_void *arg)
{
	hi_unref_param(arg);
	MLOGE("vlink_wifi_gpio14_wkup====\r\n"); 

	vlink_network_wake_up_proc();
}

static hi_u32 vlink_WIFI_CheckVoteCb(hi_void)
{
	//MLOGE("vlink_WIFI_CheckVoteCb====\r\n"); 
	return HI_DEEP_SLEEP;
}


hi_u32 vlink_wifi_deep_sleep(hi_void)  
{     
	hi_u32 ret;   
	hi_pvoid handle;  

	const hi_char *ifname = "wlan0";
	struct netif *lwipNetif = HI_NULL;

	/* 深睡唤醒阶段入口函数注册，掉电外设初始化，具体可参考SDK交付的Demo代码 */   
#if 0 //app_main 
	ret = hi_lpc_register_wakeup_entry(wakeup);     
	if (ret != HI_ERR_SUCCESS) {      
		/* 异常处理略 */   
		MLOGE("hi_lpc_register_wakeup_entry====\r\n"); 
	} 
#endif
#if 0
	/* 注册是否可以进入休眠的检查函数，对应函数在idle入睡前被调用 */   
	handle = hi_lpc_register_check_handler(vlink_WIFI_CheckVoteCb);  
	if (handle == HI_NULL) {   
		/* 异常处理略 */   
		MLOGE("hi_lpc_register_check_handler====\r\n"); 
	}  

	/* 深睡阶段降低漏电流功耗 */   
	ret = hi_lpc_register_hw_handler(vlink_wifi_hw_prepare, vlink_wifi_hw_resume);   
	if (ret != HI_ERR_SUCCESS) {      
		/* 异常处理略 */  
		MLOGE("hi_lpc_register_hw_handler====\r\n");  
	}  

	/* 深睡阶段对timer的特殊处理和维测信息统计等，一般不需要注册 */     
	ret = hi_lpc_register_sw_handler(vlink_wifi_sw_prepare, vlink_wifi_sw_resume);  
	if (ret != HI_ERR_SUCCESS) {       
		/* 异常处理略 */ 
		MLOGE("hi_lpc_register_sw_handler====\r\n");      
	} 
#endif
#if 0
#if VLINK_WAKEUP_GPIO_7
	/* 使能GPIO7上升沿中断 */
	ret = hi_gpio_deinit();
	if (ret != HI_ERR_SUCCESS) {  
		/* 异常处理略 */   
		MLOGE("hi_gpio_deinit====\r\n"); 
	}
      
	ret = hi_gpio_init();  
	if (ret != HI_ERR_SUCCESS) {  
		/* 异常处理略 */   
		MLOGE("hi_gpio_init====\r\n"); 
	}  
	ret = hi_gpio_register_isr_function(HI_GPIO_IDX_7, HI_INT_TYPE_EDGE, HI_GPIO_EDGE_RISE_LEVEL_HIGH, vlink_wifi_gpio7_wkup, HI_NULL);   
	if (ret != HI_ERR_SUCCESS) {    
		/* 异常处理略 */  
		MLOGE("hi_gpio_register_isr_func==7==\r\n");     
	} 
     
	/* 使能GPIO7唤醒 */     
	ret = hi_lpc_config_dsleep_wakeup_io(HI_GPIO_IDX_7, HI_TRUE);     
	if (ret != HI_ERR_SUCCESS) {    
		/* 异常处理略 */    
		MLOGE("hi_lpc_config_dsleep_wakeup_io7====\r\n"); 
	}  
	MLOGD("-----GPIO7-set-wakeup-ok-----!\n"); 
#endif

#if VLINK_WAKEUP_GPIO_14
#if !VLINK_WAKEUP_GPIO_7
	/* 使能GPIO14上升沿中断 */
	ret = hi_gpio_deinit();
	if (ret != HI_ERR_SUCCESS) {  
		/* 异常处理略 */   
		MLOGE("hi_gpio_deinit====\r\n"); 
	}
      
	ret = hi_gpio_init();  
	if (ret != HI_ERR_SUCCESS) {  
		/* 异常处理略 */   
		MLOGE("hi_gpio_init====\r\n"); 
	} 
#endif 

	//hi_io_set_func(HI_IO_NAME_GPIO_14, HI_IO_FUNC_GPIO_14_GPIO);
/*
	ret = hi_gpio_set_dir(HI_GPIO_IDX_14, HI_GPIO_DIR_IN);
	if (ret != HI_ERR_SUCCESS) {
		hi_gpio_deinit();
		MLOGE("hi_gpio_set_dir==14==\r\n"); 
	}
*/
	ret = hi_gpio_register_isr_function(HI_GPIO_IDX_14, HI_INT_TYPE_EDGE, HI_GPIO_EDGE_RISE_LEVEL_HIGH, vlink_wifi_gpio14_wkup, HI_NULL);   
	if (ret != HI_ERR_SUCCESS) {    
		/* 异常处理略 */  
		MLOGE("hi_gpio_register_isr_func==14==\r\n");     
	} 
     
	/* 使能GPIO14唤醒 */     
	ret = hi_lpc_config_dsleep_wakeup_io(HI_GPIO_IDX_14, HI_TRUE);     
	if (ret != HI_ERR_SUCCESS) {    
		/* 异常处理略 */    
		MLOGE("hi_lpc_config_dsleep_wakeup_io14====\r\n"); 
	}  
	MLOGD("-----GPIO14-set-wakeup-ok-----!\n"); 
#endif
#endif
	hi_at_set_check_uart_busy(HI_FALSE);

	/* 关联AP，获取IP地址，配置ARP_OFFLOAD，代码略 */  
	lwipNetif = netif_find(ifname); 
	if (lwipNetif != HI_NULL) {
		ret = hi_wifi_sta_set_pm_param(PDT_STANDBY_PM_TIMEER, PDT_STANDBY_PM_TIMEE_CNT, PDT_STANDBY_PM_BCN_TIMEOUT,
				       PDT_STANDBY_PM_MCAST_TIMEOUT);
		HI_APPCOMM_RETURN_IF_FAIL(ret, ret);
	}


	/* 设置系统休眠为深睡模式 */   
	ret = hi_lpc_set_type(HI_DEEP_SLEEP);   
	if (ret != HI_ERR_SUCCESS) {    
		/* 异常处理略 */     
		MLOGE("hi_lpc_set_type====\r\n"); 
	} else {
		MLOGD("vlink_wifi_deep_sleep-------ok-----!\n");
	}
     
	hi_sleep(5000);

	/* 打开Wi-Fi子系统低功耗 */      
	ret = hi_wifi_set_pm_switch(HI_TRUE, PDT_STANDBY_SLEEP_TIME_TMP);
	HI_APPCOMM_RETURN_IF_FAIL(ret, ret);     

	if (lwipNetif != HI_NULL) {
		ip4_addr_t ipaddr = { 0 };
		ip4_addr_t netmask = { 0 };
		ip4_addr_t gw = { 0 };
		netif_get_addr(lwipNetif, &ipaddr, &netmask, &gw);
		if (hi_wifi_arp_offload_setting(ifname, HI_TRUE, ipaddr.addr) != HI_ERR_SUCCESS) {
			MLOGE("hi_wifi_arp_offload_setting err!\n");
		}
	}

	vlink_gpio_power_off();

	return HI_ERR_SUCCESS;  
}



hi_u32 vlink_wifi_exit_deep_sleep(hi_void)  
{
	hi_s32 ret;

	hi_lpc_set_type(HI_NO_SLEEP);

	ret = hi_wifi_sta_set_pm_param(0, 0, 0, 0); /* all param is 0, use default value. */
	HI_APPCOMM_LOG_IF_EXPR_FALSE(ret == HI_ERR_SUCCESS, "hi_wifi_sta_set_pm_param \n");
	ret = hi_wifi_set_pm_switch(HI_FALSE, PDT_STANDBY_SLEEP_TIME_TMP);
	HI_APPCOMM_LOG_IF_EXPR_FALSE(ret == HI_ERR_SUCCESS, "hi_wifi_set_pm_switch \n");

	MLOGD("vlink_wifi_exit_deep_sleep-------ok-----!\n");
}


