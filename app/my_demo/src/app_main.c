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

#include "app_main.h"

#include <hi3861_platform.h>
#include <hi_mdm.h>
#include <hi_flash.h>
#include <hi_nv.h>
#include <hi_lowpower.h>
#include <hi_diag.h>
#include <hi_crash.h>
#include <hi_sal.h>
#include <hi_shell.h>
#ifdef OHOS_SUPPORT
#include <hos_init.h>
#endif
#if defined(CONFIG_AT_COMMAND) || defined(CONFIG_FACTORY_TEST_MODE)
#include <hi_at.h>
#endif
#include <hi_fs.h>
#include <hi_partition_table.h>
#include <hi_ver.h>
#include <hi_cpu.h>
#include <hi_crash.h>
#ifdef CONFIG_DMA_SUPPORT
#include <hi_dma.h>
#endif
#ifdef CONFIG_I2C_SUPPORT
#include <hi_i2c.h>
#endif
#ifdef CONFIG_I2S_SUPPORT
#include <hi_i2s.h>
#endif
#ifdef CONFIG_SPI_SUPPORT
#include <hi_spi.h>
#endif
#ifdef CONFIG_PWM_SUPPORT
#include <hi_pwm.h>
#endif
#ifdef CONFIG_SDIO_SUPPORT
#include <hi_sdio_device.h>
#include <hi_watchdog.h>
#include <app_demo_sdio_device.h>
#endif
#include <hi_early_debug.h>
#include <hi_tsensor.h>

#ifndef CONFIG_FACTORY_TEST_MODE
#include "lwip/opt.h"
#include "lwip/ip_addr.h"
#include "lwip/netifapi.h"
#endif

#include "app_demo_upg_verify.h"
#include "hi_wifi_api.h"
#ifdef CONFIG_HILINK
#include "hilink.h"
#endif

#ifdef CONFIG_KIT_FWK
#include "entry.h"
#endif // CONFIG_KIT_FWK

#include <hi_tsensor.h>

#include "hi_channel_dev.h"
#include "hi_repeater_api.h"
#include "lwip/netifapi.h"
#include "vlink_hichannel_util.h"
#include <app_io_init.h>
#if 0
#ifndef CONFIG_QUICK_SEND_MODE

#define APP_INIT_VAP_NUM    2
#ifdef CONFIG_MESH_SUPPORT
#define APP_INIT_USR_NUM    6
#else
#define APP_INIT_USR_NUM    2
#endif

#else
#define APP_INIT_VAP_NUM    1
#define APP_INIT_USR_NUM    1
#endif
#endif

#define APP_INIT_EVENT_NUM  7

#define PERIPHERAL_INIT_ERR_FLASH   (1 << 0)
#define PERIPHERAL_INIT_ERR_UART0   (1 << 1)
#define PERIPHERAL_INIT_ERR_UART1   (1 << 2)
#define PERIPHERAL_INIT_ERR_UART2   (1 << 3)
#define PERIPHERAL_INIT_ERR_IO      (1 << 4)
#define PERIPHERAL_INIT_ERR_CIPHER  (1 << 5)
#define PERIPHERAL_INIT_ERR_DMA     (1 << 6)
#define PERIPHERAL_INIT_ERR_I2C     (1 << 7)
#define PERIPHERAL_INIT_ERR_I2S     (1 << 8)
#define PERIPHERAL_INIT_ERR_SPI     (1 << 9)
#define PERIPHERAL_INIT_ERR_PWM     (1 << 10)
#define PERIPHERAL_INIT_ERR_SDIO    (1 << 11)

#ifndef IO_CTRL_REG_BASE_ADDR
#define IO_CTRL_REG_BASE_ADDR 0x904
#endif
#define iocfg_reg_addr(_x) (HI_IOCFG_REG_BASE + IO_CTRL_REG_BASE_ADDR + (_x) * 4)
#define IOCFG_LOWPOWER_CFG_VAL 0xF8

#define CONFIG_SDIO_SUPPORT

#ifdef CONFIG_SDIO_SUPPORT
#define APP_SDIO_INIT_TASK_SIZE 0x1000
#define APP_SDIO_INIT_TASK_PRIO 25


static hi_void *sdio_init_task_body(hi_void *param)
{
    hi_unref_param(param);
    /* To prevent watchdog exceptions caused by SDIO host, disable the watchdog first. */
    hi_watchdog_disable();
    hi_cache_disable();
    hi_cache_flush(); /* should flush after disable */

	/*
    do {
        hi_u32 ret = hi_sdio_init();
		
    	printf("[jiaxing] hi sdio loop\r\n");
        if (ret == HI_ERR_SUCCESS) {
            printf("sdio driver init success\r\n");
            break;
        }
    } while (1);
	*/
#ifndef CONFIG_FACTORY_TEST_MODE
    if (hi_channel_dev_init(SDIO_TYPE) != HI_ERR_SUCCESS) {
        printf("hi_channel_init:: hichannel_dev_init_wrapper failed");
        return HI_NULL;
    }
#endif
    hi_watchdog_enable();

    printf("finish sdio init\r\n");
    return HI_NULL;
}

hi_u32 app_sdio_init(hi_void)
{
    /* Create a task to init sdio */
    printf("[jiaxing][%s %d]\n",__FUNCTION__,__LINE__);

    hi_u32 sdio_init_task_id = 0;
    hi_task_attr attr = {0};
    attr.stack_size = APP_SDIO_INIT_TASK_SIZE;
    attr.task_prio = APP_SDIO_INIT_TASK_PRIO;
    attr.task_name = (hi_char*)"sdio_init";
    hi_u32 ret = hi_task_create(&sdio_init_task_id, &attr, sdio_init_task_body, HI_NULL);
    if (ret != HI_ERR_SUCCESS) {
        printf("Falied to create sdio init task!\n");
    }
    return ret;
}
#endif

#define CLKEN_I2C0      14
#define CLKEN_I2C1      15
#define CLKEN_SPI0      5
#define CLKEN_SPI1      0
#define CLKEN_MONITOR   6
#define CLKEN_DMA_WBUS  1
#define CLKEN1_PWM5     10
#define CLKEN1_PWM_BUS  6
#define CLKEN1_PWM      5
#define CLKEN1_PWM4     4
#define CLKEN1_PWM3     3
#define CLKEN1_PWM2     2
#define CLKEN1_PWM1     1
#define CLKEN1_PWM0     0
#define CLKEN1_PWM_ALL  ((1 << (CLKEN1_PWM0)) | (1 << (CLKEN1_PWM1)) | (1 << (CLKEN1_PWM2)) | (1 << (CLKEN1_PWM3)) | \
                        (1 << (CLKEN1_PWM4)) | (1 << (CLKEN1_PWM5)))
#define CLKEN2_I2S_BUS  11
#define CLKEN2_I2S      10
#define CLKEN_UART2     6
#define CLKEN_UART2_BUS 9
#define CLKEN_TIMER1    7
#define CLKEN_TIMER2    8
#define CLKEN_SDIO_WBUS 4

/* you can disable some clocks to reduce power consumption based on service requirements */
hi_void peripheral_close_clken(hi_void)
{
    hi_u16 reg_val;
    hi_reg_read16(CLDO_CTL_CLKEN_REG, reg_val);
    reg_val &= ~((1 << CLKEN_I2C0) | (1 << CLKEN_I2C1));
    reg_val &= ~((1 << CLKEN_SPI0) | (1 << CLKEN_SPI1));
    reg_val &= ~((1 << CLKEN_DMA_WBUS) | (1 << CLKEN_MONITOR));
    reg_val &= ~((1 << CLKEN_TIMER1) | (1 << CLKEN_TIMER2));
    hi_reg_write16(CLDO_CTL_CLKEN_REG, reg_val); /* disable clken0 clk gate */

#ifndef CONFIG_PWM_HOLD_AFTER_REBOOT
    hi_reg_read16(CLDO_CTL_CLKEN1_REG, reg_val);
    reg_val &= ~CLKEN1_PWM_ALL;
    reg_val &= ~((1 << CLKEN1_PWM_BUS) | (1 << CLKEN1_PWM));
    hi_reg_write16(CLDO_CTL_CLKEN1_REG, reg_val); /* disable clken1 clk gate */
#endif

    hi_reg_read16(CLDO_CTL_CLKEN2_REG, reg_val);
    reg_val &= ~((1 << CLKEN2_I2S) | (1 << CLKEN2_I2S_BUS));
    hi_reg_write16(CLDO_CTL_CLKEN2_REG, reg_val); /* disable clken2 clk gate */
    hi_reg_read16(W_CTL_UART_MAC80M_CLKEN_REG, reg_val);
#ifdef CONFIG_SDIO_SUPPORT
        reg_val &= ~((1 << CLKEN_UART2) | (1 << CLKEN_UART2_BUS));
#else
        reg_val &= ~((1 << CLKEN_UART2) | (1 << CLKEN_UART2_BUS) | (1 << CLKEN_SDIO_WBUS));
#endif
    hi_reg_write16(W_CTL_UART_MAC80M_CLKEN_REG, reg_val); /* disable uart_mac80m clk gate */
    hi_reg_write16(PMU_CMU_CTL_CLK_960M_GT_REG, 0x1); /* disable 960m clk gate */
}

static hi_uart_attribute g_at_uart_cfg  = {115200, 8, 1, 0, 0};

hi_bool g_have_inited = HI_FALSE;
static app_iocfg_backup g_iocfg_backup = {0};


#define VLINK_SDIO_ONE_LINE	1
static hi_void PDT_INIT_IoInit(hi_void)
{
    hi_io_set_func(HI_IO_NAME_GPIO_2, HI_IO_FUNC_GPIO_2_GPIO); /* camera power control */

    hi_io_set_func(HI_IO_NAME_GPIO_3, HI_IO_FUNC_GPIO_3_UART0_TXD); /* uart0 tx */
    hi_io_set_func(HI_IO_NAME_GPIO_4, HI_IO_FUNC_GPIO_4_UART0_RXD); /* uart0 rx */

    hi_io_set_func(HI_IO_NAME_GPIO_5, HI_IO_FUNC_GPIO_5_GPIO); /* pir out */
    hi_io_set_func(HI_IO_NAME_GPIO_6, HI_IO_FUNC_GPIO_6_GPIO); /* pir in */

    hi_io_set_func(HI_IO_NAME_GPIO_7, HI_IO_FUNC_GPIO_7_GPIO); /* key */

    hi_io_set_func(HI_IO_NAME_GPIO_8, HI_IO_FUNC_GPIO_8_GPIO); /* sdio interrupt */

#if VLINK_SDIO_ONE_LINE
    hi_io_set_func(HI_IO_NAME_GPIO_9, HI_IO_FUNC_GPIO_9_GPIO);
    hi_io_set_func(HI_IO_NAME_GPIO_10, HI_IO_FUNC_GPIO_10_GPIO);
#else
    hi_io_set_func(HI_IO_NAME_GPIO_9, HI_IO_FUNC_GPIO_9_SDIO_D2);
    hi_io_set_func(HI_IO_NAME_GPIO_10, HI_IO_FUNC_GPIO_10_SDIO_D3);
#endif
    hi_io_set_func(HI_IO_NAME_GPIO_11, HI_IO_FUNC_GPIO_11_SDIO_CMD);
    hi_io_set_func(HI_IO_NAME_GPIO_12, HI_IO_FUNC_GPIO_12_SDIO_CLK);
    hi_io_set_func(HI_IO_NAME_GPIO_13, HI_IO_FUNC_GPIO_13_SDIO_D0);
#if VLINK_SDIO_ONE_LINE
    hi_io_set_func(HI_IO_NAME_GPIO_14, HI_IO_FUNC_GPIO_14_GPIO); /* usb detect */
    printf("sdio one line\r\n");
#else
    hi_io_set_func(HI_IO_NAME_GPIO_14, HI_IO_FUNC_GPIO_14_SDIO_D1);
    printf("sdio four line\r\n");
#endif


    return;
}

/* time-consuming operations, such as log output, are not allowed in the low-power process */
hi_void peripheral_init(hi_void)
{
    hi_u32 ret;
    hi_u32 err_info = 0;
    hi_cipher_set_clk_switch(HI_TRUE);
    peripheral_close_clken();
    hi_flash_deinit();
    ret = hi_flash_init();
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_FLASH;
    }

    if (g_have_inited == HI_FALSE) {
        /* app_io_set_gpio2_clkout_enable(HI_TRUE); set gpio2 clock out  */
	    PDT_INIT_IoInit();
        ret = hi_uart_init(HI_UART_IDX_1, &g_at_uart_cfg, HI_NULL);
        if (ret != HI_ERR_SUCCESS) {
            err_info |= PERIPHERAL_INIT_ERR_UART1;
        }
    } else {
        ret = hi_uart_lp_restore(HI_UART_IDX_1);
        if (ret != HI_ERR_SUCCESS) {
            err_info |= PERIPHERAL_INIT_ERR_UART1;
        }
        ret = hi_uart_lp_restore(HI_UART_IDX_0);
        if (ret != HI_ERR_SUCCESS) {
            err_info |= PERIPHERAL_INIT_ERR_UART0;
        }
        ret = hi_uart_lp_restore(HI_UART_IDX_2);
        if (ret != HI_ERR_SUCCESS) {
            err_info |= PERIPHERAL_INIT_ERR_UART2;
        }
        hi_tsensor_lp_restore();
    }
    g_have_inited = HI_TRUE;

    //app_io_init();

    ret = hi_cipher_init();
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_CIPHER;
    }

#ifdef CONFIG_DMA_SUPPORT
    /* 如果需要使用UART/SPI的DMA功能，或者使用I2S驱动等，需要初始化DMA */
    /* if product use dma in uart or spi, or use I2S driver, or DMA memory transfer,
       should init DMA Driver here. */
    ret = hi_dma_init();
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_DMA;
    }
#endif

#ifdef CONFIG_I2C_SUPPORT
    ret = hi_i2c_deinit(HI_I2C_IDX_0); /* if wake_up from deep sleep, should deinit first */
    ret |= hi_i2c_init(HI_I2C_IDX_0, 100000); /* baudrate: 100000 */
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_I2C;
    }
#endif

#ifdef CONFIG_I2S_SUPPORT
    ret = hi_i2s_deinit();  /* if wake_up from deep sleep, should deinit first */
    hi_i2s_attribute i2s_cfg = {
        .sample_rate = HI_I2S_SAMPLE_RATE_8K,
        .resolution = HI_I2S_RESOLUTION_16BIT,
    };
    ret |= hi_i2s_init(&i2s_cfg);
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_I2S;
    }
#endif

#ifdef CONFIG_SPI_SUPPORT
    ret = hi_spi_deinit(HI_SPI_ID_0); /* if wake_up from deep sleep, should deinit first */
    hi_spi_cfg_basic_info spi_cfg_basic_info;
    spi_cfg_basic_info.cpha = 1;
    spi_cfg_basic_info.cpol = 1;
    spi_cfg_basic_info.data_width = HI_SPI_CFG_DATA_WIDTH_E_7BIT;
    spi_cfg_basic_info.endian = 0;
    spi_cfg_basic_info.fram_mode = 0;
    spi_cfg_basic_info.freq = 2000000; /* set frequency 2000000 */
    hi_spi_cfg_init_param spi_init_param = {0};
    spi_init_param.is_slave = HI_FALSE;
    ret |= hi_spi_init(HI_SPI_ID_0, spi_init_param, &spi_cfg_basic_info);
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_SPI;
    }
#endif

#ifdef CONFIG_PWM_SUPPORT
    ret = hi_pwm_init(HI_PWM_PORT_PWM1);
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_PWM;
    }
#endif

#ifdef AT_DEBUG_CMD_SUPPORT
    if (err_info != 0) {
        hi_at_printf("peri_init:%x\r\n", err_info);
    }
#endif
}

hi_void peripheral_init_no_sleep(hi_void)
{
    /*
     * Example: To initialize a peripheral that does not need to be reinitialized
     * during deep sleep wakeup, call this API.
     */
//#ifdef CONFIG_SDIO_SUPPORT

    hi_sdio_set_powerdown_when_deep_sleep(HI_FALSE);
    hi_u32 ret = app_sdio_init();
    if (ret != HI_ERR_SUCCESS) {
        printf("sdio init failed\r\n");
    }
//#endif
}

/* time-consuming operations, such as log output, are not allowed in the low-power process */
hi_u32 config_before_sleep(hi_void)
{
    /* Configured based on the actual I/O design to prevent current leakage during deep sleep */
    if (hi_lpc_get_type() == HI_DEEP_SLEEP) {
#ifdef AT_DEBUG_CMD_SUPPORT
        hi_at_printf("!");
#endif
        /*
         * You can set the parameters based on the actual I/O usage,
         * such as no pull-up resistor, no pull-down resistor,
         * and disabled input signal enable, to prevent current leakage. For details, see the chip manual.
         */
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_6), g_iocfg_backup.gpio6_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_8), g_iocfg_backup.gpio8_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_10), g_iocfg_backup.gpio10_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_11), g_iocfg_backup.gpio11_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_12), g_iocfg_backup.gpio12_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_13), g_iocfg_backup.gpio13_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_SFC_CSN), g_iocfg_backup.sfc_csn_cfg);

        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_6), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_8), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_10), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_11), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_12), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_13), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_SFC_CSN), IOCFG_LOWPOWER_CFG_VAL);
        hi_uart_lp_save(HI_UART_IDX_0);
        hi_uart_lp_save(HI_UART_IDX_1);
        hi_uart_lp_save(HI_UART_IDX_2);
        hi_tsensor_lp_save();

        /* app_io_set_gpio2_clkout_enable(HI_FALSE); set gpio2 input disable for lowpower */
    }
    return HI_ERR_SUCCESS;
}

/* time-consuming operations, such as log output, are not allowed in the low-power process */
hi_u32 config_after_sleep(hi_void)
{
    /* Restore the I/O status based on the actual I/O design to prevent current leakage during deep sleep. */
    if (hi_lpc_get_type() == HI_DEEP_SLEEP) {
        /* Restore the configuration based on the actual I/O usage. */
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_6), g_iocfg_backup.gpio6_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_8), g_iocfg_backup.gpio8_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_10), g_iocfg_backup.gpio10_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_11), g_iocfg_backup.gpio11_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_12), g_iocfg_backup.gpio12_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_13), g_iocfg_backup.gpio13_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_SFC_CSN), g_iocfg_backup.sfc_csn_cfg);

#ifdef AT_DEBUG_CMD_SUPPORT
        hi_at_printf("@\r\n");
#endif
    }
    return HI_ERR_SUCCESS;
}

/* for debug, To obtain sleep rejection information, define the PM_DEBUG_GET_LOG macro. */
#ifdef PM_DEBUG_GET_LOG
#define GET_PM_LOG_PER_N_TIMES  20
#define PRINT_LOG_WAIT_TIMES    1000
/* This part is used only for low-power maintenance and test. This part affects the power consumption. */
hi_u32 config_sw_after_sleep(hi_void)
{
    static hi_u32 idle_sw_cb_times = 0;
    static hi_u32 wkup_times = 0;
    hi_lpc_info *info;
    if (hi_lpc_get_type() != HI_NO_SLEEP) {
        idle_sw_cb_times++;
        info = hi_lpc_get_info();
        if ((info->wakeup_times == wkup_times) && (idle_sw_cb_times % GET_PM_LOG_PER_N_TIMES == 0)) {
            hi_u32 min_tick = info->timer_ticks > info->task_ticks ? info->task_ticks : info->timer_ticks;
            hi_u32 min_id = info->timer_ticks > info->task_ticks ? info->task_id : info->timer_handle;
            /* Do not use hi_at_printf. The AT serial port has the low-power voting attribute by default. */
            printf("[not sleep]min ticks:%u, min_id:0x%x, refuse_handle:0x%x, vote:0x%x\r\n", min_tick, min_id,
                info->refuse_vote_handle, info->veto_info);
            hi_udelay(PRINT_LOG_WAIT_TIMES);
            idle_sw_cb_times = 0;
        }
        wkup_times = info->wakeup_times;
    }
    return HI_ERR_SUCCESS;
}
#endif

#ifdef CONFIG_KIT_FWK
static netif_ext_callback_t kitfwk_netif_ext_cb;
static hi_bool g_have_authed = HI_FALSE;
static void kitfwk_auth_task_callback(struct netif* netif, netif_nsc_reason_t reason,
    const netif_ext_callback_args_t* args)
{
    if (g_have_authed == HI_TRUE) {
        return;
    }
    hi_wifi_status connect_status = {0};
    if (hi_wifi_sta_get_connect_info(&connect_status) != HISI_OK) {
        return;
    }
    if (connect_status.status == HI_WIFI_CONNECTED) {
        AuthWorkTask();
        g_have_authed = HI_TRUE;
        netif_remove_ext_callback(&kitfwk_netif_ext_cb);
    }
}

static void kitfwk_register_auth_task()
{
    err_t ret = netifapi_netif_add_ext_callback(&kitfwk_netif_ext_cb, kitfwk_auth_task_callback);
    if (ret != ERR_OK) {
        printf("Register netif extern callback for kitfwk auth failed\n");
    } else {
        printf("Register netif extern callback for kitfwk auth succeed\n");
    }
}
#endif // CONFIG_KIT_FWK


#ifndef CONFIG_QUICK_SEND_MODE
hi_void app_main(hi_void)
{
    (hi_void)hi_event_init(APP_INIT_EVENT_NUM, HI_NULL);
#ifdef CONFIG_FACTORY_TEST_MODE
        printf("factory test mode!\r\n");
#endif

    const hi_char* sdk_ver = hi_get_sdk_version();
    printf("sdk ver:%s\r\n", sdk_ver);

    hi_flash_partition_table *ptable = HI_NULL;

    peripheral_init();
    peripheral_init_no_sleep();
#ifdef PM_DEBUG_GET_LOG
    hi_lpc_register_sw_handler(HI_NULL, config_sw_after_sleep);
#endif
#ifndef CONFIG_FACTORY_TEST_MODE
    hi_lpc_register_wakeup_entry(peripheral_init);
#endif

    hi_u32 ret = hi_factory_nv_init(HI_FNV_DEFAULT_ADDR, HI_NV_DEFAULT_TOTAL_SIZE, HI_NV_DEFAULT_BLOCK_SIZE);
    if (ret != HI_ERR_SUCCESS) {
        printf("factory nv init fail\r\n");
    }

    /* partion table should init after factory nv init. */
    ret = hi_flash_partition_init();
    if (ret != HI_ERR_SUCCESS) {
        printf("flash partition table init fail:0x%x \r\n", ret);
    }
    ptable = hi_get_partition_table();

    ret = hi_nv_init(ptable->table[HI_FLASH_PARTITON_NORMAL_NV].addr, ptable->table[HI_FLASH_PARTITON_NORMAL_NV].size,
        HI_NV_DEFAULT_BLOCK_SIZE);
    if (ret != HI_ERR_SUCCESS) {
        printf("nv init fail\r\n");
    }

#ifndef CONFIG_FACTORY_TEST_MODE
    hi_upg_init();
#endif

#if defined (CONFIG_FILE_SYSTEM_SUPPORT) || defined(CONFIG_FACTORY_TEST_MODE) || defined(OHOS_SUPPORT)
    /* if not use file system, there is no need init it */
    hi_fs_init();
#endif

    hi_sal_init();
    /*
     * If this parameter is set to TRUE, the PC value during reset is displayed when the watchdog is reset.
     * However,the reset may be incomplete.
     * Therefore, you must set this parameter to FALSE for the mass production version.
     */
    hi_syserr_watchdog_debug(HI_FALSE);
    /* 默认记录宕机信息到FLASH，根据应用场景，可不记录，避免频繁异常宕机情况损耗FLASH寿命 */
    /* By default, breakdown information is recorded in the flash memory. You can choose not to record breakdown
     * information based on the application scenario to prevent flash servicelife loss caused by frequent breakdown. */
    hi_syserr_record_crash_info(HI_TRUE);

    hi_lpc_init();
    hi_lpc_register_hw_handler(config_before_sleep, config_after_sleep);

#if defined(CONFIG_AT_COMMAND) || defined(CONFIG_FACTORY_TEST_MODE)
    ret = hi_at_init();
    if (ret == HI_ERR_SUCCESS) {
        hi_at_sys_cmd_register();
    }
#endif

    /* 如果不需要使用Histudio查看WIFI驱动运行日志等，无需初始化diag */
    /* if not use histudio for diagnostic, diag initialization is unnecessary */
    /* Shell and Diag use the same uart port, only one of them can be selected */
#ifndef CONFIG_FACTORY_TEST_MODE

#ifndef ENABLE_SHELL_DEBUG
#ifdef CONFIG_DIAG_SUPPORT
    (hi_void)hi_diag_init();
#endif
#else
    (hi_void)hi_shell_init();
#endif

    /*
     * If the diag and shell are not started, this interface is invoked to reallocate the serial port number
     * for outputting debug logs based on the NV configuration.
     * hi_printf_alloc_uart_by_nv();
     * You can also invoke the change_uart interface in serial_dw.h to forcibly change the serial port number
     * for outputting debug logs.
     * change_uart((hi_uart)uart_id, default_uart_param);
     */
    tcpip_init(NULL, NULL);
#endif

    ret = hi_wifi_init(APP_INIT_VAP_NUM, APP_INIT_USR_NUM);
    if (ret != HISI_OK) {
        printf("wifi init failed!\n");
    } else {
        printf("wifi init success!\n");
    }

#ifndef CONFIG_FACTORY_TEST_MODE
    app_demo_upg_init();

#ifdef CONFIG_KIT_FWK
    kitfwk_register_auth_task();
#endif // CONFIG_KIT_FWK

#ifdef CONFIG_HILINK
    ret = hilink_main();
    if (ret != HISI_OK) {
        printf("hilink init failed!\n");
    } else {
        printf("hilink init success!\n");
    }
#endif

#ifdef OHOS_SUPPORT
    /* Mandatory for running Harmony feature */
    InitWifiGlobalLock();
    NetCfgSampleBiz();
#endif

	hi_char buf_test[512];
	hi_s32 buffer_t_size;
	buffer_t_size = tuya_send_authention_request(buf_test);
	tuya_recevie_authention_response(buf_test);

	hichannel_vlink_main();
#endif
}
#endif
