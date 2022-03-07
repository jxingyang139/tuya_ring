/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hcc_task.c.
 * Author: Hisilicon
 * Create: 2020-09-12
 */
#ifndef __HI_CHANNEL_API_H__
#define __HI_CHANNEL_API_H__

/*****************************************************************************
  其他头文件包含
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* 当前只支持SDIO_TYPE总线 */
typedef enum {
    SDIO_TYPE,
    SPI_TYPE,
    UNKNOWN_TYPE
}bus_type;

/*****************************************************************************
  函数声明
*****************************************************************************/
typedef unsigned int (*hi_channel_rx_func)(char* buf, int length);

/**
* @ingroup
* @brief Interface to init channel device.CNcomment:初始化channel device 侧必要资源.CNend
*
* @par Description:
*        Interface to init channel device.CNcomment:初始化channel device 侧必要资源.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type CNcomment:总线类型.CNend
*
* @retval #HI_ERR_SUCCESS        Execute successfully.
* @retval #HI_ERR_FAILURE        Execute failed.
* @par Dependency:
*            @li hi_channel_dev.h: WiFi Channel API
* @see  NULL
*/
unsigned int hi_channel_dev_init(bus_type type);

/**
* @ingroup
* @brief Interface of send msg to host.CNcomment:发送消息.CNend
*
* @par Description:
*         Interface of send msg to host.CNcomment:发送消息.CNend
*
* @attention  NULL
* @param buf [IN] Type #char * address of buffer.CNcomment:消息内存首地址.CNend
* @param length [IN] Type #int length of buffer CNcomment:消息长度.CNend
*
* @retval #HI_ERR_SUCCESS        Execute successfully.
* @retval #HI_ERR_FAILURE        Execute failed.
* @par Dependency:
*            @li hi_channel_dev.h: WiFi Channel API
* @see  NULL
*/
unsigned int hi_channel_send_to_host(char* buf, int length);

/**
* @ingroup
* @brief Interface to deinit channel device.CNcomment:重新初始化channel device 侧必要资源.CNend
*
* @par Description:
*        Interface to deinit channel device.CNcomment:重新初始化channel device 侧必要资源.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type.CNcomment:总线类型.CNend
*
* @retval #HI_ERR_SUCCESS        Execute successfully.
* @retval #HI_ERR_FAILURE        Execute failed.
* @par Dependency:
*            @li hi_channel_dev.h: WiFi Channel API
* @see  NULL
*/
unsigned int hi_channel_dev_reinit(bus_type type);

/**
* @ingroup
* @brief Interface to register msg rx callback.CNcomment:注册消息接收回调函数.CNend
*
* @par Description:
*        Interface to register msg rx callback.CNcomment:注册消息接收回调函数.CNend
*
* @attention  NULL
* @param rx_func [IN] Type #hi_channel_rx_func callback function of receive message
                            CNcomment:消息接收回调函数函数指针.CNend
*
* @par Dependency:
*            @li hi_channel_dev.h: WiFi Channel API
* @see  NULL
*/
void hi_channel_register_rx_cb(hi_channel_rx_func rx_func);

/**
* @ingroup
* @brief Interface to reset channel device.CNcomment:清空channel device资源.CNend
*
* @par Description:
*        Interface to reset channel device.CNcomment:清空channel device资源.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type.CNcomment:总线类型.CNend
*
* @par Dependency:
*            @li hi_channel_dev.h: WiFi Channel API
* @see  NULL
*/
void hi_channel_dev_reset(bus_type type);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of frw_task.h */

