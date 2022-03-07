/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hcc_task.c.
 * Author: Hisilicon
 * Create: 2020-09-12
 */
#ifndef __HI_CHANNEL_API_H__
#define __HI_CHANNEL_API_H__

/*****************************************************************************
  ����ͷ�ļ�����
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* ��ǰֻ֧��SDIO_TYPE���� */
typedef enum {
    SDIO_TYPE,
    SPI_TYPE,
    UNKNOWN_TYPE
}bus_type;

/*****************************************************************************
  ��������
*****************************************************************************/
typedef unsigned int (*hi_channel_rx_func)(char* buf, int length);

/**
* @ingroup
* @brief Interface to init channel device.CNcomment:��ʼ��channel device ���Ҫ��Դ.CNend
*
* @par Description:
*        Interface to init channel device.CNcomment:��ʼ��channel device ���Ҫ��Դ.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type CNcomment:��������.CNend
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
* @brief Interface of send msg to host.CNcomment:������Ϣ.CNend
*
* @par Description:
*         Interface of send msg to host.CNcomment:������Ϣ.CNend
*
* @attention  NULL
* @param buf [IN] Type #char * address of buffer.CNcomment:��Ϣ�ڴ��׵�ַ.CNend
* @param length [IN] Type #int length of buffer CNcomment:��Ϣ����.CNend
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
* @brief Interface to deinit channel device.CNcomment:���³�ʼ��channel device ���Ҫ��Դ.CNend
*
* @par Description:
*        Interface to deinit channel device.CNcomment:���³�ʼ��channel device ���Ҫ��Դ.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type.CNcomment:��������.CNend
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
* @brief Interface to register msg rx callback.CNcomment:ע����Ϣ���ջص�����.CNend
*
* @par Description:
*        Interface to register msg rx callback.CNcomment:ע����Ϣ���ջص�����.CNend
*
* @attention  NULL
* @param rx_func [IN] Type #hi_channel_rx_func callback function of receive message
                            CNcomment:��Ϣ���ջص���������ָ��.CNend
*
* @par Dependency:
*            @li hi_channel_dev.h: WiFi Channel API
* @see  NULL
*/
void hi_channel_register_rx_cb(hi_channel_rx_func rx_func);

/**
* @ingroup
* @brief Interface to reset channel device.CNcomment:���channel device��Դ.CNend
*
* @par Description:
*        Interface to reset channel device.CNcomment:���channel device��Դ.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type.CNcomment:��������.CNend
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

