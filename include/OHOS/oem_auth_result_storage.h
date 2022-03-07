/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: headfile of oem_auth_result_storage
 * Author: Kit Framework group
 * Create: 2020-12-26
 */
#ifndef HOS_LITE_OEM_AUTH_RESULT_STORAGE_H
#define HOS_LITE_OEM_AUTH_RESULT_STORAGE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief check whether the temperature of the device's flash chip is over limit or not.
 * @return true is over limit.
 */
bool OEMIsOverTemperatureLimit(void);

/**
 * @brief check reset flag is exist or not which implemented by OEM.
 * @return true is reset flag existed, false is not.
 */
bool OEMIsResetFlagExist(void);

/**
 * @brief create reset flag in device which implemented by OEM.
 * @return 0 is create succeed, others is failed.
 */
int32_t OEMCreateResetFlag(void);

/**
 * @brief delete reset flag in device which implemented by OEM.
 * @return 0 is create succeed, others is failed.
 */
int32_t OEMDeleteResetFlag(void);

/**
 * @brief check auth status file is exist or not which implemented by OEM.
 * @return true is auth status file existed, false is not.
 */
bool OEMIsAuthStatusExist(void);

/**
 * @brief write auth status to device which implemented by OEM.
 * @param data: pointer of data which to be written.
 * @param len: length of data which to be written.
 * @return 0 is written succeed, others is failed.
 */
int32_t OEMWriteAuthStatus(const char* data, uint32_t len);

/**
 * @brief read auth status from device which implemented by OEM.
 * @param buffer: pointer of auth status's buffer.
 * @param bufferLen: length of auth status's buffer.
 * @return 0 is read succeed, others is failed.
 */
int32_t OEMReadAuthStatus(char* buffer, uint32_t bufferLen);

/**
 * @brief delete auth status file from device which implemented by OEM.
 * @return 0 is delete succeed, others is failed.
 */
int32_t OEMDeleteAuthStatus(void);

/**
 * @brief get auth status's content size from device which implemented by OEM.
 * @param len: pointer of auth status's content size.
 * @return 0 is succeed, others is failed.
 */
int32_t OEMGetAuthStatusFileSize(uint32_t* len);

/**
 * @brief check ticket file is exist or not which implemented by OEM.
 * @return true is ticket file existed, false is not.
 */
bool OEMIsTicketExist(void);

/**
 * @brief write ticket to device which implemented by OEM.
 * @param data: pointer of data which to be written.
 * @param len: length of data which to be written.
 * @return 0 is written succeed, others is failed.
 */
int32_t OEMWriteTicket(const char* data, uint32_t len);

/**
 * @brief read ticket from device which implemented by OEM.
 * @param buffer: pointer of ticket's buffer.
 * @param bufferLen: length of ticket's buffer.
 * @return 0 is read succeed, others is failed.
 */
int32_t OEMReadTicket(char* buffer, uint32_t bufferLen);

/**
 * @brief delete ticket file from device which implemented by OEM.
 * @return 0 is delete succeed, others is failed.
 */
int32_t OEMDeleteTicket(void);

/**
 * @brief get ticket's content size from device which implemented by OEM.
 * @param len: pointer of ticket's content size.
 * @return 0 is succeed, others is failed.
 */
int32_t OEMGetTicketFileSize(uint32_t* len);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HOS_LITE_OEM_AUTH_RESULT_STORAGE_H */
