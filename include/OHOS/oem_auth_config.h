/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: headfile of oem_auth_config
 * Author: Kit Framework group
 * Create: 2020-12-26
 */

#ifndef HOS_LITE_OEM_AUTH_CONFIG_H
#define HOS_LITE_OEM_AUTH_CONFIG_H

#include <stdint.h>
#include <stdlib.h>
#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define KIT_INFO_JSON_KEY "KitInfos"
#define KIT_INFO_PAIR_KEY 0
#define KIT_INFO_PAIR_VAL 1
#define KIT_INFO_PAIR_LEN 2

/**
 * @brief load authentication's certs from device which implemented by OEM.
 * @param chain: pointer of TLS session cert chain.
 * @param data: pointer of cert data.
 * @param dataLen: length of cert data.
 * @return 0 is read succeed, others is failed.
 */
int32_t OEMLoadTlsCert(mbedtls_x509_crt* chain, const uint8_t* data, size_t dataLen);

/**
 * @brief read authentication's server info from device which implemented by OEM.
 *        format: server1:port1;server2:port2; ...
 * @param port: pointer of server info's buffer.
 * @param len: length of server info's buffer, max value is 256.
 *             The max length for signal NV srtuct is 252 Bytes, so please be careful if the server info is save as NV.
 * @return 0 is read succeed, others is failed.
 */
int32_t OEMReadAuthServerInfo(char* buff, uint32_t len);

/**
 * @brief load kit's id and verison information from device which implemented by OEM.
 * @return char* not NULL means load succeed, NULL is means OEM haven't set kit infos or no others kit to authenticate
 *         example : NULL means no others kit
 *                   "{\"KitInfos\":[]}" means no others kit
 *                   "{\"KitInfos\":[{\"HiLinkKit\":\"1.0.0\"},{\"DvKit\":\"1.0.1\"}]}" means with HiLink and DvKit
 */
char* OEMLoadKitInfos(void);

/**
 * @brief get total timeout information from device which implemented by OEM.
 * @return the millisecond timeout value.
 */
uint32_t OEMGetTotalTimeout();

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HOS_LITE_OEM_AUTH_CONFIG_H */
