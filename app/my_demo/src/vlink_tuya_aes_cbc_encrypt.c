/*****************************************
for tuya low power wake up ways
******************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <hi_cpu.h>
#include <hi_crash.h>
#include <hi_flash.h>
#include <hi_mem.h>
#include <hi_mux.h>
#include <hi_nv.h>
#include <hi_os_stat.h>
#include <hi_reset.h>
#include <hi_sal_nv.h>
#include <hi_stdlib.h>
#include <hi_task.h>
#include <hi_time.h>
#include <hi_tsensor.h>
#include <hi_uart.h>
#include <hi_watchdog.h>
#include <hi_upg_api.h>
#include <hi_ver.h>
#include <hi_wifi_api.h>
#include "mbedtls/base64.h"
#include "vlink_hichannel_util.h"
#include "hi_cipher.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define AES_PHY_ADDR_ALIGNSIZE 4
#define PADDING_BLOCK_SIZE 16
#define ALIGN(x, mask)  (((x) + ((mask)-1)) & ~((mask)-1))

static void pkcs7_padding(hi_char * buf, int buflen, int blocksize, hi_char * paddingBuf)
{
	int i;
	int p = blocksize - buflen % blocksize;

	for( i = 0; i < buflen; i++ ) {
		paddingBuf[i] = buf[i];
	}
	for( i = buflen; i < buflen + p; i++ ) {
	    paddingBuf[i] = p;
	}
	paddingBuf[i] = '\0';
}


static int aes_buf_phy_addr_align(const unsigned char *input,
                                    const unsigned char *output,
                                    unsigned char **p_temp_input,
                                    unsigned char **p_temp_output,
                                    size_t length,
                                    size_t temp_length)
{
    if( (uintptr_t)input % AES_PHY_ADDR_ALIGNSIZE )
    {
        *p_temp_input = (unsigned char *)hi_malloc(HI_MOD_ID_APP_COMMON, temp_length);
        if( *p_temp_input == NULL )
            return -1;

        (VOID)memset(*p_temp_input, 0, temp_length);
        (VOID)memcpy(*p_temp_input, input, length);
    } else
        *p_temp_input = (unsigned char *)input;

    if( (uintptr_t)output % AES_PHY_ADDR_ALIGNSIZE )
    {
        *p_temp_output = (unsigned char *)hi_malloc(HI_MOD_ID_APP_COMMON,temp_length);
        if( *p_temp_output == NULL )
            return -1;
    } else
        *p_temp_output = (unsigned char *)output;

    return 0;
}


hi_u32 aes128_cbc_encrypt(hi_uchar *sr_content, hi_u8 *key, hi_u8 *iv, hi_uchar *des_content)
{
	hi_u32 ret;
	hi_u32 cs;
	hi_uchar *padding_buf;

	hi_cipher_aes_ctrl aes_ctrl = {
		.random_en = HI_FALSE,
		.key_from = HI_CIPHER_AES_KEY_FROM_CPU,
		.work_mode = HI_CIPHER_AES_WORK_MODE_CBC,
		.key_len = HI_CIPHER_AES_KEY_LENGTH_128BIT,
		.ccm = HI_NULL,
	};

	ret = memcpy_s(aes_ctrl.key, sizeof(aes_ctrl.key), key, 16);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("memory copy the key error!\n");
		goto fail;
	}

	ret = memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), iv, 16);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("memory copy the iv error!\n");
		goto fail;
	}

	padding_buf = (hi_uchar*)hi_malloc(HI_MOD_ID_APP_COMMON, strlen(sr_content) + PADDING_BLOCK_SIZE + 1);
	if (padding_buf == NULL) {
		MLOGE("malloc failure !");
		goto fail;
	}
	(hi_void)pkcs7_padding(sr_content, strlen(sr_content), 16, padding_buf);

	ret = hi_cipher_aes_config(&aes_ctrl);
	if (ret != HI_ERR_SUCCESS) {
		goto crypto_fail;
	}

	ret = hi_cipher_aes_crypto((uintptr_t)padding_buf, (uintptr_t)des_content, strlen(padding_buf), HI_TRUE);
	if (ret != HI_ERR_SUCCESS) {
		goto crypto_fail;
	}

success:
	(hi_void) hi_cipher_aes_destroy_config();
	hi_free(HI_MOD_ID_APP_COMMON, padding_buf);
	return HI_ERR_SUCCESS;
crypto_fail:
	(hi_void) hi_cipher_aes_destroy_config();
	hi_free(HI_MOD_ID_APP_COMMON, padding_buf);
fail:
    return HI_ERR_FAILURE;
}

hi_u32 aes128_cbc_decrypt(hi_uchar *sr_content, hi_u8 *key, hi_u8 *iv, hi_uchar *des_content)
{
    hi_u32 ret;
    hi_u32 cs;

    hi_cipher_aes_ctrl aes_ctrl = {
        .random_en = HI_FALSE,
        .key_from = HI_CIPHER_AES_KEY_FROM_CPU,
        .work_mode = HI_CIPHER_AES_WORK_MODE_CBC,
        .key_len = HI_CIPHER_AES_KEY_LENGTH_128BIT,
        .ccm = HI_NULL,
    };

	ret = memcpy_s(aes_ctrl.key, sizeof(aes_ctrl.key), key, 16);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("memory copy the key error!\n");
		goto fail;
	}

	ret = memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), iv, 16);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("memory copy the iv error!\n");
		goto fail;
	}

	ret = hi_cipher_aes_config(&aes_ctrl);
	if (ret != HI_ERR_SUCCESS) {
		goto crypto_fail;
	}
	ret = hi_cipher_aes_crypto((uintptr_t)sr_content, (uintptr_t)des_content, strlen(sr_content), HI_FALSE);
	if (ret != HI_ERR_SUCCESS) {
		goto crypto_fail;
	}

crypto_fail:
    (hi_void) hi_cipher_aes_destroy_config();
fail:
    return ret;
}


#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
