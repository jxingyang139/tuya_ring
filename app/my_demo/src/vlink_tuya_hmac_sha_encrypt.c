/*****************************************
for tuya low power wake up ways
******************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <cpup_diag_dfx.h>
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
#include "hi_cipher.h"
#include "vlink_hichannel_util.h"


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


#define HASH_PROC_BLOCK_SIZE 0x100
extern hi_uchar g_local_key[16];

hi_u32 hmac_sha256_encrypt(hi_uchar *src, hi_uchar *hash)
{
	hi_u8 key[16];
	hi_u32 this_size;
	hi_cipher_hash_atts hash_atts;
	uintptr_t src_addr;
	hi_u32 ret;

	src_addr = (uintptr_t)src;
	this_size = strlen(src);

	(hi_void) memset_s(&hash_atts, sizeof(hash_atts), 0, sizeof(hash_atts));
	hash_atts.sha_type = HI_CIPHER_HASH_TYPE_HMAC_SHA256;

	///FixME, will be change in tuya release version
	ret = memcpy_s(hash_atts.hmac_key, sizeof(hash_atts.hmac_key), g_local_key, 16);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("memory copy the key error!\n");
		return ret;
	}

	ret = hi_cipher_hash_start((hi_cipher_hash_atts *)(&hash_atts));
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("cipher start ret: %d\r\n", ret);
		return ret;
	}

	ret = hi_cipher_hash_update((uintptr_t)src_addr, this_size);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("hi_cipher_hash_update ret: %d\r\n", ret);
		return ret;
	}

	ret =hi_cipher_hash_final(hash, sizeof(hash));
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("hi_cipher_hash_final ret: %d\r\n", ret);
		return ret;
	}
	return HI_ERR_SUCCESS;
}


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
