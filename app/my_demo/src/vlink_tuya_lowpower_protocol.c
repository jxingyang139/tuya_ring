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
#include "vlink_tuya_lowpower_protocol.h"
#include <mbedtls/base64.h>
#include "vlink_hichannel_util.h"
#include <hi_cipher.h>


#ifndef CONFIG_FACTORY_TEST_MODE
#include "lwip/netifapi.h"
#include "lwip/api_shell.h"
#include "lwip/sockets.h"
#ifdef CONFIG_IPERF_SUPPORT
#include "iperf.h"
#endif
#endif
#ifdef CONFIG_SIGMA_SUPPORT
#include "hi_wifitest.h"
#endif
#include "hi_config.h"
#include "sal_common.h"
#include "cJSON.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


//FIXME
hi_uchar g_local_key[16] = {0x23, 0xac, 0x7b, 0x15, 0x0d, 0x89, 0x34,
				 			0x92, 0xf1, 0x19, 0x33, 0xde, 0xc8, 0x6a,
				 			0x10, 0x55};
hi_char g_utc_time[16]={"1322343458"};

/*key*/
hi_u8 const fixed_key[16] = {0x23, 0xac, 0x7b, 0x15, 0x0d, 0x89, 0x34,
				 0x92, 0xf1, 0x19, 0x33, 0xde, 0xc8, 0x6a,
				 0x10, 0x55};

/*iv*/
hi_u8 const fixed_iv[16] = {0x1e, 0x25, 0x77, 0xb8, 0x66, 0xc1, 0x10, 
				0x33, 0x93, 0x69, 0xcb, 0xa8, 0x2c, 0x54,
				0xe5, 0xab};


/*heartbeat data packets*/
hi_u8 const heartbeat_packet[5] ={0x1, 0x2, 0x0, 0x0, 0x0};

/*wakeup host data packets*/
hi_u8 const wakeup_packet[9] ={0x1, 0x3, 0x0, 0x0, 0x4, 0x11, 0x23, 0xab, 0xbf};

link_payload_packets g_payload_pkg;


hi_u32 tuya_ipc_device_id_get(hi_uchar *str);
hi_u32 tuya_parse_payload_data(hi_char *rw_data, hi_char *random, hi_char *author, hi_char *signature);
hi_u32 tuya_gen_payload_data(link_payload_data_packets *payloa_data, hi_uchar *buffer);


/*authentication data packet*/
hi_u32 tuya_generate_authention_request(hi_uchar *buf)
{
    size_t len;
	hi_u32 ret;
	hi_uchar encry_devid[64];
	hi_uchar buffer[192];
	hi_uchar encry_buffer[192];
	//hi_char author[96] = {"time="};
	hi_uchar encry_sha256[32];
	//hi_char encry_base64[128];
	hi_uchar key[16];

	link_packets_header g_header_pkg;

	/*step1: generate iv random size*/
	(hi_void) memset_s(g_payload_pkg.iv, sizeof(g_payload_pkg.iv), 0, sizeof(g_payload_pkg.iv));
	(hi_void)hi_cipher_trng_get_random_bytes(g_payload_pkg.iv, IV_RANDOM_STRING_SIZE);
	g_payload_pkg.iv_len = IV_RANDOM_STRING_SIZE;

	MLOGD("g_payload_pkg.iv = %s g_payload_pkg.iv_len =%d\n",g_payload_pkg.iv, g_payload_pkg.iv_len);

	/*step2: get devID data*/
	//FIXME:this code will be change in release version
	(hi_void) memset_s(g_payload_pkg.row_devid, sizeof(g_payload_pkg.row_devid), 0, sizeof(g_payload_pkg.row_devid));
	tuya_ipc_device_id_get(g_payload_pkg.row_devid);

	MLOGE("g_payload_pkg.devid = %s\n",g_payload_pkg.row_devid);

	/*step3: encrypt devID data with aes_cbc*/
	aes128_cbc_encrypt(g_payload_pkg.row_devid, fixed_key, fixed_iv, encry_devid);
	/*origin devid encrypt with base64,the output size increase 33%*/
	ret = mbedtls_base64_encode(g_payload_pkg.encry_devid, sizeof(g_payload_pkg.encry_devid), &len, encry_devid, strlen(encry_devid));
    if( ret != 0 ) {
		MLOGE("base64 encode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}
	g_payload_pkg.devid_len = strlen((size_t)g_payload_pkg.encry_devid);

	MLOGE("g_payload_pkg.encry_devid = %s \n",g_payload_pkg.encry_devid);
	MLOGE("encry_devid = %s len =%d\n",encry_devid, len);

	/*step4: get the payload data of authorization string with utc and random*/
	(hi_void)hi_cipher_trng_get_random_bytes(g_payload_pkg.data.random, PAYLOAD_DATA_RANDOM_LEN);
	strcat(g_payload_pkg.data.authorization, "time=");
	strcat(g_payload_pkg.data.authorization, g_utc_time);
	strcat(g_payload_pkg.data.authorization, ",random=");
	strcat(g_payload_pkg.data.authorization, g_payload_pkg.data.random);
	MLOGD(".authorization = %s random=%s\n",g_payload_pkg.data.authorization, g_payload_pkg.data.random);

	/*step5: get the signature row data*/
	strcat(g_payload_pkg.data.row_signature, g_payload_pkg.encry_devid);
	strcat(g_payload_pkg.data.row_signature, g_utc_time);
	strcat(g_payload_pkg.data.row_signature, g_payload_pkg.data.random);

	MLOGE("g_signature = %s\n", g_payload_pkg.data.row_signature);

	/*step6: calc payload g_signature encrypy*/
	hmac_sha256_encrypt(g_payload_pkg.data.row_signature, encry_sha256);
	ret = mbedtls_base64_encode(g_payload_pkg.data.encry_signature, sizeof(g_payload_pkg.data.row_signature),
								&len, encry_sha256, strlen(encry_sha256));
	if( ret != 0 ) {
		MLOGE("base64 encode has failed! ret:\n", ret);
		return HI_ERR_FAILURE;
	}

	MLOGE("g_payload_pkg.data.encry_signature = %s \n ",g_payload_pkg.data.encry_signature);

	/*step7: get the row payload data buffer*/
	(hi_void) memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
	tuya_gen_payload_data(&g_payload_pkg.data, buffer);

	/*step8: encry the payload data*/
	aes128_cbc_encrypt(buffer, g_local_key, g_payload_pkg.iv, encry_buffer);
	/*this data_len need calc the after encrypt data*/
	g_payload_pkg.data_len = strlen(encry_buffer);

	MLOGD("buffer = %s encry_buffer =%d \n",buffer, encry_buffer);

	/*step9: generate header struture*/
	g_header_pkg.version = 1;
	g_header_pkg.type = LP_TYPE_AUTH_REQUEST;
	g_header_pkg.flag = 1;
	g_header_pkg.size = 6 + g_payload_pkg.iv_len + g_payload_pkg.devid_len + g_payload_pkg.data_len;

	/*step10: header data stored the ram for crypto*/
	hi_u32 idx = 0;
	buf[0] = g_header_pkg.version & 0xFF;
	buf[1] = g_header_pkg.type & 0xFF;
	buf[2] = g_header_pkg.flag & 0xFF;
	buf[3] = g_header_pkg.size & 0xFF;
	buf[4] = (g_header_pkg.size >> 8) & 0xFF;
	idx = idx + 5;

	/*payload data of iv stored the ram for crypto*/
	buf[idx++] = g_payload_pkg.iv_len & 0xFF;
	buf[idx++] = (g_payload_pkg.iv_len >> 8) & 0xFF;
	memcpy_s(&buf[idx], g_payload_pkg.iv_len, g_payload_pkg.iv, g_payload_pkg.iv_len);
	idx += g_payload_pkg.iv_len;

	/*payload data of devid stored the ram for crypto*/
	buf[idx++] = g_payload_pkg.devid_len & 0xFF;
	buf[idx++] = (g_payload_pkg.devid_len >> 8) & 0xFF;
	memcpy_s(&buf[idx], g_payload_pkg.devid_len, g_payload_pkg.encry_devid, g_payload_pkg.devid_len);
	idx += g_payload_pkg.devid_len;

	/*payload data of data stored the ram for crypto*/
	buf[idx++] = g_payload_pkg.data_len & 0xFF;
	buf[idx++] = (g_payload_pkg.data_len >> 8) & 0xFF;
	memcpy_s(&buf[idx], g_payload_pkg.data_len, encry_buffer, g_payload_pkg.data_len);
	idx += g_payload_pkg.data_len;

	MLOGD("buf = %s  \n", buf);
	return HI_ERR_SUCCESS;
}


hi_u32 tuya_authention_pkg_response(hi_uchar *buf)
{
	hi_u32 idx;
	hi_uchar decrypt_data[512];
	hi_uchar author[128];
	hi_uchar signature[128];

	link_payload_packets payload;
	hi_uchar rand_str[32];
	hi_uchar utc_str[16];
	hi_uchar calc_sign[128];

	hi_uchar hash_sha256[32];
	hi_uchar hash_base64[64];

    size_t len;
	hi_u32 ret;

	/*get iv data packets*/
	payload.iv_len = buf[5] + (buf[6] << 8);
	memcpy_s(payload.iv, payload.iv_len, &buf[7], payload.iv_len);
	idx = 8 + payload.iv_len;

	/*get devid data packets*/
	payload.devid_len = buf[idx] + (buf[idx + 1] << 8);
	memcpy_s(payload.encry_devid, payload.devid_len, &buf[idx + 2], payload.devid_len);
	idx = idx + payload.devid_len + 2;

	/*decrypt data frist, two bytes is len*/
	idx = idx + 2;
	aes128_cbc_decrypt(&buf[idx], g_local_key, payload.iv, decrypt_data);

	/*parse payload data*/
	tuya_parse_payload_data(decrypt_data, rand_str, author, signature);

	/*compare payload data's random string*/
	if(!memcmp(g_payload_pkg.data.random, rand_str, strlen(rand_str))) {
		MLOGE("random string compare fail! random = %s g_rand_str =%s\n", g_payload_pkg.data.random, rand_str);
		return HI_ERR_FAILURE;
	}

	/*extra the utc time and random strign in authorzation string*/
	strncpy(utc_str, author + 5, strlen(g_utc_time));
	strncpy(rand_str, author + strlen(g_utc_time) + 5 + 7, 32);

	/*generate the "devid:time:random" pattern*/
	strcat(calc_sign, payload.encry_devid);
	strcat(calc_sign, utc_str);
	strcat(calc_sign, rand_str);

	/*data signature encrypt: 1.hmac sha256 2.base 64*/
	ret = hmac_sha256_encrypt(calc_sign, hash_sha256);
	if( ret != HI_ERR_SUCCESS ) {
		MLOGE("base64 encode has failed! ret:\n", ret);
		return HI_ERR_FAILURE;
	}
	ret = mbedtls_base64_encode(hash_base64, sizeof(hash_base64), &len, hash_sha256, strlen(hash_sha256));
	if( ret != HI_ERR_SUCCESS ) {
		MLOGE("base64 encode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}

	/*compare signature with calc result*/
	if(!memcmp(signature, hash_base64, strlen(signature))) {
		MLOGE("signature failed! hash_base64 = %s g_payload_pkg.data.encry_signature =%s\n", hash_base64, g_payload_pkg.data.encry_signature);
		return HI_ERR_FAILURE;
	}

	return HI_ERR_SUCCESS;
}


/*
	generate json file as the playload data 
	@PARAM
	*sign: it's encrypt data [input]
	*data: member of playload data, without encrypt now
*/
hi_u32 tuya_gen_payload_data(link_payload_data_packets *payloa_data, hi_uchar *buffer)
{
	hi_u32 datalen;
	cJSON *pJsonRoot = NULL;
	cJSON *pJson = NULL;

	pJsonRoot = cJSON_CreateObject();

	cJSON_AddNumberToObject(pJsonRoot, "type", payloa_data->type);
	cJSON_AddNumberToObject(pJsonRoot, "method", payloa_data->method);
	cJSON_AddStringToObject(pJsonRoot, "authorization", payloa_data->authorization);
	/*signature must be encrypt*/
	cJSON_AddStringToObject(pJsonRoot, "signature", payloa_data->encry_signature);
	
	pJson = cJSON_Print(pJsonRoot);
	printf("Json:\r\n %s \r\n len = %d\n", pJson, strlen((char*)pJson));

	/*store the json file to memory for server*/
	datalen = strlen(pJson);
	memcpy_s(buffer, datalen, pJson, datalen);

	free(pJson);
	cJSON_Delete(pJsonRoot);
	return HI_ERR_SUCCESS;
}

hi_u32 tuya_parse_payload_data(hi_char *rw_data, hi_char *random, hi_char *author, hi_char *signature)
{
	cJSON* root;
	cJSON* item;
	hi_u32 err;
	hi_u32 interval;

	root = cJSON_Parse(rw_data); 
	if(!root) {
		printf(":parseJson---Parse fail\n");
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "err");
	if(cJSON_IsString(item)) {
		err = item->valueint;
		if(err) {
			printf(":server---err code was set from server!\n");
			return HI_ERR_FAILURE;
		}
	} else {
		printf(":parseJson-err--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}
	
	item = cJSON_GetObjectItem(root, "interval");
	if(cJSON_IsString(item)) {
		interval = item->valueint;
	} else {
		printf(":parseJson-interval--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "random");
	if((item) && (item->valuestring) && (0 != strlen(item->valuestring)) && ((HI_WIFI_MAX_SSID_LEN + 1) > strlen(item->valuestring))) {
		memcpy(random, item->valuestring, strlen(item->valuestring));
	} else {
		printf(":parseJson-random--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "authorization");
	if((cJSON_IsString(item))&& (item->valuestring) && (0 != strlen(item->valuestring)) && ((HI_WIFI_MAX_SSID_LEN + 1) > strlen(item->valuestring))) {
		memcpy(author, item->valuestring, strlen(item->valuestring));
	} else {
		printf(":parseJson-authorization--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "signature");
	if((cJSON_IsString(item))&& (item->valuestring) && (0 != strlen(item->valuestring)) && ((HI_WIFI_MAX_SSID_LEN + 1) > strlen(item->valuestring))) {
		memcpy(signature, item->valuestring, strlen(item->valuestring));
	} else {
		printf(":parseJson-signature--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	printf("[%d] [%d] [%s] [%s] [%s]\n", err, interval, random, author, signature);
	cJSON_Delete(root);
	return HI_ERR_SUCCESS;
}


hi_u8 *tuya_get_heart_beat_packet()
{
	return heartbeat_packet;
}


hi_u8 *tuya_get_wake_up_packet()
{
	return wakeup_packet;
}


//FIXME:this code will be change in release version
hi_u32 tuya_ipc_device_id_get(hi_uchar *str)
{
	hi_cipher_trng_get_random_bytes(str, 32);
	return HI_ERR_SUCCESS;
}

//FIXME:this code will be change in release version
hi_u32 tuya_ipc_local_key_get(hi_uchar *str)
{
	str = g_local_key;
	return HI_ERR_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
