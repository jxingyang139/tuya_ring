/*****************************************
for tuya low power wake up ways
******************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <hi_cpu.h>
#include <hi_crash.h>
#include <hi_mem.h>
#include <hi_mux.h>
#include <hi_os_stat.h>
#include <hi_reset.h>
#include <hi_stdlib.h>
#include <hi_task.h>
#include <hi_time.h>
#include <hi_ver.h>
#include <hi_wifi_api.h>
#include <mbedtls/base64.h>
#include <hi_cipher.h>
#include "vlink_tuya_lowpower_protocol.h"
#include "vlink_hichannel_util.h"
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
hi_u32 tuya_parse_payload_data(hi_uchar *rw_data, hi_uchar *random, hi_uchar *author, hi_uchar *signature);
hi_u32 tuya_gen_payload_data(link_payload_data_packets *payloa_data, hi_uchar *buffer);
hi_bool cipher_get_random_bytes(hi_uchar *str, hi_u8 len);


/*authentication data packet*/
hi_u32 tuya_send_authention_request(hi_uchar *buf)
{
    size_t len;
	hi_u32 ret;
	hi_uchar aes_devid[128];
	hi_uchar data_buffer[512];
	hi_uchar data_encry_buffer[512];
	hi_uchar hash_sha256[HASH_SHA256_LEN];
	link_packets_header g_header_pkg;
	hi_u32 aes_out_len;

	/*step1: generate iv random size*/
	g_payload_pkg.data.type = 1;
	g_payload_pkg.data.method = 1;
	
	(hi_void) memset_s(g_payload_pkg.iv, sizeof(g_payload_pkg.iv), 0, sizeof(g_payload_pkg.iv));
	(hi_void)cipher_get_random_bytes(g_payload_pkg.iv, IV_RANDOM_STRING_SIZE);
	g_payload_pkg.iv_len = IV_RANDOM_STRING_SIZE;

	/*step2: get devID data*/
	//FIXME:this code will be change in release version
	(hi_void) memset_s(g_payload_pkg.row_devid, sizeof(g_payload_pkg.row_devid), 0, sizeof(g_payload_pkg.row_devid));
	tuya_ipc_device_id_get(g_payload_pkg.row_devid);
	g_payload_pkg.row_devid_len = PAYLOAD_DEVID_STRING_LEN;

	/*step3: encrypt devID data with aes_cbc, need recalc padding size*/
	aes_out_len = g_payload_pkg.row_devid_len + PADDING_BLOCK_SIZE - (g_payload_pkg.row_devid_len % PADDING_BLOCK_SIZE);
	(hi_void) memset_s(aes_devid, sizeof(aes_devid), 0, sizeof(aes_devid));
	ret = aes128_cbc_encrypt(g_payload_pkg.row_devid, g_payload_pkg.row_devid_len, fixed_key, fixed_iv, aes_devid, aes_out_len);
	if( ret != HI_ERR_SUCCESS ) {
		MLOGE("aes128_cbc_encrypt encode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}
	(hi_void) memset_s(g_payload_pkg.encry_devid, sizeof(g_payload_pkg.encry_devid), 0, sizeof(g_payload_pkg.encry_devid));
	ret = mbedtls_base64_encode(g_payload_pkg.encry_devid, sizeof(g_payload_pkg.encry_devid), &len, aes_devid, aes_out_len);
    if( ret != HI_ERR_SUCCESS ) {
		MLOGE("base64 encode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}
	g_payload_pkg.encry_devid_len = strlen((size_t)g_payload_pkg.encry_devid);
	MLOGE("g_payload_pkg.iv_len = %d\n", g_payload_pkg.iv_len);
	MLOGE("g_payload_pkg.row_devid_len = %d\n", g_payload_pkg.row_devid_len);
	MLOGE("aes_out_len = %d\n", aes_out_len);
	MLOGE("g_payload_pkg.encry_devid = %s\n", g_payload_pkg.encry_devid);
	MLOGE("g_payload_pkg.encry_devid_len = %d\n", g_payload_pkg.encry_devid_len);

	/*step4: get the payload data of authorization string with utc and random*/
	(hi_void)cipher_get_random_bytes(g_payload_pkg.data.random, PAYLOAD_DATA_RANDOM_LEN);
	strcat(g_payload_pkg.data.authorization, "time=");
	strcat(g_payload_pkg.data.authorization, g_utc_time);
	strcat(g_payload_pkg.data.authorization, ",random=");
	strcat(g_payload_pkg.data.authorization, g_payload_pkg.data.random);

	/*step5: get the signature row data*/
	strcat(g_payload_pkg.data.row_signature, g_payload_pkg.encry_devid);
	strcat(g_payload_pkg.data.row_signature, g_utc_time);
	strcat(g_payload_pkg.data.row_signature, g_payload_pkg.data.random);
	MLOGD("g_payload_pkg.data.random len = %d\n", strlen(g_payload_pkg.data.random));
	MLOGD("g_payload_pkg.data.authorization len = %d\n", strlen(g_payload_pkg.data.authorization));
	MLOGD("g_payload_pkg.data.row_signature len = %d\n", strlen(g_payload_pkg.data.row_signature));

	/*step6: calc payload g_signature encrypy*/
	(hi_void) memset_s(hash_sha256, sizeof(hash_sha256), 0, sizeof(hash_sha256));
	ret = hmac_sha256_encrypt(g_payload_pkg.data.row_signature, hash_sha256);
	if( ret != HI_ERR_SUCCESS ) {
		MLOGE("hmac_sha256_encrypt encode has failed! ret: 0x%x\n", ret);
		return HI_ERR_FAILURE;
	}
	for(int i = 0; i<32; i++)
	{
		if(i%8 == 0)
			printf("\n");
		printf("hash_sha256[%d]=%d ",i,hash_sha256[i]);
	}
	printf("\n");

	ret = mbedtls_base64_encode(g_payload_pkg.data.encry_signature, sizeof(g_payload_pkg.data.encry_signature),
								&len, hash_sha256, HASH_SHA256_LEN);
	if( ret != 0 ) {
		MLOGE("base64 encode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}

	/*step7: get the row payload data buffer*/
	(hi_void) memset_s(data_buffer, sizeof(data_buffer), 0, sizeof(data_buffer));
	len = tuya_gen_payload_data(&g_payload_pkg.data, data_buffer);

	/*step8: encry the payload data*/
	aes_out_len = len + PADDING_BLOCK_SIZE - (len % PADDING_BLOCK_SIZE);
	(hi_void) memset_s(data_encry_buffer, sizeof(data_encry_buffer), 0, sizeof(data_encry_buffer));
	ret = aes128_cbc_encrypt(data_buffer, len, g_local_key, g_payload_pkg.iv, data_encry_buffer, aes_out_len);
	if( ret != HI_ERR_SUCCESS ) {
		MLOGE("aes128_cbc_encrypt encode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}
	g_payload_pkg.data_len = aes_out_len;
	MLOGD("hash_sha256 len = %d\n ", strlen(hash_sha256));
	MLOGD("g_payload_pkg.data.encry_signature: %s len = %d\n ", g_payload_pkg.data.encry_signature, strlen(g_payload_pkg.data.encry_signature));
	MLOGD("payload row date len = %d\n ", len);
	MLOGD("payload encry date len = %d\n ", aes_out_len);

	/*step9: generate header struture*/
	g_header_pkg.version = 1;
	g_header_pkg.type = LP_TYPE_AUTH_REQUEST;
	g_header_pkg.flag = 1;
	g_header_pkg.size = 6 + g_payload_pkg.iv_len + g_payload_pkg.encry_devid_len + g_payload_pkg.data_len;

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
	buf[idx++] = g_payload_pkg.encry_devid_len & 0xFF;
	buf[idx++] = (g_payload_pkg.encry_devid_len >> 8) & 0xFF;
	memcpy_s(&buf[idx], g_payload_pkg.encry_devid_len, g_payload_pkg.encry_devid, g_payload_pkg.encry_devid_len);
	idx += g_payload_pkg.encry_devid_len;

	/*payload data of data stored the ram for crypto*/
	buf[idx++] = g_payload_pkg.data_len & 0xFF;
	buf[idx++] = (g_payload_pkg.data_len >> 8) & 0xFF;
	memcpy_s(&buf[idx], g_payload_pkg.data_len, data_encry_buffer, g_payload_pkg.data_len);
	idx += g_payload_pkg.data_len;

	MLOGD("g_header_pkg.size = %d\n", g_header_pkg.size);
	MLOGD("idx = %d\n", idx);

	for(int i = 0;i<idx;i++)
	{
		if(i%8 == 0)
			printf("\n");
		printf("buf[%d]=%d ",i,buf[i]);
	}
	printf("\n");

	return HI_ERR_SUCCESS;
}


hi_u32 tuya_recevie_authention_response(hi_uchar *buf)
{
	size_t len;
	hi_u32 ret;

	hi_u32 idx;
	hi_uchar *cipher_payload_data;
	hi_uchar decrypt_data[512];
	hi_uchar author[256];
	hi_uchar signature[256];

	link_payload_packets payload;
	hi_uchar rand_str[64];
	hi_uchar utc_str[16];
	hi_uchar calc_sign[256];

	hi_uchar hash_sha256[HASH_SHA256_LEN];
	hi_uchar hash_base64[HASH_SHA256_LEN*4];

	/*get iv data packets*/
	payload.iv_len = buf[5] + (buf[6] << 8);
	memcpy_s(payload.iv, payload.iv_len, &buf[7], payload.iv_len);

	/*get devid data packets*/
	idx = 7 + payload.iv_len;
	payload.encry_devid_len = buf[idx] + (buf[idx + 1] << 8);
	memcpy_s(payload.encry_devid, payload.encry_devid_len, &buf[idx + 2], payload.encry_devid_len);

	/*decrypt data frist, two bytes is len*/
	idx = idx + payload.encry_devid_len + 2;
	payload.data_len = buf[idx] + (buf[idx+1] << 8);
	MLOGD("payload.data_len = %d\n ", payload.data_len );
	MLOGD("idx = %d\n ", idx);
	(hi_void) memset_s(decrypt_data, sizeof(decrypt_data), 0, sizeof(decrypt_data));
	cipher_payload_data = hi_malloc(HI_MOD_ID_APP_COMMON, payload.data_len); 
	if(!cipher_payload_data) {
		MLOGD("hi_malloc error!");
		return HI_ERR_FAILURE;
	}
	memcpy_s(cipher_payload_data, payload.data_len, &buf[idx + 2], payload.data_len);
	ret = aes128_cbc_decrypt(cipher_payload_data, payload.data_len, g_local_key, payload.iv, decrypt_data);
	if( ret != HI_ERR_SUCCESS ) {
		hi_free(HI_MOD_ID_APP_COMMON, cipher_payload_data);
		MLOGE("aes128_cbc_decrypt decode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}
	hi_free(HI_MOD_ID_APP_COMMON, cipher_payload_data);

	MLOGD("payload iv_len = %d\n ", payload.iv_len);
	MLOGD("payload encry_devid_len = %d\n ", payload.encry_devid_len);
	MLOGD("payload data_len = %d\n ", payload.data_len);

	/*parse payload data*/
	ret = tuya_parse_payload_data(decrypt_data, rand_str, author, signature);
	if( ret != HI_ERR_SUCCESS ) {
		MLOGE("tuya_parse_payload_data has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}

	/*compare payload data's random string*/
	/*if(!memcmp(g_payload_pkg.data.random, rand_str, strlen(rand_str))) {
		MLOGE("random string compare fail! random = %s g_rand_str =%s\n", g_payload_pkg.data.random, rand_str);
		return HI_ERR_FAILURE;
	}
	*/

	/*extra the utc time and random strign in authorzation string*/
	strncpy(utc_str, author + 5, strlen(g_utc_time));
	strncpy(rand_str, author + strlen(g_utc_time) + 5 + 7, 32);

	/*generate the "devid:time:random" pattern*/
	strcat(calc_sign, payload.encry_devid);
	strcat(calc_sign, utc_str);
	strcat(calc_sign, rand_str);

	/*data signature encrypt: 1.hmac sha256 2.base 64*/
	(hi_void) memset_s(hash_sha256, sizeof(hash_sha256), 0, sizeof(hash_sha256));
	ret = hmac_sha256_encrypt(calc_sign, hash_sha256);
	if( ret != HI_ERR_SUCCESS ) {
		MLOGE("base64 encode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}
	ret = mbedtls_base64_encode(hash_base64, sizeof(hash_base64), &len, hash_sha256, HASH_SHA256_LEN);
	if( ret != HI_ERR_SUCCESS ) {
		MLOGE("base64 encode has failed! ret: %d\n", ret);
		return HI_ERR_FAILURE;
	}
	MLOGD("hash_base64: %s\n ", hash_base64);

	/*compare signature with calc result*/
	if(memcmp(signature, hash_base64, strlen(signature))) {
		MLOGE("signature failed! hash_base64: %s hash_base64: %s\n", hash_base64, signature);
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
	cJSON_AddStringToObject(pJsonRoot, "signature", payloa_data->encry_signature);
	
	pJson = cJSON_Print(pJsonRoot);
	MLOGD("Json:\r\n %s \r\nlen = %d\n", pJson, strlen((char*)pJson));

	/*store the json file to memory for server*/
	datalen = strlen(pJson);
	memcpy_s(buffer, datalen, pJson, datalen);

	free(pJson);
	cJSON_Delete(pJsonRoot);
	return datalen;
}

hi_u32 tuya_parse_payload_data(hi_uchar *rw_data, hi_uchar *random, hi_uchar *author, hi_uchar *signature)
{
	cJSON* root;
	cJSON* pJson;
	cJSON* item;
	hi_u32 err;
	hi_u32 interval;

	root = cJSON_Parse(rw_data); 
	if(!root) {
		MLOGE(":parseJson---Parse fail\n");
		return HI_ERR_FAILURE;
	}

	/*
	item = cJSON_GetObjectItem(root, "err");
	if(cJSON_IsString(item)) {
		err = item->valueint;
		if(err) {
			MLOGE(":server---err code was set from server!\n");
			return HI_ERR_FAILURE;
		}
	} else {
		MLOGE(":parseJson-err--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}
	
	item = cJSON_GetObjectItem(root, "interval");
	if(cJSON_IsString(item)) {
		interval = item->valueint;
	} else {
		MLOGE(":parseJson-interval--Parse fail\n");
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
	*/

	item = cJSON_GetObjectItem(root, "authorization");
	if((item != NULL)){//&& (item->valuestring) && (0 != strlen(item->valuestring)) && ((HI_WIFI_MAX_SSID_LEN + 1) > strlen(item->valuestring))) {
		memcpy_s(author, strlen(item->valuestring), item->valuestring, strlen(item->valuestring));
	} else {
		MLOGE(":parseJson-authorization--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "signature");
	if((item != NULL)){//&& (item->valuestring) && (0 != strlen(item->valuestring)) && ((HI_WIFI_MAX_SSID_LEN + 1) > strlen(item->valuestring))) {
		memcpy_s(signature, strlen(item->valuestring), item->valuestring, strlen(item->valuestring));
	} else {
		MLOGE(":parseJson-signature--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	pJson = cJSON_Print(root);
	MLOGD("Json:\r\n %s \r\nlen = %d\n", pJson, strlen((char*)pJson));
	MLOGD("random: [%s]\n author = [%s]\n signature = [%s]\n", random, author, signature);
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


hi_bool cipher_get_random_bytes(hi_uchar *str, hi_u8 len)
{
	hi_u8 idx;
	for(idx = 0; idx < len; idx ++) {
		str[idx] = 'a' + rand()%26;
	}
	return HI_ERR_SUCCESS;
}


//FIXME:this code will be change in release version
hi_u32 tuya_ipc_device_id_get(hi_uchar *str)
{
	cipher_get_random_bytes(str, 32);
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
