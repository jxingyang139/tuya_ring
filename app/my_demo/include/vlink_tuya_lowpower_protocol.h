#ifndef __TUYA_WAKEUP_H__
#define __TUYA_WAKEUP_H__

#define IV_RANDOM_STRING_SIZE			16
#define PAYLOAD_DATA_AUTHORIZATION_LEN	128
#define PAYLOAD_DATA_SIGNATURE_LEN		128
#define PAYLOAD_DATA_UTC_TIME_LEN		16
#define PAYLOAD_DATA_RANDOM_LEN			32
#define PAYLOAD_DEVID_STRING_SIZE		32


typedef struct {
    hi_u8 type;
    hi_u8 method;
    hi_uchar authorization[PAYLOAD_DATA_AUTHORIZATION_LEN];
    hi_uchar row_signature[PAYLOAD_DATA_SIGNATURE_LEN];
	hi_uchar encry_signature[PAYLOAD_DATA_SIGNATURE_LEN];
	hi_uchar time[PAYLOAD_DATA_UTC_TIME_LEN];
	hi_uchar random[PAYLOAD_DATA_RANDOM_LEN+1];
} link_payload_data_packets;


typedef struct {
    hi_u16 iv_len;
    hi_uchar iv[IV_RANDOM_STRING_SIZE+1];
    hi_u16 devid_len;
    hi_uchar row_devid[PAYLOAD_DEVID_STRING_SIZE+1];
    hi_uchar encry_devid[PAYLOAD_DEVID_STRING_SIZE*2];
	hi_u16 data_len;
	link_payload_data_packets data;
} link_payload_packets;


typedef struct {
    hi_u8 version;
    hi_u8 type;
    hi_u8 flag;
    hi_u16 size;
} link_packets_header;


typedef enum {
    LP_TYPE_AUTH_REQUEST = 0,
    LP_TYPE_AUTH_RESPONSE  = 1,
    LP_TYPE_HEARTBEAT  = 2,
    LP_TYPE_WAKEUP = 3,
} TUYA_LINK_VERSION;




hi_u32 hmac_sha256_encrypt(hi_uchar *src, hi_uchar *hash);
hi_u32 aes128_cbc_decrypt(hi_uchar *sr_content, hi_u8 *key, hi_u8 *iv, hi_uchar *des_content);
hi_u32 aes128_cbc_encrypt(hi_uchar *sr_content, hi_u8 *key, hi_u8 *iv, hi_uchar *des_content);
hi_u32 tuya_generate_authention_request(hi_uchar *buf);
hi_u32 tuya_authention_pkg_response(hi_uchar *buf);


#endif
