#ifndef __TUYA_WAKEUP_H__
#define __TUYA_WAKEUP_H__

#define IV_RANDOM_STRING_SIZE			16
#define PAYLOAD_DATA_AUTHORIZATION_LEN	128
#define PAYLOAD_DATA_SIGNATURE_LEN		256
#define PAYLOAD_DATA_UTC_TIME_LEN		32
#define PAYLOAD_DATA_RANDOM_LEN			32
#define PAYLOAD_DEVID_STRING_LEN		32

#define HASH_SHA256_LEN					32
#define HASH_PROC_BLOCK_SIZE 			256

#define PADDING_BLOCK_SIZE 16


typedef struct {
    hi_u32 type;
    hi_u32 method;
    hi_uchar authorization[PAYLOAD_DATA_AUTHORIZATION_LEN];
    hi_uchar row_signature[PAYLOAD_DATA_SIGNATURE_LEN];
	hi_uchar encry_signature[PAYLOAD_DATA_SIGNATURE_LEN*2];
	hi_uchar time[PAYLOAD_DATA_UTC_TIME_LEN];
	hi_uchar random[PAYLOAD_DATA_RANDOM_LEN*2];
} link_payload_data_packets;


typedef struct {
    hi_u32 iv_len;
    hi_uchar iv[IV_RANDOM_STRING_SIZE];
	hi_u32 row_devid_len;
    hi_uchar row_devid[PAYLOAD_DEVID_STRING_LEN];
    hi_u32 encry_devid_len;
    hi_uchar encry_devid[(PAYLOAD_DEVID_STRING_LEN+PADDING_BLOCK_SIZE)*2];
	hi_u32 data_len;
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


hi_u32 tuya_send_heart_beat_packet(hi_uchar *buf);
hi_u32 tuya_recevie_wake_up_packet(hi_uchar *buf);
hi_u32 tuya_receive_heart_beat_packet(hi_uchar *buf);

hi_u32 hmac_sha256_encrypt(hi_uchar *src, hi_uchar *hash);
hi_u32 aes128_cbc_decrypt(hi_uchar *sr_content, hi_u32 src_len, hi_u8 *key, hi_u8 *iv, hi_uchar *des_content);
hi_u32 aes128_cbc_encrypt(hi_uchar *sr_content, hi_u32 sr_len, hi_u8 *key, hi_u8 *iv, hi_uchar *des_content, hi_u32 des_len);
hi_s32 tuya_send_authention_request(hi_uchar *buf);
hi_u32 tuya_recevie_authention_response(hi_uchar *buf);
void pkcs7_padding(hi_char * buf, int buflen, int blocksize, hi_char * paddingBuf);


#endif
