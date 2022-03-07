#ifndef __TUYA_WAKEUP_H__
#define __TUYA_WAKEUP_H__


/*client structure for tcp*/
typedef struct {
    hi_s32 sfd;
    hi_u8 stats;
    hi_u8 mode;
    hi_u8 protocol;
    hi_u8 reserve;
} link_client_stru;

/*server structure for tcp*/
typedef struct {
    hi_s32 sfd;
    hi_u8 stats;
    hi_u8 reserve[3]; /* 3 bytes reserved */
} link_server_stru;


typedef struct {
    hi_u16 iv_len;
    hi_uchar *iv;
    hi_u16 devid_len;
    hi_uchar *devid;
	hi_u16 data_len;
	hi_uchar *data;
} link_payload_packets;


typedef struct {
    hi_u8 version;
    hi_u8 type;
    hi_u8 flag;
    hi_u16 size;
	link_payload_packets payload;
} link_low_power_packets;



typedef enum {
	LINK_STATE_IDLE = 0,		/* Idle state */
	LINK_STATE_WAIT,
	LINK_STATE_USER_CLOSE,			/*user close the client*/
	LINK_STATE_ERR_CLOSE,			/*error cause the client*/
	LINK_STATE_SERVER_LISTEN,
	LINK_STATE_MAX
} LINK_STATE_MACHINE;


typedef enum {
    LINK_MODE_INIT = 0, 	/* Initial Value */
    LINK_MODE_MANUAL  = 1,  /* Creating a Link manually */
    LINK_MODE_AUTO  = 2,    /* Creating Links automatically */
} LINK_WORK_MODE;


typedef enum {
    IP_NULL = 0,
    IP_TCP  = 1,
    IP_UDP  = 2,
} LINK_PROTOCAL;


typedef enum {
    LP_TYPE_AUTH_REQUEST = 0,
    LP_TYPE_AUTH_RESPONSE  = 1,
    LP_TYPE_HEARTBEAT  = 2,
    LP_TYPE_WAKEUP = 3,
} TUYA_LINK_VERSION;


typedef enum {
    CRYPTO_AES_CBC = 0,
    CRYPTO_OFF  = 1,
} TUYA_CRYPTO_TYPE;


#define VLINK_TASK_STAK_SIZE (1024*20)
#define VLINK_TASK_PRIORITY  25
#define VLINK_WAIT_TIME          HI_SYS_WAIT_FOREVER
#define IP_TCP_SERVER_LISTEN_NUM  4           /* TCP Maximum number of clients that can be received by the server */

#define IP_RESV_BUF_LEN           1024        /* IP packet receiving buffer */
#define IP_SEND_BUF_LEN           1024        /* IP packet sending buffer */
#define PRINT_SIZE_MAX            128

#define IV_RANDOM_PKG_SIZE        16

hi_u32 tuya_gen_payload_data(hi_u32 type, hi_u32 method, hi_char *author, hi_char *sign, hi_char *data);

hi_u32 start_tuya_tcp_server(hi_u16 local_port);
hi_u32 start_tuya_tcp_client(const hi_char *ipaddr, hi_u16 port);

hi_char aes_cbc_128_encrypt(hi_char *rw_data, hi_char *encrypt_data);
hi_char hmac_sha_256_encrypt(hi_char *rw_data, hi_char *encrypt_data);
//hi_char base_64_encrypt(hi_char *rw_data, hi_char *encrypt_data);
hi_char aes_cbc_128_decrypt(hi_char *encrypt_data, hi_char *rw_data);
hi_char hmac_sha_256_decrypt(hi_char *encrypt_data, hi_char *rw_data);
hi_char base_64_decrypt(hi_char *encrypt_data, hi_char *rw_data);
hi_u32 tuya_ipc_device_id_get(hi_char *str);


#endif
