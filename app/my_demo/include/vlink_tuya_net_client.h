#ifndef __TUYA_NET_CLIENT_H__
#define __TUYA_NET_CLIENT_H__


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


#define VLINK_TASK_STAK_SIZE     (1024*20)
#define VLINK_TASK_PRIORITY      25
#define VLINK_WAIT_TIME          HI_SYS_WAIT_FOREVER
#define IP_TCP_SERVER_LISTEN_NUM  4           /* TCP Maximum number of clients that can be received by the server */

#define IP_RESV_BUF_LEN           1024        /* IP packet receiving buffer */
#define IP_SEND_BUF_LEN           1024        /* IP packet sending buffer */
#define PRINT_SIZE_MAX            128

hi_u32 start_tuya_tcp_client(const hi_char *ipaddr, hi_u16 port);
hi_u32 start_tuya_tcp_server(hi_u16 local_port);

#endif
