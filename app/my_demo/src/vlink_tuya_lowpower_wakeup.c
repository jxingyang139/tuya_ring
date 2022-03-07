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
#include "vlink_tuya_lowpower_wakeup.h"
#include "mbedtls/base64.h"

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

#define HI_WIFI_MAX_SSID_LEN 256

static link_client_stru g_client_link;
static link_server_stru g_server_link;
static hi_s8 g_task_on;
static hi_u32 g_ip_mux_id;
hi_u32 g_tuya_heartbeat_task_id = 0;

/*auth packets*/
link_low_power_packets g_auth_pkt;
link_payload_packets g_payload_pkt;

hi_char g_rand_str[32];
hi_char g_utc_time[16];
hi_char g_signature[128];

static hi_void link_monitor_socket(fd_set *read_set, hi_s32 *sfd_max);
static hi_void client_state_machine_check_close(hi_void);
static hi_u32 client_state_machine_check_idle(hi_void);
static hi_u32 tuya_client_show_msg();
static void client_state_machine_set_wait(hi_s32 sfd);
static hi_void client_link_release();
static hi_u32 creat_tuya_client_task(hi_void);
static hi_void server_tcp_accept(hi_void);
static hi_void server_state_machine_check_close(hi_void);


/*key*/
hi_u8 key[16] = {0x23, 0xac, 0x7b, 0x15, 0x0d, 0x89, 0x34,
				 0x92, 0xf1, 0x19, 0x33, 0xde, 0xc8, 0x6a,
				 0x10, 0x55};

/**/
hi_u8 iv[16] = {0x1e, 0x25, 0x77, 0xb8, 0x66, 0xc1, 0x10, 
				0x33, 0x93, 0x69, 0xcb, 0xa8, 0x2c, 0x54,
				0xe5, 0xab};


/*heartbeat data packets*/
hi_u8 const heartbeat_packet[5] ={0x1, 0x2, 0x0, 0x0, 0x0};


/*wakeup host data packets*/
hi_u8 const wakeup_packet[9] ={0x1, 0x3, 0x0, 0x0, 0x4, 0x11, 0x23, 0xab, 0xbf};


/*
	generate json file as the playload data 
	@PARAM
	*sign: it's encrypt data [input]
	*data: member of playload data, without encrypt now
*/
hi_u32 tuya_gen_payload_data(hi_u32 type, hi_u32 method, hi_char *author, hi_char *sign, hi_char *data)
{
	hi_u32 datalen;
	cJSON *pJsonRoot = NULL;
	cJSON *pJson = NULL;

	pJsonRoot = cJSON_CreateObject();

	/*add item*/
	cJSON_AddNumberToObject(pJsonRoot, "type", type);
	cJSON_AddNumberToObject(pJsonRoot, "method", method);
	cJSON_AddStringToObject(pJsonRoot, "authorization", author);
	cJSON_AddStringToObject(pJsonRoot, "signature", sign);
	
	pJson = cJSON_Print(pJsonRoot);
	printf("Json:\r\n %s \r\n len = %d\n", pJson, strlen((char*)pJson));

	/*store the json file to memory for server*/
	datalen = strlen(pJson);
	memcpy_s(data, datalen, pJson, datalen);

	free(pJson);
	cJSON_Delete(pJsonRoot);
	return HI_ERR_SUCCESS;
}

void tuya_parse_payload_data(hi_char *rw_data, hi_char *random, hi_char *author, hi_char *signature)
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
}


/*just as gennerate lowercase for generate the random string*/
hi_bool random_string(hi_u8 len, hi_uchar *str)
{
	hi_u8 idx;
	for(idx = 0; idx < len; idx ++) {
		str[idx] = 'a' + rand()%26;
	}
	return HI_ERR_SUCCESS;
}

/*authentication data packet*/
hi_u32 tuya_generate_authention_request_pgk(char *buf)
{
	char encrypt_data[256];
	char auth_data[256]={"time="};
    size_t len;
	hi_u32 ret;
	hi_char encry_devid[32];

	/*generate iv packet which is 16byte random data*/
	g_payload_pkt.iv = (char *)malloc(IV_RANDOM_PKG_SIZE);
	g_payload_pkt.iv_len = IV_RANDOM_PKG_SIZE;
	random_string(IV_RANDOM_PKG_SIZE, g_payload_pkt.iv);

	//FIXME:this code will be change in release version
	g_payload_pkt.devid = (char)malloc(IV_RANDOM_PKG_SIZE);
	g_payload_pkt.devid_len = strlen(g_payload_pkt.devid); 
	tuya_ipc_device_id_get(g_payload_pkt.devid);

	/*origin devid encrypt with aes_cbc*/
	aes_cbc_128_encrypt(g_payload_pkt.devid, encry_devid);
	/*origin devid encrypt with base64*/
	ret = mbedtls_base64_encode(encry_devid, sizeof(encry_devid), &len, g_payload_pkt.devid, strlen(g_payload_pkt.devid));
    if( ret != 0 ) {
		MLOGE("[%s %d]base64 encode has failed!\n");
		return HI_ERR_FAILURE;
	}

	/*generate the 32byte random str for authorization*/
	random_string(32, g_rand_str);

	/*get the signature original data*/
	strcat(g_signature, encry_devid);
	strcat(g_signature, g_utc_time);
	strcat(g_signature, g_rand_str);

	//FixMe, my be need change for size
	/*row signature data encrypt: 1.hmac sha256 2.base 64*/
	g_payload_pkt.data = (char *)malloc(256);
	hmac_sha_256_encrypt(g_signature, encrypt_data);
	ret = mbedtls_base64_encode(encrypt_data, sizeof(encrypt_data), &len, g_signature, strlen(g_signature));
    if( ret != 0 ) {
		MLOGE("base64 encode has failed!\n");
		return HI_ERR_FAILURE;
	}

	/*genrate  row authorization, it's include the utc time and random string*/
	strcat(auth_data, g_utc_time);
	strcat(auth_data, ",random=");
	strcat(auth_data, g_rand_str);
	MLOGD("auth_data = %s",auth_data);

	/*generate payload data*/
	tuya_gen_payload_data(1, 1, auth_data, g_signature, g_payload_pkt.data);
	g_payload_pkt.data_len = strlen(g_payload_pkt.data);
	/*payload data encrypt*/
	aes_cbc_128_encrypt(g_payload_pkt.data, encrypt_data);
	memcpy_s(g_payload_pkt.data, g_payload_pkt.data_len, encrypt_data, g_payload_pkt.data_len);

	g_auth_pkt.version = 1;
	g_auth_pkt.type = LP_TYPE_AUTH_REQUEST;
	g_auth_pkt.flag = 1;
	g_auth_pkt.size = 6 + g_payload_pkt.iv_len + g_payload_pkt.devid_len + g_payload_pkt.data_len;
	g_auth_pkt.payload = g_payload_pkt;

	/*header data stored the ram for crypto*/
	hi_u32 idx = 0;
	buf[0] = g_auth_pkt.version & 0xFF;
	buf[1] = g_auth_pkt.type & 0xFF;
	buf[2] = g_auth_pkt.flag & 0xFF;
	buf[3] = g_auth_pkt.size & 0xFF;
	buf[4] = (g_auth_pkt.size >> 8) & 0xFF;
	idx = idx + 5;

	/*payload data of iv stored the ram for crypto*/
	buf[idx++] = g_payload_pkt.iv_len & 0xFF;
	buf[idx++] = (g_payload_pkt.iv_len >> 8) & 0xFF;
	memcpy_s(&buf[idx], g_payload_pkt.iv_len, g_payload_pkt.iv, g_payload_pkt.iv_len);
	idx += g_payload_pkt.iv_len;

	/*payload data of devid stored the ram for crypto*/
	buf[idx++] = g_payload_pkt.devid_len & 0xFF;
	buf[idx++] = (g_payload_pkt.devid_len >> 8) & 0xFF;
	memcpy_s(&buf[idx], g_payload_pkt.devid, g_payload_pkt.devid, g_payload_pkt.devid_len);
	idx += g_payload_pkt.devid_len;

	/*payload data of data stored the ram for crypto*/
	buf[idx++] = g_payload_pkt.data_len & 0xFF;
	buf[idx++] = (g_payload_pkt.data_len >> 8) & 0xFF;
	memcpy_s(&buf[idx], g_payload_pkt.data_len, g_payload_pkt.data, g_payload_pkt.data_len);
	idx += g_payload_pkt.data_len;

	return HI_ERR_SUCCESS;
}


void tuya_release_authention_request_pgk()
{
	free(g_payload_pkt.iv);
	g_auth_pkt.version = 0;
	g_auth_pkt.flag = 0;
	g_auth_pkt.size = 0;
}


hi_char *tuya_get_heart_beat_packet()
{
	return heartbeat_packet;
}


hi_char *tuya_get_wake_up_packet()
{
	return wakeup_packet;
}


hi_u32 tuya_authention_pkg_response(hi_char *buf)
{
	hi_u32 idx;
	hi_char decrypt_data[512];
	hi_char encrypt_data[512];
	hi_char author[128];
	hi_char signature[128];
	link_low_power_packets pwd_pkt;
	link_payload_packets payload;
	hi_char rand_str[32];
	hi_char utc_str[16];
	hi_char calc_sign[128];
    size_t len;
	hi_u32 ret;

	/*get iv data packets*/
	payload.iv_len = buf[5] + (buf[6] << 8);
	payload.iv = &buf[7];
	idx = 8 + payload.iv_len;

	/*get devid data packets*/
	payload.devid_len = buf[idx] + (buf[idx + 1] << 8);
	payload.devid = &buf[idx + 2];
	idx = idx + payload.devid_len + 2;

	/*decrypt data frist, two bytes is len*/
	idx = idx + 2;
	aes_cbc_128_decrypt(&buf[idx], decrypt_data);

	/*parse payload data*/
	tuya_parse_payload_data(decrypt_data, rand_str, author, signature);

	/*compare payload data's random string*/
	if(!memcmp(g_rand_str, rand_str, strlen(g_rand_str))) {
		MLOGE("random string compare fail! random = %s g_rand_str =%s\n", rand_str, g_rand_str);
		return HI_ERR_FAILURE;
	}

	/*extra the utc time and random strign in authorzation string*/
	strncpy(utc_str, author + 5, strlen(g_utc_time));
	strncpy(rand_str, strlen(g_utc_time) + 5 + 7, 32);

	/*generate the "devid:time:random" pattern*/
	strcat(calc_sign, payload.devid);
	strcat(calc_sign, utc_str);
	strcat(calc_sign, rand_str);

	/*data signature encrypt: 1.hmac sha256 2.base 64*/
	hmac_sha_256_encrypt(calc_sign, encrypt_data);
	ret = mbedtls_base64_encode(encrypt_data, sizeof(encrypt_data), &len, calc_sign, strlen(calc_sign));
    if( ret != 0 ) {
		MLOGE("base64 encode has failed! encrypt_data =%s calc_sign =%s\n", encrypt_data, calc_sign);
		return HI_ERR_FAILURE;
	}

	/*compare signature with calc result*/
	if(!memcmp(g_signature, calc_sign, strlen(g_signature))) {
		MLOGE("signature failed! random = %s g_rand_str =%s\n", calc_sign, g_signature);
		return HI_ERR_FAILURE;
	}

	return HI_ERR_SUCCESS;
}



hi_char aes_cbc_128_encrypt(hi_char *rw_data, hi_char *encrypt_data)
{
	;
}


hi_char hmac_sha_256_encrypt(hi_char *rw_data, hi_char *encrypt_data)
{
	;
}

hi_char aes_cbc_128_decrypt(hi_char *encrypt_data, hi_char *rw_data)
{
	;
}

hi_char hmac_sha_256_decrypt(hi_char *encrypt_data, hi_char *rw_data)
{
	;
}


/*3861 is client, connect tuya server*/
hi_u32 start_tuya_tcp_client(const hi_char *ipaddr, hi_u16 port)
{
    hi_s32 ret;
    hi_u32 opt = 0;
    hi_s32 tos;
    struct sockaddr_in srv_addr = {0};

    /*create 3861 client*/
    hi_s32 sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        printf("{[%s %d]: socket fail}\r\n",__FUNCTION__,__LINE__);
        return HI_ERR_FAILURE;
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    tos = 128; 
    ret = setsockopt(sfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    if (ret) {
        printf("{[%s %d]: setsockopt TOPS fail fail}\r\n",__FUNCTION__,__LINE__);
        closesocket(sfd);
        return HI_ERR_FAILURE;
    }

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = inet_addr(ipaddr);
    srv_addr.sin_port = htons(port);
    ret = connect(sfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    if (ret != 0) {
		printf("{[%s %d]: connect fail} ret =%d\r\n",__FUNCTION__,__LINE__,ret);
        closesocket(sfd);
        return HI_ERR_FAILURE;
    }

	/*set the socket state machine as wait*/
	client_state_machine_set_wait(sfd);

	/*process rec or send data*/
    if (creat_tuya_client_task() != HI_ERR_SUCCESS) {
        hi_mux_pend(g_ip_mux_id, VLINK_WAIT_TIME);
        client_link_release();
        hi_mux_post(g_ip_mux_id);
        printf("{start_tuya_tcpip_client: creat tuya task fail}\r\n");
        return HI_ERR_FAILURE;
    }

	printf("{start_tuya_tcp_client: create link with server is ok!}\r\n", ret);
    return HI_ERR_SUCCESS;
}

hi_u32 start_tuya_tcp_server(hi_u16 local_port)
{
    struct sockaddr_in srv_addr = {0};
    hi_s32 ret;
    hi_u32 opt = 1;

    g_server_link.sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_link.sfd == -1) {
        printf("{ip_tcp_server_start: creat socket failed}\r\n");
        return HI_ERR_FAILURE;
    }

    setsockopt(g_server_link.sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons(local_port);
    ret = bind(g_server_link.sfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    if (ret != 0) {
        printf("{ip_tcp_server_start:bind failed, return is %d}\r\n", ret);

        closesocket(g_server_link.sfd);
        g_server_link.sfd = -1;
        g_server_link.stats = LINK_STATE_IDLE;
        return HI_ERR_FAILURE;
    }

    ret = listen(g_server_link.sfd, IP_TCP_SERVER_LISTEN_NUM);
    if (ret != 0) {
        printf("{ip_tcp_server_start:listen failed, return is %d\n}", ret);

        closesocket(g_server_link.sfd);
        g_server_link.sfd = -1;
        g_server_link.stats = LINK_STATE_IDLE;
        return HI_ERR_FAILURE;
    }

    if (creat_tuya_client_task() != HI_ERR_SUCCESS) {
        printf("{ip_tcp_server_start:ip_creat_ip_task fail}\r\n");
        closesocket(g_server_link.sfd);
        g_server_link.sfd = -1;
        g_server_link.stats = LINK_STATE_IDLE;
        return HI_ERR_FAILURE;
    }

    g_server_link.stats = LINK_STATE_SERVER_LISTEN;

    return HI_ERR_SUCCESS;
}


static hi_void *tuya_heartbeat_task(hi_void *param)
{
	int i;
    hi_s32 sfd_max;
    fd_set read_set;
    struct timeval time_val;
    hi_s32 ret;

	hi_unref_param(param);
	printf("Create the tuya_heartbeat_task \r\n");

    hi_mux_create(&g_ip_mux_id);
    g_task_on = 0;
    while (!g_task_on) {

		hi_cpup_load_check_proc(hi_task_get_current_id(), LOAD_SLEEP_TIME_DEFAULT);

        /* When all links are in the idle state, exit. */
        if (client_state_machine_check_idle() == HI_ERR_SUCCESS) {
            hi_mux_delete(g_ip_mux_id);
            g_task_on = 1;
            continue;
        }

		/*check the client fd need close or not*/
        client_state_machine_check_close();
		server_state_machine_check_close();

		/*select system call, for multi client*/
		sfd_max = 0;
		FD_ZERO(&read_set);

		/*add the socket to the fd set*/
        link_monitor_socket(&read_set, &sfd_max);
        time_val.tv_sec = 0;
        time_val.tv_usec = 500000;
        ret = lwip_select(sfd_max + 1, &read_set, 0, 0, &time_val);
		if(ret > 0)
		{
			hi_mux_pend(g_ip_mux_id, VLINK_WAIT_TIME);
			/*for tuya heartbeat tcp task*/
			if ((g_client_link.stats == LINK_STATE_WAIT) && 
				(FD_ISSET(g_client_link.sfd, &read_set))) {
				tuya_client_show_msg();
			} else if((g_server_link.stats == LINK_STATE_SERVER_LISTEN) && 
						(FD_ISSET(g_server_link.sfd, &read_set))) {
				server_tcp_accept();
			} else {
				;
			}
			hi_mux_post(g_ip_mux_id);
		}
        else if (ret < 0) {
			printf("[%s %d]lwip_select monitor fail!!\r\n",__FUNCTION__, __LINE__);
            goto failure;
        } else {
            continue;
        }
    }
    g_tuya_heartbeat_task_id = -1;

failure:
	if (g_client_link.stats != LINK_STATE_IDLE) {
		client_link_release();
	}
	g_tuya_heartbeat_task_id = - 1;
    hi_mux_delete(g_ip_mux_id);
	printf("{link_monitor : socket select failure\r\n");
}


static hi_u32 creat_tuya_client_task(hi_void)
{
	hi_u32 ret;

	/* Create a task to handle tcp/ip communication */
	hi_task_attr vlinkattr = {0};
	vlinkattr.stack_size = VLINK_TASK_STAK_SIZE;
	vlinkattr.task_prio = VLINK_TASK_PRIORITY - 5;
	vlinkattr.task_name = (hi_char*)"tuya_heartbeat";
	ret = hi_task_create(&g_tuya_heartbeat_task_id, &vlinkattr, tuya_heartbeat_task, HI_NULL);
	if (ret != HI_ERR_SUCCESS) {
		printf("Falied to create tuya_heartbeat_task task!\n");
		return ret;
	}
	printf("[%s %d]creat_tuya_client_task is ok\r\n",__FUNCTION__,__LINE__);
    return HI_ERR_SUCCESS;
}

static hi_u32 tuya_client_show_msg()
{
    struct sockaddr_in cln_addr = {0};
    socklen_t cln_addr_len = (socklen_t)sizeof(cln_addr);
    hi_u32 print_len = 0;
    hi_s32 ret;

    hi_char *ip_buffer = (hi_char*)malloc(IP_RESV_BUF_LEN + 1);
    if (ip_buffer == HI_NULL) {
        printf("{ip_ip_resv_output:ip buffer malloc fail}\r\n");
        return HI_ERR_FAILURE;
    }

    memset_s(ip_buffer, IP_RESV_BUF_LEN + 1, 0, IP_RESV_BUF_LEN + 1);
    errno = 0;
	ret = recvfrom(g_client_link.sfd, ip_buffer, IP_RESV_BUF_LEN, 0,
					(struct sockaddr *)&cln_addr, (socklen_t *)&cln_addr_len);
    if (ret < 0) {
        if ((errno != EINTR) && (errno != EAGAIN)) {
            g_client_link.stats = LINK_STATE_ERR_CLOSE;
        }
        free(ip_buffer);
        return HI_ERR_FAILURE;
    } else if (ret == 0) {
        g_client_link.stats = LINK_STATE_ERR_CLOSE;
        free(ip_buffer);
        return HI_ERR_FAILURE;
    }

    if (ret < PRINT_SIZE_MAX) {
        printf("\r\n+IPD,%d,%s,%d:%s\r\n", ret, inet_ntoa(cln_addr.sin_addr), htons(cln_addr.sin_port),
            ip_buffer);
    } else if ((ret >= PRINT_SIZE_MAX) && (ret <= IP_RESV_BUF_LEN)) {
        printf("\r\n+IPD,%d,%s,%d:", ret, inet_ntoa(cln_addr.sin_addr), htons(cln_addr.sin_port));
        do {
            char print_out_buff[PRINT_SIZE_MAX] = {0};
            if ((memset_s(print_out_buff, sizeof(print_out_buff), 0x0, sizeof(print_out_buff)) != EOK) ||
                (memcpy_s(print_out_buff, sizeof(print_out_buff) - 1, ip_buffer + print_len,
                          sizeof(print_out_buff)-1) != EOK)) {
                printf("{ip_ip_resv_output: print_out_buff memset_s/memcpy_s fail\r\n}");
            }
            printf("%s", print_out_buff);

            ret -= sizeof(print_out_buff) - 1;
            print_len += sizeof(print_out_buff) - 1;
        } while (ret >= (PRINT_SIZE_MAX - 1));

        if (ret > 0) {
            printf("%s", ip_buffer + print_len);
        }
    }
    free(ip_buffer);
    return HI_ERR_SUCCESS;
}



static hi_void server_tcp_accept(hi_void)
{
    struct sockaddr_in cln_addr = {0};
    socklen_t cln_addr_len = (socklen_t)sizeof(cln_addr);
    hi_s32 resv_fd;
    hi_s8 link_id = -1;
    hi_s32 ret;
    hi_u32 send_len;
	hi_char *send_msg = "huawei";
    send_len = strlen(send_msg);

    resv_fd = accept(g_server_link.sfd, (struct sockaddr *)&cln_addr, (socklen_t *)&cln_addr_len);
    if (resv_fd < 0) {
        printf("{accept failed, return is %d}\r\n", resv_fd);
        return;
    }

    ret = send(g_server_link.sfd, send_msg, send_len, 0);
    if (ret <= 0) {
        printf("ERROR\r\n");
        return;
    }
    printf("SEND %d bytes\r\nOK\r\n", ret);

    return;
}



/*add the tuya heartbeat tcp task in fd set*/
static hi_void link_monitor_socket(fd_set *read_set, hi_s32 *sfd_max)
{
    hi_s32 sfd_max_inter = 0;
    hi_u8 i;
    hi_mux_pend(g_ip_mux_id, VLINK_WAIT_TIME);
    if (g_client_link.stats == LINK_STATE_WAIT) {
        FD_SET(g_client_link.sfd, read_set);
        if (g_client_link.sfd > sfd_max_inter) {
            sfd_max_inter = g_client_link.sfd;
        }
    }

    if (g_server_link.stats == LINK_STATE_SERVER_LISTEN) {
        FD_SET(g_server_link.sfd, read_set);
        if (g_server_link.sfd > sfd_max_inter) {
            sfd_max_inter = g_server_link.sfd;
        }
    }

    *sfd_max = sfd_max_inter;
    hi_mux_post(g_ip_mux_id);

    return;
}

static hi_u32 client_state_machine_check_idle(hi_void)
{
    int i;
    hi_mux_pend(g_ip_mux_id, VLINK_WAIT_TIME);

    if (g_client_link.stats != LINK_STATE_IDLE) {
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }

    hi_mux_post(g_ip_mux_id);
    return HI_ERR_SUCCESS;
}


static hi_void client_state_machine_check_close(hi_void)
{
	hi_u8 i;

	if ((g_client_link.stats == LINK_STATE_ERR_CLOSE) ||
		(g_client_link.stats == LINK_STATE_USER_CLOSE)) {
		client_link_release();
		printf("link %d CLOSED\r\n", i);
	}

}

static hi_void server_state_machine_check_close(hi_void)
{
	if (g_server_link.stats == LINK_STATE_ERR_CLOSE) {
		closesocket(g_server_link.sfd);
		g_server_link.sfd = -1;
		g_server_link.stats = LINK_STATE_IDLE;
	} else if (g_server_link.stats == LINK_STATE_USER_CLOSE) {
		closesocket(g_server_link.sfd);
		g_server_link.sfd = -1;
		g_server_link.stats = LINK_STATE_IDLE;
		hi_at_printf("OK\r\n");
	}
}


static void client_state_machine_set_wait(hi_s32 sfd)
{
    hi_mux_pend(g_ip_mux_id, VLINK_WAIT_TIME);
    g_client_link.sfd = sfd;
    g_client_link.stats = LINK_STATE_WAIT;
    g_client_link.mode = LINK_MODE_MANUAL;
    g_client_link.protocol = IP_TCP;
    hi_mux_post(g_ip_mux_id);
}


static hi_void client_link_release()
{
    closesocket(g_client_link.sfd);
    g_client_link.sfd = -1;
    g_client_link.stats = LINK_STATE_IDLE;
    g_client_link.mode = LINK_MODE_INIT;
    g_client_link.protocol = IP_NULL;
}

//FIXME:this code will be change in release version
hi_u32 tuya_ipc_device_id_get(hi_char *str)
{
	random_string(16, str);
}


#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
