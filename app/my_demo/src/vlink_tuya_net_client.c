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
#include <hi_stdlib.h>
#include <hi_task.h>
#include <hi_time.h>
#include <hi_upg_api.h>
#include <hi_ver.h>
#include <hi_wifi_api.h>
#include "vlink_tuya_net_client.h"
#include <hi_cipher.h>
#include "vlink_hichannel_util.h"
#include "vlink_tuya_lowpower_protocol.h"


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
#include "vlink_tuya_net_client.h"

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
hi_u32 g_author_status = 0;


static hi_void link_monitor_socket(fd_set *read_set, hi_s32 *sfd_max);
static hi_void client_state_machine_check_close(hi_void);
static hi_u32 client_state_machine_check_idle(hi_void);
static hi_u32 tuya_client_show_msg();
static void client_state_machine_set_wait(hi_s32 sfd);
static hi_void client_link_release();
static hi_u32 create_tuya_client_task(hi_void);
static hi_void server_tcp_accept(hi_void);
static hi_void server_state_machine_check_close(hi_void);
static hi_u32 tuya_server_info_process();


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
    if (create_tuya_client_task() != HI_ERR_SUCCESS) {
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

    if (create_tuya_client_task() != HI_ERR_SUCCESS) {
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
			if ((g_client_link.stats == LINK_STATE_WAIT) && (FD_ISSET(g_client_link.sfd, &read_set))) {
				if(tuya_server_info_process()!=HI_ERR_SUCCESS) {
					hi_mux_post(g_ip_mux_id);
					MLOGE("sync with server has fail, retry!\r\n");
					continue;
				}
			}
			hi_mux_post(g_ip_mux_id);
		}
		else if (ret < 0) {
			MLOGE("lwip_select monitor fail!!\r\n");
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


static hi_u32 create_tuya_client_task(hi_void)
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
	printf("[%s %d]create_tuya_client_task is ok\r\n",__FUNCTION__,__LINE__);
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



static hi_u32 tuya_server_info_process()
{
	hi_s32 ret;
	struct sockaddr_in cln_addr = {0};
	socklen_t cln_addr_len = (socklen_t)sizeof(cln_addr);
	hi_u32 print_len = 0;
	hi_u32 ip_buffer_size;
	hi_char *ip_buffer = (hi_char*)malloc(IP_RESV_BUF_LEN);
	if (ip_buffer == HI_NULL) {
		printf("{ip_ip_resv_output:ip buffer malloc fail}\r\n");
		return HI_ERR_FAILURE;
	}
	memset_s(ip_buffer, IP_RESV_BUF_LEN , 0, IP_RESV_BUF_LEN);

	/*
		send packet to tuya server
		0: author request
		1: heartbeat request
		2: wake up
	*/
	switch(g_author_status)
	{
		case 0:
			ip_buffer_size = tuya_send_authention_request(ip_buffer);
		break;
		case 1:
			ip_buffer_size = tuya_send_heart_beat_packet(ip_buffer);
		break;
		case 2:
			MLOGD("wake up the host, stop the heartbeat packets!\n");
			free(ip_buffer);
			return HI_ERR_SUCCESS;
		break;
	}
	ret = sendto(g_client_link.sfd, ip_buffer, ip_buffer_size, 0, (struct sockaddr *)&cln_addr, (socklen_t)sizeof(cln_addr));
	if(ret < 0) {
		free(ip_buffer);
		MLOGD("send message to server faild!\n");
		return HI_ERR_FAILURE;
	}

	ret = recvfrom(g_client_link.sfd, ip_buffer, IP_RESV_BUF_LEN, 0, (struct sockaddr *)&cln_addr, (socklen_t *)&cln_addr_len);
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

	/*recevie buffer process*/
	memset_s(ip_buffer, IP_RESV_BUF_LEN , 0, IP_RESV_BUF_LEN);
	switch(ip_buffer[1])
	{
		case LP_TYPE_AUTH_RESPONSE:
			if(tuya_recevie_authention_response(ip_buffer) == HI_ERR_SUCCESS) {
				g_author_status = 1;
			}
		break;
		case LP_TYPE_HEARTBEAT:
			if(tuya_receive_heart_beat_packet(ip_buffer) != HI_ERR_SUCCESS)
				g_author_status = 0;
			else
				g_author_status = 0;
		break;
		case LP_TYPE_WAKEUP:
			if(tuya_recevie_wake_up_packet(ip_buffer) != HI_ERR_SUCCESS)
				g_author_status = 2;
			else
				g_author_status = 0;
		break;
		default:
			g_author_status = 0;
			MLOGD("unknow packet from server!\n");
		break;
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


#ifdef __cplusplus
#if __cplusplus
	}
#endif
#endif
