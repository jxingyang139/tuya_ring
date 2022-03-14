#include <hi_task.h>
#include "hi_types_base.h"
#include "securec.h"
#include "hi_wifi_api.h"
#include "wifi_sta.h"
#include "lwip/ip_addr.h"
#include "lwip/netifapi.h"
#include "lwip/dns.h"
#include <hi_nv.h>
#include <hi_time.h>
#include <hi_io.h>
#include "vlink_tuya_net_client.h"

#include "vlink_hichannel_util.h"
#include "hi_repeater_api.h"
#include "cJSON.h"
#include "hi_gpio.h"
#include "hi_event.h"
#include <hi_watchdog.h>

#define VLINK_TASK_STAK_SIZE (1024*20)
#define VLINK_TASK_PRIORITY  25

#define VLINK_TASK_STA_CONNECT_STAK_SIZE (1024*5)

#define USR_WPA_SSID_ID 0x83
#define USR_WPA_PWD_ID  0x84

#define APP_INIT_VAP_NUM    1
#define APP_INIT_USR_NUM    1

#define MAIN_STA_DHCP_EVENT 0x1
#define MAIN_STA_DHCP_TIMEOUT        (2 * 10 * 1000)

#define MAIN_INVALID_EVENT_ID 0xFFFFFFFF


hi_u32 g_main_sta_dhcp_event_id = MAIN_INVALID_EVENT_ID;
hi_u32 g_main_softap_event_id = MAIN_INVALID_EVENT_ID;

#define MAIN_DEEPSLEEP_EVENT 0x1
#define MAIN_DEEPSLEEP_TIMEOUT        (5 * 1000)

hi_u32 g_main_deepsleep_event_id = 0;




//static hi_u32 g_main_hisyslink_status = 0; //0:error, 1:ok

static struct netif *g_lwip_netif = NULL;

static VLINK_WIFI_WORK_STATUS g_work_status = VLINK_WIFI_WORK_NETCFG;

static hi_s32 vlink_hi_channel_get_ip(hi_void);
static hi_s32 vlink_hi_channel_set_device_filter(hi_char *device);

hi_u32 g_vlink_main_task_id = 0;
hi_u32 g_vlink_sta_connect_task_id = 0;

/* clear netif's ip, gateway and netmask */
static void dz_test_softap_reset_addr(struct netif *pst_lwip_netif)
{
	ip4_addr_t st_gw;
	ip4_addr_t st_ipaddr;
	ip4_addr_t st_netmask;

	if (pst_lwip_netif == NULL) {
		printf("hisi_reset_addr::Null param of netdev\r\n");
		return;
	}

	IP4_ADDR(&st_ipaddr, 0, 0, 0, 0);
	IP4_ADDR(&st_gw, 0, 0, 0, 0);
	IP4_ADDR(&st_netmask, 0, 0, 0, 0);

	netifapi_netif_set_addr(pst_lwip_netif, &st_ipaddr, &st_netmask, &st_gw);
}

static hi_u32 vlink_start_sta_disconnect(hi_void)
{

	hi_u32 ret = hi_wifi_sta_disconnect();
	return ret;
}

static hi_void vlink_test_stop_softap_station(hi_void)
{
	hi_u32 ret;

	if (g_lwip_netif != HI_NULL) 
	{
		netifapi_dhcps_stop(g_lwip_netif);
		dz_test_softap_reset_addr(g_lwip_netif);
	}

	ret = hi_wifi_softap_stop();
	if (ret != HISI_OK) {
		MLOGE("failed to stop softap\n");
	} else {
		hi_vlwip_netif_deinit(WIFI_AP_NETIF_NAME);
		MLOGD("------hi_vlwip_netif_deinit--netif[%s]--\n", WIFI_AP_NETIF_NAME);
	}

	//---------------------------------------

/*
	if (hi_vlwip_netif_init(WIFI_AP_NETIF_NAME) != HI_ERR_SUCCESS) {
		MLOGE("hi_vlwip_netif_init:: netif [%s] failed\n", WIFI_AP_NETIF_NAME);
		return HI_ERR_FAILURE;
	}
*/
	ret = hi_wifi_sta_disconnect();
	if (ret != HISI_OK) {
		MLOGE("failed to stop sta disconnect\n");
	}

	/*stop sta need call hi_vlwip_netif_deinit*/
	ret = hi_wifi_sta_stop();
	if (ret != HISI_OK) {
		MLOGE("failed to stop sta\n");
	} else {
		hi_vlwip_netif_deinit(WIFI_NETIF_NAME);
		MLOGD("------hi_vlwip_netif_deinit--netif[%s]--\n", WIFI_NETIF_NAME);
	}
	
	/*
	ret = hi_wifi_deinit();
	if (ret != HISI_OK) {
		printf("failed to deinit wifi\n");
	}
	*/
	g_lwip_netif = NULL;

}

static hi_void STA_WIFI_NetifExtCb(struct netif *netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t *args)
{
    if ((reason & LWIP_NSC_IPV4_SETTINGS_CHANGED) || (reason & LWIP_NSC_IPV6_ADDR_STATE_CHANGED)) {
        hi_event_send(g_main_sta_dhcp_event_id, MAIN_STA_DHCP_EVENT);
    }
}

static hi_void vlink_wifi_wpa_start_dhcp(hi_void)
{
	netif_ext_callback_t netifCB;
	hi_s32 ret;
        hi_u32 eventRet;
        hi_u32 eventBit;

	if (netifapi_dhcp_start(g_lwip_netif) != ERR_OK)
	{
		MLOGE("------netifapi_dhcp_start fail\n");
		//PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("dhcpfail");
		error_and_fail_reset();
		return;
	} else {
		MLOGD("------netifapi_dhcp_start ok\n");
	}

	hi_event_create(&g_main_sta_dhcp_event_id);
/*
	ret = netifapi_netif_add_ext_callback(&netifCB, STA_WIFI_NetifExtCb);
        if (ret != ERR_OK) {
                MLOGE("netifapi_netif_add_ext_callback err !\n");
		//PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("dhcpfail");
		error_and_fail_reset();
        	return;
        }
*/
        eventRet = hi_event_wait(g_main_sta_dhcp_event_id, MAIN_STA_DHCP_EVENT, &eventBit, MAIN_STA_DHCP_TIMEOUT, HI_EVENT_WAITMODE_OR | HI_EVENT_WAITMODE_CLR);
        //netifapi_netif_remove_ext_callback(&netifCB);
        ret = hi_event_delete(g_main_sta_dhcp_event_id);
		g_main_sta_dhcp_event_id = MAIN_INVALID_EVENT_ID;
    	if (eventRet == HI_ERR_EVENT_WAIT_TIME_OUT) {
			MLOGE("get DHCP timeout\r\n");
			netifapi_dhcp_stop(g_lwip_netif);
			//PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("dhcpfail");
			error_and_fail_reset();
			return;
    	}
		else {
			MLOGD("========DHCP ok=======\r\n");

			/*[jiaxing]tmp comment*/
			/*
			vlink_hi_channel_get_ip();
			//PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("dhcpok");
			vlink_HI_PARAM_System status = {0};
			vlink_HI_PDT_PARAM_GetSystemStatus(&status);

			vlink_test_function_start_event();
			if (status.workstatus > VLINK_WIFI_WORK_WAKEUP) //keeplive,deepsleep
			{

				//hi_s32 ret = hi_syslink_set_default_forward(HI_SYSLINK_FORWARD_SELECTION_WIFI);
				//HI_APPCOMM_LOG_AND_RETURN_IF_FAIL(ret, ret, "hi_syslink_set_default_filter");
				//MLOGD("set all net packets forward to wifi default.\n");
				//PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("keeplive");
				//aliiot_mqtt_start_keeplive();
				vlink_hi_channel_set_device_filter("camera");
				if (status.workstatus > VLINK_WIFI_WORK_KEEPLIVE) //keeplive,deepsleep
				{
					vlink_hichannel_sdio_deepsleep_proc();
					//PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("deepsleep");
					vlink_wifi_deep_sleep();
				}
			}
			//hi_task_delete(g_vlink_sta_connect_task_id);
	    		//g_vlink_sta_connect_task_id = 0;
			*/
	}
	return;
}


static hi_void vlink_wifi_wpa_event_cb(const hi_wifi_event *hisi_event)
{
    if (hisi_event == NULL)
        return;

    switch (hisi_event->event) {
        case HI_WIFI_EVT_SCAN_DONE:
            printf("WiFi: Scan results available\n");
	    //PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("scandone");
            break;
        case HI_WIFI_EVT_CONNECTED:
            printf("WiFi: Connected\n");
	    //PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("connectok");	    
	    vlink_wifi_wpa_start_dhcp();
            break;
        case HI_WIFI_EVT_DISCONNECTED:
            printf("WiFi: Disconnected\n");
            netifapi_dhcp_stop(g_lwip_netif);
            dz_test_softap_reset_addr(g_lwip_netif);
	    //PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("disconnectok");
	    //dz_test_wpa_connect_ap_again();
            break;
        case HI_WIFI_EVT_STA_FCON_NO_NETWORK:
            printf("WiFi: find no network\n");
	    //PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("scanfail");
            break;
        default:
            break;
    }
}

static hi_s32 vlink_start_sta_connect_dhcp(hi_void)
{
	hi_s32 ret;
	errno_t rc;
	char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
	int len = sizeof(ifname);

	hi_wifi_assoc_request assoc_req = {0};
	vlink_HI_PDT_WIFI_Param wifiCfg = { 0 };

	ret = vlink_HI_PDT_PARAM_GetWifiParam(&wifiCfg);
	HI_APPCOMM_RETURN_IF_FAIL(ret, ret);

	MLOGD("vlink_start_sta_connect_dhcp-ssid[%s]--key[%s]-\n", wifiCfg.ssid, wifiCfg.key);

	ret = memcpy_s(&assoc_req.ssid, sizeof(assoc_req.ssid), wifiCfg.ssid, strlen((hi_char *)wifiCfg.ssid));
	HI_APPCOMM_LOG_IF_EXPR_FALSE(ret == HI_ERR_SUCCESS, "memcpy_s");

	if (wifiCfg.auth != HI_WIFI_SECURITY_OPEN) {
		ret = memcpy_s(&assoc_req.key, sizeof(assoc_req.key), wifiCfg.key, strlen((hi_char *)wifiCfg.key));
		HI_APPCOMM_LOG_IF_EXPR_FALSE(ret == HI_ERR_SUCCESS, "memcpy_s");
		MLOGD("ssid:%s pwd:%s \r\n", assoc_req.ssid, assoc_req.key);
		assoc_req.auth = HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX;
		assoc_req.pairwise = HI_WIFI_PAIRWISE_TKIP_AES_MIX;
	} else { //open
		assoc_req.auth = HI_WIFI_SECURITY_OPEN;
	}
	MLOGE("jiaxing[%s]\n",ifname);

	//[temp comment, jiaxing]
	vlink_test_stop_softap_station();
/*
	ret = hi_wifi_init(APP_INIT_VAP_NUM, APP_INIT_USR_NUM);
	if (ret != HISI_OK) {
		MLOGE("vlink_wpa_connect_ap=hi_wifi_init==%x\n", ret);
		return HI_ERR_FAILURE;
	}
*/
	ret = hi_wifi_sta_start(ifname, &len);
	if (ret != HISI_OK) {
		MLOGE("vlink_wpa_connect_ap=hi_wifi_sta_start==%x\n", ret);
		return HI_ERR_FAILURE;
	}
	MLOGE("jiaxing[%s]\n",ifname);

	if (hi_vlwip_netif_init(ifname) != HI_ERR_SUCCESS) {
		MLOGE("hi_vlwip_netif_init:: netif[%s] failed\n", ifname);
		return HI_ERR_FAILURE;
	}
	MLOGE("jiaxing[%s]\n",ifname);

	/* acquire netif for IP operation */
	g_lwip_netif = netifapi_netif_find(ifname);
	if (g_lwip_netif == NULL) {
		MLOGE("%s: get netif failed\n", __FUNCTION__);
		return HI_ERR_FAILURE;
	}
	MLOGE("jiaxing[%s]\n",ifname);

	ret = hi_wifi_register_event_callback(vlink_wifi_wpa_event_cb);
	if (ret != HISI_OK) {
		MLOGE("===============hi_wifi_register_event_callback=error===============\r\n");
		return HI_ERR_FAILURE;
	}

	ret = hi_wifi_sta_set_reconnect_policy(1, 10, 65535, 10);
	if (ret != HISI_OK) {
		MLOGE("hi_wifi_sta_set_reconnect_policy fail\n");
		return HI_ERR_FAILURE;
	}

	ret = hi_wifi_sta_connect(&assoc_req);

    g_lwip_netif = netif_find("wlan0");
	if (g_lwip_netif == HI_NULL) {
		MLOGE("netif_find fail\n");
	        return HI_ERR_FAILURE;    
	}

	if (HISI_OK == ret)
	{
		MLOGD("vlink_wpa_connect_ap success\n");
	} else {
		MLOGE("vlink_wpa_connect_ap fail\n");
		return HI_ERR_FAILURE;
	}
	return HISI_OK;
}

static hi_void *vlink_sta_connect_task_proc(hi_void *param)
{
	hi_unref_param(param);

	vlink_start_sta_connect_dhcp();

}

static hi_u32 vlink_start_sta_connect_task()
{
	hi_u32 ret;

	/* Create a task to handle uart communication */
	hi_task_attr sta_connect_attr = {0};
	sta_connect_attr.stack_size = VLINK_TASK_STA_CONNECT_STAK_SIZE;
	sta_connect_attr.task_prio = VLINK_TASK_PRIORITY;
	sta_connect_attr.task_name = (hi_char*)"sta_connect";
	ret = hi_task_create(&g_vlink_sta_connect_task_id, &sta_connect_attr, vlink_sta_connect_task_proc, HI_NULL);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("Falied to create vlink_start_sta_connect_task task!\n");
	}
}

static hi_u32 vlink_get_ssid_pwd_from_camera(hi_char *ssid_pwd, hi_u32 length)
{
	hi_char camera_ssid[HI_WIFI_MAX_SSID_LEN + 1] = {0};
	hi_char camera_pwd[HI_WIFI_MAX_KEY_LEN + 1] = {0};	
	vlink_HI_PDT_WIFI_Param wifiParam = { 0 };
	vlink_HI_PARAM_System status = {0};

	cJSON* item;

	cJSON* root = cJSON_Parse(&ssid_pwd[3]); 

	vlink_test_function_stop_event();

	if(NULL == root)                                                                                         
	{
		MLOGE("-:parseJson---Parse fail\n");
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "ssid");
	if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)) && ((HI_WIFI_MAX_SSID_LEN + 1) > strlen(item->valuestring)))
	{
		memcpy(camera_ssid, item->valuestring, strlen(item->valuestring));
	} else {
		MLOGE("-:parseJson-camera_ssid--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "key");
	if((NULL != item) && (NULL != item->valuestring) && ((HI_WIFI_MAX_KEY_LEN + 1) > strlen(item->valuestring)))
	{
		memcpy(camera_pwd, item->valuestring, strlen(item->valuestring));
	} else {
		MLOGE("-:parseJson-camera_pwd--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	cJSON_Delete(root);
	MLOGD("-:parseJson-camera_ssid[%s]--camera_pwd[%s]-\n", camera_ssid, camera_pwd);

	memcpy(wifiParam.ssid, camera_ssid, strlen(camera_ssid));
	
	if (strlen(camera_pwd) > 0)
	{
		//memcpy(wifiParam.key, camera_pwd, strlen(camera_pwd));
		memcpy_s(wifiParam.key, sizeof(wifiParam.key), camera_pwd, strlen((hi_char *)camera_pwd));
		MLOGD("-:===========--wifiParam.key[%s]-len[%d]---pwd-len[%d]----\n", wifiParam.key, sizeof(wifiParam.key), strlen((hi_char *)camera_pwd));
		wifiParam.auth = HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX;
	} else {
		wifiParam.auth = HI_WIFI_SECURITY_OPEN;
	}

	wifiParam.pairwise = HI_WIFI_PAIRWISE_TKIP_AES_MIX;
	wifiParam.openDHCP = 1;
	wifiParam.protocolMode = HI_WIFI_PHY_MODE_11BGN;

	MLOGD("-:parseJson-wifiParam.ssid[%s]--wifiParam.key[%s]-\n", wifiParam.ssid, wifiParam.key);

	vlink_HI_PDT_PARAM_SetWifiParam(&wifiParam);

	g_work_status = VLINK_WIFI_WORK_WAKEUP;
	status.workstatus = VLINK_WIFI_WORK_WAKEUP;

	vlink_HI_PDT_PARAM_SetSystemStatus(&status);

	//vlink_start_sta_connect_dhcp();

	vlink_start_sta_connect_task();

	return HI_ERR_SUCCESS;
}

static hi_s32 PDT_SYSTEM_SYSLINK_ProcNetInfoMsg(hi_void)
{
	MLOGD("PDT_SYSTEM_SYSLINK_ProcNetInfoMsg========1=========\n");
	//PDT_SYSTEM_SYSLINK_FillNetInfoMsgToCamera();
	return HI_ERR_SUCCESS;
}

static hi_s32 PDT_SYSTEM_SYSLINK_Standby(hi_u32 argc, hi_char **argv)
{
	MLOGD("received standby msg from soc ...enter standby\n");
	vlink_HI_PARAM_System status = {0};
	vlink_HI_PDT_PARAM_GetSystemStatus(&status);
	
	//if (status.workstatus != VLINK_WIFI_WORK_DEEPSLEEP)
	{
		status.workstatus = VLINK_WIFI_WORK_KEEPLIVE;
		g_work_status = VLINK_WIFI_WORK_KEEPLIVE;
		vlink_HI_PDT_PARAM_SetSystemStatus(&status);	

		//hi_s32 ret = hi_syslink_set_default_forward(HI_SYSLINK_FORWARD_SELECTION_WIFI);
		//HI_APPCOMM_LOG_AND_RETURN_IF_FAIL(ret, ret, "hi_syslink_set_default_filter");
		MLOGD("set all net packets forward to wifi default.\n");
		//PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("keeplive");
		//aliiot_mqtt_start_keeplive();
	}
	return HI_ERR_SUCCESS;
}

static hi_s32 PDT_SYSTEM_SYSLINK_ExitStandby(hi_u32 argc, hi_char **argv)
{
	MLOGD("received standby msg from soc ...exit standby\n");
	vlink_HI_PARAM_System status = {0};
	vlink_HI_PDT_PARAM_GetSystemStatus(&status);
	
	//if (status.workstatus != VLINK_WIFI_WORK_WAKEUP)
	{
		status.workstatus = VLINK_WIFI_WORK_WAKEUP;
		g_work_status = VLINK_WIFI_WORK_WAKEUP;
		vlink_HI_PDT_PARAM_SetSystemStatus(&status);
		
		//vlink_gpio_power_off();

		//aliiot_mqtt_stop_keeplive();

		//vlink_PDT_SYSTEM_AddPacketFilterToSyslink();
	}
	return HI_ERR_SUCCESS;
}

static hi_s32 PDT_SYSTEM_SYSLINK_DeepSleep(hi_u32 argc, hi_char **argv)
{
	MLOGD("received standby msg from soc ...enter deepsleep\n");
	vlink_HI_PARAM_System status = {0};
	vlink_HI_PDT_PARAM_GetSystemStatus(&status);

	{
		hi_s32 ret;
		hi_u32 eventRet;
		hi_u32 eventBit;

		hi_event_create(&g_main_deepsleep_event_id);

		status.workstatus = VLINK_WIFI_WORK_DEEPSLEEP;
		g_work_status = VLINK_WIFI_WORK_DEEPSLEEP;
		vlink_HI_PDT_PARAM_SetSystemStatus(&status);
		//PDT_SYSTEM_SYSLINK_FillNetConnectInfoMsgToCamera("deepsleep");
		//g_main_hisyslink_status = 0;

		vlink_wifi_deep_sleep();	
	}
	return HI_ERR_SUCCESS;
}

static hi_s32 vlink_hi_channel_get_mac(hi_void)
{
#define VMACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define vmac2str(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

	MLOGD("--start--\n");
	hi_char allmac[20] = {0};

    hi_uchar mac_addr[6] = {0}; /* 6 mac len */

	if (hi_wifi_get_macaddr((hi_char*)mac_addr, 6) != HI_ERR_SUCCESS) { /* 6 mac len */
		return HI_ERR_FAILURE;
	}
	sprintf(allmac, VMACSTR, vmac2str(mac_addr));

	cJSON * pJsonRoot = NULL;
	cJSON *pJson = NULL;	

	pJsonRoot = cJSON_CreateObject();

	cJSON_AddStringToObject(pJsonRoot, "cmd", VLINK_WIFI_CMD_SENDMSG_GETMAC);
	cJSON_AddStringToObject(pJsonRoot, "mac", allmac);

	pJson = cJSON_Print(pJsonRoot);

	MLOGD("--pJson[%s]-[%d]--\n", pJson, strlen((char*)pJson));

    hi_channel_send_to_host((char*)pJson, strlen((char*)pJson));

	free(pJson);
	cJSON_Delete(pJsonRoot);

	return HI_ERR_SUCCESS;
}

static hi_s32 vlink_hi_channel_get_ip(hi_void)
{
	MLOGD("vlink_hi_channel_get_ip-------------------\n");
	ip4_addr_t ipaddr = { 0 };
	ip4_addr_t netmask = { 0 };
	ip4_addr_t gw = { 0 };
	ip_addr_t dns;

	int i;

	cJSON * pJsonRoot = NULL;
	cJSON *pJson = NULL;

	pJsonRoot = cJSON_CreateObject();

    //struct netif *netif = netifapi_netif_find(WIFI_NETIF_NAME);
    if (g_lwip_netif == HI_NULL) {
		MLOGD("--------g_lwip_netif is null--------------\n");
		return HI_ERR_FAILURE;
    }

	err_t ret = netifapi_netif_get_addr(g_lwip_netif, &ipaddr, &netmask, &gw);
	if (ret != ERR_OK) {
		return HI_ERR_FAILURE;
	}

	cJSON_AddStringToObject(pJsonRoot, "cmd", VLINK_WIFI_CMD_SENDMSG_GETIP);

	cJSON_AddStringToObject(pJsonRoot, "ip", ip4addr_ntoa(&ipaddr));		
	cJSON_AddStringToObject(pJsonRoot, "gw", ip4addr_ntoa(&gw));
	cJSON_AddStringToObject(pJsonRoot, "nm", ip4addr_ntoa(&netmask));

	for (i = 0; i < DNS_MAX_SERVERS; i++) {
		err_t err = lwip_dns_getserver((u8_t)i, &dns);
		if (err == ERR_OK) {
			if (i == 0) {
				cJSON_AddStringToObject(pJsonRoot, "dns1", ip4addr_ntoa(&dns));
			} else {
				cJSON_AddStringToObject(pJsonRoot, "dns2", ip4addr_ntoa(&dns));
			}
		} else {
			if (i == 0) {
				cJSON_AddStringToObject(pJsonRoot, "dns1", "0.0.0.0");
			} else {
				cJSON_AddStringToObject(pJsonRoot, "dns2", "0.0.0.0");
			}
		}
	}

	pJson = cJSON_Print(pJsonRoot);
	MLOGD("vlink_hi_channel_get_ip========[%s]====len[%d]=====\n", pJson, strlen(pJson));
	ret = hi_channel_send_to_host((char*)pJson, strlen(pJson));

	/*
    hi_io_set_driver_strength(HI_IO_NAME_GPIO_8, HI_IO_DRIVER_STRENGTH_0);
	hi_gpio_set_dir(HI_IO_NAME_GPIO_8, HI_GPIO_DIR_OUT);
	hi_gpio_set_output_val(HI_IO_NAME_GPIO_8, HI_GPIO_VALUE1);
	hi_sleep(10);
	hi_gpio_set_output_val(HI_IO_NAME_GPIO_8, HI_GPIO_VALUE0);
	*/

	if(ret == HI_ERR_SUCCESS)
		MLOGD("[jiaxing]send msg to host success!\n");
	else
		MLOGD("[jiaxing]send msg to host fail!\n");

	free(pJson);
	cJSON_Delete(pJsonRoot);

	return HI_ERR_SUCCESS;
}

static hi_s32 vlink_localserver_start_keeplive(hi_char *serverip, hi_char *port, hi_u32 expire)
{
	MLOGD("vlink_localserver_start_keeplive========serverip[%s]==port[%s]==expire[%d]=====\n", serverip, port, expire);
	HI_KEEPALIVE_StartKeepAlive(serverip, port, expire);
}

static hi_s32 vlink_hi_channel_set_device_filter(hi_char *device)
{
	MLOGD("vlink_hi_channel_set_device_filter========device[%s]=======\n", device);
	
	if (strncmp(device, "wifi", 4) == 0)
	{
		hi_channel_set_default_wifi_filter();
	} 
	else if (strncmp(device, "camera", 6) == 0) 
	{
		hi_channel_set_default_filter();
	} else {
		MLOGD("vlink_hi_channel_set_device_filter========device[%s]==error=====\n", device);
	}
}

static hi_s32 vlink_wifi_startap_event_proc(hi_void)
{
	hi_s32 ret;
	hi_u32 eventRet;
	hi_u32 eventBit;

	hi_event_create(&g_main_softap_event_id);

	eventRet = hi_event_wait(g_main_softap_event_id, MAIN_STA_DHCP_EVENT, &eventBit, MAIN_STA_DHCP_TIMEOUT, HI_EVENT_WAITMODE_OR | HI_EVENT_WAITMODE_CLR);

	ret = hi_event_delete(g_main_softap_event_id);
	g_main_softap_event_id = MAIN_INVALID_EVENT_ID;
	if (eventRet == HI_ERR_EVENT_WAIT_TIME_OUT) {
		MLOGE(" timeout\r\n");
		return;
	} else {
		MLOGD("========softap ip ok=======\r\n");
		vlink_hi_channel_get_ip();
	}
	return;	
}

static hi_void *vlink_start_softap_event_task_proc(hi_void *param)
{
	hi_unref_param(param);

	vlink_wifi_startap_event_proc();

}

static hi_u32 vlink_start_softap_event_task()
{
	hi_u32 ret;
	hi_u32 ap_event_task_id = 0;

	/* Create a task to handle uart communication */
	hi_task_attr event_attr = {0};
	event_attr.stack_size = VLINK_TASK_STA_CONNECT_STAK_SIZE;
	event_attr.task_prio = VLINK_TASK_PRIORITY;
	event_attr.task_name = (hi_char*)"ap_event";
	ret = hi_task_create(&ap_event_task_id, &event_attr, vlink_start_softap_event_task_proc, HI_NULL);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("Falied to create task!\n");
	}
}


#define VLINK_AP_SSID "infotm_test"
#define VLINK_AP_PWD  "12345678"

static hi_s32 vlink_wifi_startap(hi_void)
{
	hi_u32 ret;
	errno_t rc;
	char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
	int len = sizeof(ifname);
	hi_char *ifname_point = ifname;
	hi_wifi_softap_config hapd_conf = {0};

	MLOGD("=====start========\n");

	vlink_start_sta_disconnect();
	vlink_test_stop_softap_station();

	/* copy SSID to hapd_conf */
	rc = memcpy_s(hapd_conf.ssid, HI_WIFI_MAX_SSID_LEN + 1, VLINK_AP_SSID, strlen(VLINK_AP_SSID) + 1); 
	if (rc != EOK) {
		MLOGE("memcpy_s==2==ssid error\n");
		return HI_ERR_FAILURE;
	}

	if (strlen(VLINK_AP_PWD))
	{
		rc = memcpy_s(hapd_conf.key, HI_WIFI_MAX_KEY_LEN + 1, VLINK_AP_PWD, strlen(VLINK_AP_PWD) + 1); 
		if (rc != EOK) {
			MLOGE("memcpy_s==2==pwd error\n");
			return HI_ERR_FAILURE;
		}
		hapd_conf.authmode = HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX;
		//assoc_req.pairwise = HI_WIFI_PAIRWISE_TKIP_AES_MIX;

	} else { /*no pass word, mode need change*/
		hapd_conf.authmode = HI_WIFI_SECURITY_OPEN;
	}

	hapd_conf.ssid_hidden = 0;
	hapd_conf.channel_num = 1;	

	if (hi_wifi_softap_set_beacon_period(200) != HISI_OK) {
		MLOGE("hi_wifi_soft__set_beacon_period:: ap0 failed\n");
		return HISI_FAIL;
	}

	if (hi_wifi_softap_start(&hapd_conf, ifname_point, &len) != HISI_OK) {
		MLOGE("======hi_wifi_softap_start==FAIL======\r\n");
		return HI_ERR_FAILURE;
	}

	if (hi_vlwip_netif_init(WIFI_AP_NETIF_NAME) != HI_ERR_SUCCESS) {
		MLOGE("hi_vlwip_netif_init:: netif ap0 failed\n");
		return HI_ERR_FAILURE;
	}

	/* acquire netif for IP operation */
	g_lwip_netif = netifapi_netif_find(ifname);
	if (g_lwip_netif == NULL) {
		MLOGE("%s: get netif failed\n", __FUNCTION__);
		return HI_ERR_FAILURE;
	}

	ip4_addr_t st_gw;
	ip4_addr_t st_ipaddr;
	ip4_addr_t st_netmask;

	IP4_ADDR(&st_gw, 192, 168, 43, 1);
	IP4_ADDR(&st_ipaddr, 192, 168, 43, 1);
	IP4_ADDR(&st_netmask, 255, 255, 255, 0);
	netifapi_netif_set_addr(g_lwip_netif, &st_ipaddr, &st_netmask, &st_gw);

	if(netifapi_dhcps_start(g_lwip_netif, NULL, 0)!=HISI_OK)
	{
		(hi_void)hi_wifi_softap_stop();
		MLOGE("start ap0 dhcps fail!\r\n");
		return HISI_FAIL;
	}
	MLOGD("vlink_wifi_startap======OK========\r\n");

	return HI_ERR_SUCCESS;	
}

static hi_void *vlink_start_softap_task_proc(hi_void *param)
{
	hi_unref_param(param);

	vlink_start_softap_event_task();

	vlink_wifi_startap();

}

static hi_u32 vlink_start_softap_task()
{
	hi_u32 ret;

	/* Create a task to handle uart communication */
	hi_task_attr softap_attr = {0};
	softap_attr.stack_size = VLINK_TASK_STA_CONNECT_STAK_SIZE;
	softap_attr.task_prio = VLINK_TASK_PRIORITY;
	softap_attr.task_name = (hi_char*)"start_softap";
	ret = hi_task_create(&g_vlink_sta_connect_task_id, &softap_attr, vlink_start_softap_task_proc, HI_NULL);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("Falied to create vlink_start_softap_task task!\n");
	}
}

hi_s32 vlink_fota_send_ok_msg_to_camera(hi_char * isOk)
{
	MLOGD("--start--\n");

	cJSON * pJsonRoot = NULL;
	cJSON *pJson = NULL;	

	pJsonRoot = cJSON_CreateObject();

	cJSON_AddStringToObject(pJsonRoot, "cmd", VLINK_WIFI_CMD_SENDMSG_OTAWRITERET);
	cJSON_AddStringToObject(pJsonRoot, "ret", isOk);

	pJson = cJSON_Print(pJsonRoot);

	MLOGD("--pJson[%s]-[%d]--\n", pJson, strlen((char*)pJson));

	hi_channel_send_to_host((char*)pJson, strlen((char*)pJson));

	free(pJson);
	cJSON_Delete(pJsonRoot);

	return HI_ERR_SUCCESS;
}


static hi_s32 vlink_hi_channel_get_tuya(hi_void)
{
	hi_wifi_set_default_filter(WIFI_FILTER_LWIP);
	start_tuya_tcp_client("192.168.1.119", 8080);
	//start_tuya_tcp_server(20000);

	return HI_ERR_SUCCESS;
}


static hi_s32 vlink_hi_channel_get_utc(char *buf)
{
	char utc_time[64];
	cJSON* item;
	cJSON* root = cJSON_Parse(&buf[3]); 
	hi_u64 utime;

	if(NULL == root) {
		MLOGE("-:parseJson---Parse fail\n");
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "time");
	if((NULL != item) && (NULL != item->valuestring)
		&& (0 != strlen(item->valuestring)) && ((HI_WIFI_MAX_SSID_LEN + 1) > strlen(item->valuestring))) {
		memcpy(utc_time, item->valuestring, strlen(item->valuestring));
	} else {
		MLOGE(":parseJson-time--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	cJSON_Delete(root);
	MLOGD(":parseJson-time = [%s]\n", utc_time);
	utime = atol(utc_time);
	hi_set_real_time(utime);
	MLOGD("%lld\n",utime);
	return HI_ERR_SUCCESS;
}


unsigned int hi_channel_rx_callback(char *buf, int length)
{
	cJSON* item;
	MLOGD("====start======\n");
	if ((buf == HI_NULL) || (length == 0)) {
		return HI_ERR_FAILURE;
	}

	if (buf[0] == 61) { 
		MLOGE("buf[0] == 61\n");
		hi_channel_dev_reset(SDIO_TYPE);
		vlink_hichannel_sdio_reinit();
		return HI_ERR_SUCCESS;
	} else if (buf[0] == 62) {  
		MLOGE("buf[0] == 62\n");
		printf("sdio_soft_rst\r\n");
		hi_channel_dev_reset(SDIO_TYPE);
		vlink_hichannel_sdio_reinit();

		hi_gpio_set_dir(HI_GPIO_IDX_2, HI_GPIO_DIR_OUT);
		hi_gpio_set_output_val(HI_GPIO_IDX_2, HI_GPIO_VALUE0);
		hi_sleep(10);
		hi_gpio_set_output_val(HI_GPIO_IDX_2, HI_GPIO_VALUE1);
		return HI_ERR_SUCCESS;
	}
#if 1
	MLOGD("======buf[%02X][%02X][%02X]===len[%d]=====\n", buf[0], buf[1], buf[2], length);

	switch(buf[0])
	{
		case CMD_SENDMSG_NETCFG:
			vlink_get_ssid_pwd_from_camera(buf, length);
		break;	

		case CMD_SENDMSG_GETMAC:
			vlink_hi_channel_get_mac();
		break;	

		case CMD_SENDMSG_GETIP:
			vlink_hi_channel_get_ip();
		break;	

		case CMD_SENDMSG_SETFILTER:
		{
			cJSON* root = cJSON_Parse(&buf[3]); 
			if(NULL == root)                                                                                         
			{
				MLOGE(":parseJson---Parse fail\n");
				return HI_ERR_FAILURE;
			}
			item = cJSON_GetObjectItem(root, "device");
			if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)))
			{
				vlink_hi_channel_set_device_filter(item->valuestring);
			}
			cJSON_Delete(root);
		}
		break;	

		case CMD_SENDMSG_KEEPLIVE:
		{
			hi_char serverip[20] = {0};
			hi_char port[20] = {0};
			hi_u32 expire =0;

			cJSON* root = cJSON_Parse(&buf[3]); 
			if(NULL == root)                                                                                         
			{
				MLOGE(":parseJson---Parse fail\n");
				return HI_ERR_FAILURE;
			}

			item = cJSON_GetObjectItem(root, "ip");
			if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)))
			{
				memcpy(serverip, item->valuestring, strlen(item->valuestring));
			}
			item = cJSON_GetObjectItem(root, "port");
			if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)))
			{
				memcpy(port, item->valuestring, strlen(item->valuestring));
			}
			item = cJSON_GetObjectItem(root, "expire");
			if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)))
			{
				expire = atoi(item->valuestring);
			}
			vlink_localserver_start_keeplive(serverip, port, expire);
			cJSON_Delete(root);
		}
		break;	

		case CMD_SENDMSG_STANDBY:

		break;
		case CMD_SENDMSG_DEEPSLEEP:
			vlink_wifi_deep_sleep();
		break;
		case CMD_SENDMSG_STARTAP:
			vlink_start_softap_task();
		break;
		case CMD_SENDMSG_STARTOTA:
			vlink_start_startota_task();
		break;
		case CMD_SENDMSG_OTADATA:
			vlink_start_fota_proc_ota_data(buf, length);
		break;
		case CMD_SENDMSG_TUYA_SERVER_LINK:
			vlink_hi_channel_get_tuya();
		break;
		case CMD_SENDMSG_GET_UTC_TIME:
			vlink_hi_channel_get_utc(buf);
		break;

		default:
			break;

	}
	return HI_ERR_SUCCESS;
#else

	MLOGD("====len1:[%d]==len2:[%d]====\n", strlen(buf), length);

	cJSON* root = cJSON_Parse(buf); 
	if(NULL == root)                                                                                         
	{
		MLOGE(":parseJson---Parse fail\n");
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "cmd");
	if(NULL != item)
	{
		hi_u8 cmdval = atoi(item->valuestring);
		MLOGD(":parseJson---Parse----[%d]-----\n", cmdval);
		switch(cmdval)
		{
			case 1:
				vlink_get_ssid_pwd_from_camera(buf, length);
			break;
			case 2:
				vlink_hi_channel_get_mac();
			break;
			case 3:
				vlink_hi_channel_get_ip();
			break;
			case 4:
			{
				item = cJSON_GetObjectItem(root, "device");
				if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)))
				{
					vlink_hi_channel_set_device_filter(item->valuestring);
				}
			}
			break;
			case 5:
			{
				hi_char serverip[20] = {0};
				hi_char port[20] = {0};
				hi_u32 expire =0;
				item = cJSON_GetObjectItem(root, "ip");
				if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)))
				{
					memcpy(serverip, item->valuestring, strlen(item->valuestring));
				}
				item = cJSON_GetObjectItem(root, "port");
				if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)))
				{
					memcpy(port, item->valuestring, strlen(item->valuestring));
				}
				item = cJSON_GetObjectItem(root, "expire");
				if((NULL != item) && (NULL != item->valuestring) && (0 != strlen(item->valuestring)))
				{
					expire = atoi(item->valuestring);
				}
				vlink_localserver_start_keeplive(serverip, port, expire);
			}

			break;
			case 6:

			break;
			case 7:
				vlink_wifi_deep_sleep();
			break;
			case 8:
				vlink_start_softap_task();
			break;
			case 9:
				vlink_start_startota_task();
			break;
			case 10:
				//vlink_start_fota_proc_ota_data(buf);
			break;


			default: //

			break;
		}

	} else {
		MLOGE(":parseJson-cmd--Parse fail\n");
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}	

	cJSON_Delete(root);
	return HI_ERR_SUCCESS;
#endif
}

static hi_void app_demo_netif_ext_callback(struct netif *netif, netif_nsc_reason_t reason,
                                          const netif_ext_callback_args_t *args) {
    hi_unref_param(args);
    if (netif == HI_NULL) {
        return;
    }

    if ((reason & LWIP_NSC_IPV4_ADDRESS_CHANGED) ||
       (reason & LWIP_NSC_IPV4_NETMASK_CHANGED) ||
       (reason & LWIP_NSC_IPV4_GATEWAY_CHANGED) ||
       (reason & LWIP_NSC_IPV4_SETTINGS_CHANGED)) {

	printf("LWIP_NSC_IPV4_ADDRESS_CHANGED:0x%x\n", reason);
	if (g_main_sta_dhcp_event_id != MAIN_INVALID_EVENT_ID)
	{
	        hi_event_send(g_main_sta_dhcp_event_id, MAIN_STA_DHCP_EVENT);
	}

	if (g_main_softap_event_id != MAIN_INVALID_EVENT_ID)
	{
	        hi_event_send(g_main_softap_event_id, MAIN_STA_DHCP_EVENT);
	}

    } else if (reason & LWIP_NSC_NETIF_ADDED) {
        printf("LWIP_NSC_NETIF_ADDED COME\n");
    } else if (reason & LWIP_NSC_LINK_CHANGED) {
        printf("LWIP_NSC_LINK_CHANGED COME\n");
    } else if (reason & LWIP_NSC_IPV6_ADDR_STATE_CHANGED) {
        printf("LWIP_NSC_IPV6_ADDR_STATE_CHANGED COME\n");
	if (g_main_sta_dhcp_event_id != MAIN_INVALID_EVENT_ID)
	{
	        hi_event_send(g_main_sta_dhcp_event_id, MAIN_STA_DHCP_EVENT);
	}
    } else if (reason & LWIP_NSC_NETIF_REMOVED) {
        printf("LWIP_NSC_NETIF_REMOVED COME\n");
    } else if (reason & LWIP_NSC_STATUS_CHANGED) {
        printf("LWIP_NSC_STATUS_CHANGED COME\n");
    } else if (reason & LWIP_NSC_IPV6_SET) {
        printf("LWIP_NSC_IPV6_SET COME\n");
    } else {
        printf("Netif status callback id:0x%x\n", reason);
    }
}

static netif_ext_callback_t callback;
hi_s32 hi_channel_init(hi_void)
{
    printf("hichannel 2021-06-11 18:00:00\n");
    err_t ret = netifapi_netif_add_ext_callback(&callback, app_demo_netif_ext_callback);
    if (ret != ERR_OK) {
        printf("hi_channel_init:: netifapi_netif_add_ext_callback failed!");
        return HI_ERR_FAILURE;
    }
#if 0
    if (hi_channel_dev_init(SDIO_TYPE) != HI_ERR_SUCCESS) {
        printf("hi_channel_init:: hichannel_dev_init_wrapper failed");
        return HI_ERR_FAILURE;
    }
#endif
    if (hi_vlwip_netif_init("wlan0") != HI_ERR_SUCCESS) {
        printf("hi_channel_init:: netif failed\n");
        return HI_ERR_FAILURE;
    }

    if (hi_channel_set_default_filter() != HI_ERR_SUCCESS) {
        printf("hi_channel_init:: set_default_filter failed\n");
        return HI_ERR_FAILURE;
    }

    hi_channel_register_rx_cb(hi_channel_rx_callback);
    printf("hi_channel_init is success\n");

    return HI_ERR_SUCCESS;
}

static hi_u32 vlink_hichannel_init(hi_void)
{
	hi_u32 ret = hi_channel_init();
	if (ret != HI_ERR_SUCCESS) {
		printf("hichannel_dev_init failed!\n");
	}

	MLOGD("===OK===\n");
	return ret;
}

hi_void vlink_hichannel_sdio_deepsleep_proc(hi_void)
{
	hi_channel_dev_reset(SDIO_TYPE);
	//vlink_hichannel_sdio_reinit();
	usleep(10*1000);
	MLOGD("===OK===\n");
	return;
}

#define APP_SDIO_INIT_TASK_SIZE 0x1000
#define APP_SDIO_INIT_TASK_PRIO 25

static hi_void *vlink_hichannel_sdio_reinit_proc(hi_void *param)
{
	MLOGD("start sdio reinit\r\n");
	hi_unref_param(param);

	hi_watchdog_disable();
	hi_cache_flush();
	hi_cache_disable();
	hi_channel_dev_reinit(SDIO_TYPE);
	hi_watchdog_enable();
	MLOGD("finish sdio reinit\r\n");
	return HI_NULL;
}

hi_u32 vlink_hichannel_sdio_reinit(hi_void)
{
	/* Create a task to init sdio */
	hi_u32 sdio_reinit_task_id = 0;
	hi_task_attr attr = {0};
	attr.stack_size = APP_SDIO_INIT_TASK_SIZE;
	attr.task_prio = APP_SDIO_INIT_TASK_PRIO;
	attr.task_name = (hi_char*)"sdio_reinit";
	hi_u32 ret = hi_task_create(&sdio_reinit_task_id, &attr, vlink_hichannel_sdio_reinit_proc, HI_NULL);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("Falied to create sdio init task!\n");
	}
	return ret;
}

hi_s32 vlink_PDT_SYSTEM_AddPacketFilterToSyslink(hi_void)
{
	hi_u32 ret;

	return ret;
}

#define HAL_POWER_SOC_GPIO_ON_VALUE  HI_GPIO_VALUE1
#define HAL_POWER_SOC_GPIO_OFF_VALUE HI_GPIO_VALUE0
#define HAL_POWER_SOC_GPIO_DIR_OUT   HI_GPIO_DIR_OUT

#define HI_PDT_SYSTEM_SOC_POWER_PIN  HI_GPIO_IDX_2

hi_u32 vlink_gpio_power_on(hi_void)
{
	hi_gpio_value val = HAL_POWER_SOC_GPIO_ON_VALUE;


	hi_u32 ret = hi_gpio_set_dir(HI_PDT_SYSTEM_SOC_POWER_PIN, HAL_POWER_SOC_GPIO_DIR_OUT);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("dir err.\n");
		return HI_ERR_FAILURE;
	}

	ret = hi_gpio_set_ouput_val(HI_PDT_SYSTEM_SOC_POWER_PIN, val);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("val err.\n");
		return HI_ERR_FAILURE;
	}

	MLOGD("==============vlink_gpio_power_on=OK================\n");
	return 0;
}

hi_u32 vlink_network_wake_up_proc(hi_void)
{
	hi_gpio_value val = HAL_POWER_SOC_GPIO_ON_VALUE;

	vlink_HI_PARAM_System status = {0};
	status.workstatus = VLINK_WIFI_WORK_KEEPLIVE;
	g_work_status = VLINK_WIFI_WORK_KEEPLIVE;
	vlink_HI_PDT_PARAM_SetSystemStatus(&status);	

	vlink_wifi_exit_deep_sleep();
	MLOGE("======check 1-------\n");

	vlink_hichannel_sdio_reinit();

	hi_u32 ret = hi_gpio_set_dir(HI_PDT_SYSTEM_SOC_POWER_PIN, HAL_POWER_SOC_GPIO_DIR_OUT);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("dir err.\n");
		return HI_ERR_FAILURE;
	}

	ret = hi_gpio_set_ouput_val(HI_PDT_SYSTEM_SOC_POWER_PIN, val);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("val err.\n");
		return HI_ERR_FAILURE;
	}

	MLOGD("==============vlink_network_wake_up_proc=OK================\n");
	return 0;
}


hi_u32 vlink_gpio_power_off(hi_void)
{
	hi_gpio_value val = HAL_POWER_SOC_GPIO_OFF_VALUE;
	hi_s32 ret;

	//vlink_hichannel_sdio_deepsleep_proc();

	ret = hi_gpio_set_dir(HI_PDT_SYSTEM_SOC_POWER_PIN, HAL_POWER_SOC_GPIO_DIR_OUT);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("dir err.\n");
		return HI_ERR_FAILURE;
	}

	ret = hi_gpio_set_ouput_val(HI_PDT_SYSTEM_SOC_POWER_PIN, val);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("val err.\n");
		return HI_ERR_FAILURE;
	}

	MLOGD("==============vlink_gpio_power_off=OK================\n");
	return 0;
}

static hi_u32 vlink_set_ssid_pwd_test(hi_void)
{
	hi_char camera_ssid[HI_WIFI_MAX_SSID_LEN + 1] = {0};
	hi_char camera_pwd[HI_WIFI_MAX_KEY_LEN + 1] = {0};	
	vlink_HI_PDT_WIFI_Param wifiParam = { 0 };

#define SSID_PARAM	"infotm"
#define PWD_PARAM	"infotm666666"

	memcpy(wifiParam.ssid, SSID_PARAM, strlen(SSID_PARAM));
	memcpy_s(wifiParam.key, sizeof(wifiParam.key), PWD_PARAM, strlen((hi_char *)PWD_PARAM));

	wifiParam.auth = HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX;
	//wifiParam.auth = HI_WIFI_SECURITY_OPEN;

	wifiParam.pairwise = HI_WIFI_PAIRWISE_TKIP_AES_MIX;
	wifiParam.openDHCP = 1;
	wifiParam.protocolMode = HI_WIFI_PHY_MODE_11BGN;

	MLOGD("-:parseJson-wifiParam.ssid[%s]--wifiParam.key[%s]-\n", wifiParam.ssid, wifiParam.key);

	vlink_HI_PDT_PARAM_SetWifiParam(&wifiParam);

}

static hi_u32 vlink_set_wifi_status(hi_void)
{
	vlink_HI_PARAM_System status = {0};

	vlink_HI_PDT_PARAM_GetSystemStatus(&status);

	status.workstatus = VLINK_WIFI_WORK_DEEPSLEEP;//VLINK_WIFI_WORK_DEEPSLEEP;VLINK_WIFI_WORK_KEEPLIVE
	g_work_status = VLINK_WIFI_WORK_DEEPSLEEP;//VLINK_WIFI_WORK_DEEPSLEEP;VLINK_WIFI_WORK_KEEPLIVE;VLINK_WIFI_WORK_WAKEUP
	vlink_HI_PDT_PARAM_SetSystemStatus(&status);
}


static hi_void *vlink_main_task(hi_void *param)
{
	hi_u32 ret;
	char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
	int len = sizeof(ifname);
	vlink_HI_PARAM_System status = {0};
	hi_unref_param(param);

	vlink_hichannel_init();

	ret = hi_wifi_sta_start(ifname, &len);
	if (ret != HISI_OK) {
		MLOGE("vlink_wpa_connect_ap=hi_wifi_sta_start==%x\n", ret);
		return HI_ERR_FAILURE;
	}
/*
	if (hi_vlwip_netif_init(ifname) != HI_ERR_SUCCESS) {
		MLOGE("hi_vlwip_netif_init:: netif[%s] failed\n", ifname);
		return HI_ERR_FAILURE;
	}
*/
	/* acquire netif for IP operation */
	g_lwip_netif = netifapi_netif_find(ifname);
	if (g_lwip_netif == NULL) {
		MLOGE("%s: get netif failed\n", __FUNCTION__);
		return HI_ERR_FAILURE;
	}
	
	//vlink_check_battery_vol_main();
	//vlink_set_ssid_pwd_test();
	//vlink_set_wifi_status();

	

	//sleep(2);
	//vlink_gpio_power_off();

	//vlink_wifi_deep_sleep();

	//return;
	//vlink_start_softap_task();
	vlink_gpio_power_on(); 			 //@jiaxing temp comment
	//vlink_test_function_main();

	vlink_HI_PDT_PARAM_GetSystemStatus(&status);
	
	if (status.workstatus == VLINK_WIFI_WORK_NETCFG)
	{
		g_work_status = VLINK_WIFI_WORK_NETCFG;
		vlink_HI_PDT_PARAM_SetSystemStatus(&status);
	} else {
		vlink_PDT_SYSTEM_AddPacketFilterToSyslink();
		//vlink_start_sta_connect_dhcp();
		vlink_start_sta_connect_task();
		g_work_status = status.workstatus;
	}
}


hi_void hichannel_vlink_main(hi_void)
{
	hi_u32 ret;

	/* Create a task to handle uart communication */
	hi_task_attr vlinkattr = {0};
	vlinkattr.stack_size = VLINK_TASK_STAK_SIZE;
	vlinkattr.task_prio = VLINK_TASK_PRIORITY - 5;
	vlinkattr.task_name = (hi_char*)"vlink_main";
	ret = hi_task_create(&g_vlink_main_task_id, &vlinkattr, vlink_main_task, HI_NULL);
	if (ret != HI_ERR_SUCCESS) {
		MLOGE("Falied to create hisyslink_vlink_main task!\n");
	}
}


