
#include <hi_task.h>
#include "hi_types_base.h"
#include "securec.h"
#include "hi_wifi_api.h"
#include "wifi_sta.h"
#include "lwip/ip_addr.h"
#include "lwip/netifapi.h"
#include <hi_nv.h>
#include <hi_time.h>
#include "hi_timer.h"
#include <hi_io.h>

#include "vlink_hichannel_util.h"
#include "cJSON.h"
#include "hi_gpio.h"
#include "hi_event.h"

#include <hi_upg_api.h>
#include <hi_partition_table.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"

hi_u32 g_vlink_update_task_id = 0;
//static hi_u32 g_sta_dhcp_event_id = 0;
static hi_u32 g_wifi_ota_event_id = 0;

#define WIFI_OTA_SUCCESS  (1 << 0)
#define WIFI_OTA_FAIL     (1 << 1)

#define VLINK_UPGRADE_TASK_STAK_SIZE (1024*10)
#define VLINK_UPGRADE_TASK_PRIORITY  25

//#define STA_DHCP_SUCCESS  (1 << 0)
//#define STA_DHCP_FAIL     (1 << 1)



#if 0
struct resp_header//保持相应头信息
{
    int status_code;//HTTP/1.1 '200' OK
    char content_type[128];//Content-Type: application/gzip
    long content_length;//Content-Length: 11683079
    char file_name[256];
};

struct resp_header resp;//全剧变量以便在多个进程中使用


struct resp_header get_resp_header(const char *response)
{
    /*获取响应头的信息*/
    struct resp_header resp;

    char *pos = strstr(response, "HTTP/");
    if (pos)
        sscanf(pos, "%*s %d", &resp.status_code);//返回状态码

    pos = strstr(response, "Content-Type:");//返回内容类型
    if (pos)
        sscanf(pos, "%*s %s", resp.content_type);

    pos = strstr(response, "Content-Length:");//内容的长度(字节)
    if (pos)
        sscanf(pos, "%*s %ld", &resp.content_length);

    return resp;
}

void parse_url(const char *url, char *domain, int *port, char *file_name)
{
    /*通过url解析出域名, 端口, 以及文件名*/
    int j = 0;
    int start = 0;
    *port = 80;
    char *patterns[] = {"http://", "https://", NULL};

    for (int i = 0; patterns[i]; i++)
        if (strncmp(url, patterns[i], strlen(patterns[i])) == 0)
            start = strlen(patterns[i]);

    //解析域名, 这里处理时域名后面的端口号会保留
    for (int i = start; url[i] != '/' && url[i] != '\0'; i++, j++)
        domain[j] = url[i];
    domain[j] = '\0';

    //解析端口号, 如果没有, 那么设置端口为80
    char *pos = strstr(domain, ":");
    if (pos)
        sscanf(pos, ":%d", port);

    //删除域名端口号
    for (int i = 0; i < (int)strlen(domain); i++)
    {
        if (domain[i] == ':')
        {
            domain[i] = '\0';
            break;
        }
    }

    //获取下载文件名
    j = 0;
    for (int i = start; url[i] != '\0'; i++)
    {
        if (url[i] == '/')
        {
            if (i !=  strlen(url) - 1)
                j = 0;
            continue;
        }
        else
            file_name[j++] = url[i];
    }
    file_name[j] = '\0';
}



void get_ip_addr(char *domain, char *ip_addr)
{
    /*通过域名得到相应的ip地址*/
    struct hostent *host = gethostbyname(domain);
    if (!host)
    {
        ip_addr = NULL;
        return;
    }

    for (int i = 0; host->h_addr_list[i]; i++)
    {
        strcpy(ip_addr, inet_ntoa( * (struct in_addr*) host->h_addr_list[i]));
        break;
    }
}


void progressBar(long cur_size, long total_size)
{
    /*用于显示下载进度条*/
    float percent = (float) cur_size / total_size;
    const int numTotal = 50;
    int numShow = (int)(numTotal * percent);

    if (numShow == 0)
        numShow = 1;


    if (numShow > numTotal)
        numShow = numTotal;

    char sign[51] = {0};
    memset(sign, '=', numTotal);

    printf("\r%.2f%%\t[%-*.*s] %.2f/%.2fKB\n", percent * 100, numTotal, numShow, sign, cur_size/1024.0, total_size/1024.0);

    if (numShow == numTotal)
        printf("\n");
}

static int http_download(int socket_d, uintptr_t kernel_upg_addr)
{
    printf("=================start=http_download=====================\n");

    /*下载文件函数, 放在线程中执行*/
    int client_socket = socket_d;
    int length = 0;
    int mem_size = 4096;//mem_size might be enlarge, so reset it
    int buf_len = mem_size;//read 4k each time
    int len;
    hi_u32 ret;

    char *buf = (char *) malloc(mem_size * sizeof(char));
    memset(buf, 0, mem_size);
    printf("=================start=read stream=====================\n");
    //从套接字中读取文件流
    while ((len = lwip_read(client_socket, buf, buf_len)) != 0 && length < resp.content_length)
    {
        //write(fd, buf, len);
	printf("=================start=write addr[%X]======len[%d]===============\n", kernel_upg_addr + length, len);
	ret = hi_upg_transmit(kernel_upg_addr + length, buf, len);
	if (ret != HI_ERR_SUCCESS) {
		free(buf);
		printf("=================start=write fail=====ret[%X]================\n", ret);
		return -1;
	}
        length += len;
	//printf("=================start=read stream=======curr[%d]=all[%d]=============\n", length, resp.content_length);
        progressBar(length, resp.content_length);
	memset(buf, 0, mem_size);
	if (length == resp.content_length)
		break;
    }

    printf("=================start=read ALL=====================\n");

    if (length == resp.content_length)
        printf("Download successful ^_^\n\n");

    free(buf);
    return 0;
}

static int get_http_response_data(uintptr_t kernel_upg_addr, hi_u8 kernel_index)
{
	/* test url: http://img.ivsky.com/img/tupian/pre/201312/04/nelumbo_nucifera-009.jpg */
	char url[100] = "http://192.168.3.116:8080/ubuntu/020/Hi3861_demo_allinone-test-020.bin";
	//char url[100] = "http://192.168.3.5:8080/ubuntu/020/Hi3861_demo_allinone-test-020.bin";
	char domain[64] = {0};
	char ip_addr[16] = {0};
	int port = 80;
	char file_name[50] = {0};
	hi_u32 ret;

	char* header = (char *) malloc(1024 * sizeof(char));
	memset(header, 0, 1024);

	printf("1: Parsing url...\n");
	parse_url(url, domain, &port, file_name);

	printf("2: Get ip address...\n");
	get_ip_addr(domain, ip_addr);
	if (strlen(ip_addr) == 0)
	{
		printf("can not get ip address\n");
		return -1;
	}

	printf("\n>>>>Detail<<<<");
	printf("URL: %s\n", url);
	printf("DOMAIN: %s\n", domain);
	printf("IP: %s\n", ip_addr);
	printf("PORT: %d\n", port);
	printf("FILENAME: %s\n\n", file_name);

	
	if (kernel_index == 1)
	{
		sprintf(header,"GET %s HTTP/1.1\r\nHost: %s\r\n", "/3861L/wifi/Hi3861L_demo_ota_A.bin", domain); 
		printf("download FILENAME: %s\n\n", "Hi3861L_demo_ota_A.bin");
	} else if (kernel_index == 2)
	{
		sprintf(header,"GET %s HTTP/1.1\r\nHost: %s\r\n", "/3861L/wifi/Hi3861L_demo_ota_B.bin", domain); 
		printf("download FILENAME: %s\n\n", "Hi3861L_demo_ota_B.bin");
	}

	strcat(header, "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20100101 Firefox/12.0\r\n");
	strcat(header, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
	strcat(header, "Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n");
	strcat(header, "Accept-Encoding: gzip,deflate\r\n");
	strcat(header, "Connection: keep-alive\r\n\r\n");

	printf("====================================\n");
	printf("header==len:%d\n", strlen(header));
	printf("====================================\n");
	//创建套接字
	int client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client_socket < 0)
	{
		printf("invalid socket descriptor: %d\n", client_socket);
		return -1;
	}
	//创建地址结构体
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip_addr);
	addr.sin_port = htons(port);

	//连接服务器
	printf("3: Connect server...\n");
	int res = connect(client_socket, (struct sockaddr *) &addr, sizeof(addr));
	if (res == -1)
	{
		printf("connect failed, return: %d\n", res);
		return -1;
	}

	printf("4: Send request...\n");//向服务器发送下载请求
	if (lwip_write(client_socket, header, strlen(header)) < 0) {
		lwip_close(client_socket);
		printf("client_socket--------write-error----\n");
		return -1;
	}

	free(header);

	int mem_size = 2048;
	int length = 0;
	int len;
	char buf[5] = {0};
	char *response = (char *) malloc(mem_size * sizeof(char));

	//每次单个字符读取响应头信息, 仅仅读取的是响应部分的头部, 后面单独开线程下载
	while ((len = lwip_read(client_socket, buf, 1)) != 0)
	{
		//printf("lwip_read--------length:%d-len:%d-mem_size:%d--\n", length, len, mem_size);
		if (length + len > mem_size)
		{
			printf("length error------\n");	
		}
		buf[len] = '\0';
		//printf("lwip_read--------buf:%s------\n", buf);
		strcat(response, buf);

		memset(buf, 0, 5);
		//找到响应头的头部信息, 两个"\n\r"为分割点
		int flag = 0;
		for (int i = strlen(response) - 1; response[i] == '\n' || response[i] == '\r'; i--, flag++);
		if (flag == 4)
			break;

		length += len;
	}

	resp = get_resp_header(response);
	strcpy(resp.file_name, file_name);

	
	free(response);

	MLOGD("5: Start thread to download...[%s]\n", resp.file_name);
	ret = http_download(client_socket, kernel_upg_addr);
	return ret;
}


static int dz_test_start_fota_process(hi_void)
{
	hi_u32 max_len; 
	hi_u8 file_index;
	hi_u8 kernel_index;
	hi_u32 file_size = 0x2000;  /*  升级文件大小（实际大小由APP获取）  */ 
	uintptr_t kernel_upg_addr = NULL;

	/*  1.获取APP升级文件大小上限.  */ 
	hi_u32 ret = hi_upg_get_max_file_len(HI_UPG_FILE_KERNEL, &max_len); 
	if ((ret != HI_ERR_SUCCESS)) 
	{ 
		printf("hi_upg_get_max_file_len------error------\n");
		return HI_ERR_UPG_FILE_LEN; 
	}
	printf("hi_upg_get_max_file_len------ok[%X]------\n", max_len);

	ret = hi_upg_get_file_index(&kernel_index);
	if ((ret != HI_ERR_SUCCESS)) 
	{ 
		printf("hi_upg_get_file_index------error------\n");
		return HI_ERR_UPG_FILE_LEN; 
	}
	printf("hi_upg_get_file_index------ok[%d]------\n", kernel_index);


	hi_flash_partition_table *partition = hi_get_partition_table();

	kernel_upg_addr = 0x0;
	printf("kernel_upg_addr------ok[%x]------\n", kernel_upg_addr);

	/*  3.用户自行实现: 通过网口或串口等方式加载对应编号的升级文件. 并调用接口hi_upg_transmit将升级文件传输给UPG模块.  */
/*
	ret = get_http_response_data(kernel_upg_addr, kernel_index);
	if (ret < 0) { 
		printf("get_http_response_data------fail------\n");
		return -1;
	} 
*/
	int length = 0;
	int mem_size = 450;//mem_size might be enlarge, so reset it
	int buf_len = mem_size;//read 4k each time
	int len;
	hi_u32 ret;

	char *buf = (char *) malloc(mem_size * sizeof(char));
	memset(buf, 0, mem_size);

	while (length < resp.content_length)
	{
		

		printf("=================start=write addr[%X]======len[%d]===============\n", kernel_upg_addr + length, len);
		ret = hi_upg_transmit(kernel_upg_addr + length, buf, len);
		if (ret != HI_ERR_SUCCESS) {
			free(buf);
			printf("=================start=write fail=====ret[%X]================\n", ret);
			return -1;
		}
		length += len;

		memset(buf, 0, mem_size);
		if (length == resp.content_length)
			break;
	}

	/*  4.传输完成hi_upg_transmit_finish.如果该接口返错，则停止升级流程.  */ 
	ret = hi_upg_transmit_finish(); 
	if (ret != HI_ERR_SUCCESS) { 
	/*  停止升级流程  */ 
		hi_upg_stop(); 
		printf("hi_upg_transmit_finish------fail------\n");
	} else {
		printf("hi_upg_transmit_finish------ok------\n");
		#if !VLINK_CUSTOM_YUEMIAN_40M
		vlink_gpio_power_off_soc();
		#endif
	}
	/*  5.升级结束hi_upg_finish.  */ 
	hi_upg_finish();
	return 0;
}

static int dz_test_httpclient(hi_void)
{
	hi_u32 dhcpEvent = 0;

	hi_u32 ret = hi_event_create(&g_wifi_ota_event_id);
	if (ret != HI_ERR_SUCCESS) 
	{ 
		MLOGE("dz_test_httpclient ===create event failed .\n"); 
		return -1; 
	}

	MLOGD("dz_test_httpclient wait event===\n"); 

	ret = hi_event_wait(g_sta_dhcp_event_id, STA_DHCP_SUCCESS | STA_DHCP_FAIL, &dhcpEvent, HI_SYS_WAIT_FOREVER, HI_EVENT_WAITMODE_OR | HI_EVENT_WAITMODE_CLR); 
	if (ret == HI_ERR_SUCCESS) 
	{ 
		if (dhcpEvent & STA_DHCP_SUCCESS) 
		{
			MLOGD("dz_test_httpclient wait event dhcp success===\n"); 
			dz_test_start_fota_process();

		} else {
			MLOGE("dz_test_httpclient wait event dhcp fail===\n"); 
		}
	} 
	else 
	{ 
		MLOGD("dz_test_httpclient read event fail!===ret=0X%0X, dhcpEvent = %d--\n", ret, dhcpEvent); 
	} 	

    	return 0;
}
#else

static hi_s32 vlink_hi_channel_sendota_result(hi_u8 result)
{
	hi_u8 rettmp[5] = {0};

	MLOGD("----------start---------\n");

	cJSON * pJsonRoot = NULL;
	cJSON *pJson = NULL;	

	pJsonRoot = cJSON_CreateObject();

	sprintf(rettmp,"%d", result); 

	cJSON_AddStringToObject(pJsonRoot, "cmd", VLINK_WIFI_CMD_SENDMSG_OTARET);
	cJSON_AddStringToObject(pJsonRoot, "ret", rettmp);

	pJson = cJSON_Print(pJsonRoot);

	MLOGD("--pJson[%s]---\n", pJson);

        hi_channel_send_to_host((char*)pJson, strlen(pJson));

	free(pJson);
	cJSON_Delete(pJsonRoot);

	return HI_ERR_SUCCESS;
}

static hi_s32 vlink_hi_channel_sendota_write_result(hi_u8 result)
{
	hi_u8 rettmp[5] = {0};

	MLOGD("----------start---------\n");

	cJSON * pJsonRoot = NULL;
	cJSON *pJson = NULL;	

	pJsonRoot = cJSON_CreateObject();

	sprintf(rettmp,"%d", result); 

	cJSON_AddStringToObject(pJsonRoot, "cmd", VLINK_WIFI_CMD_SENDMSG_OTAWRITERET);
	cJSON_AddStringToObject(pJsonRoot, "ret", rettmp);

	pJson = cJSON_Print(pJsonRoot);

	MLOGD("--pJson[%s]---\n", pJson);

        hi_channel_send_to_host((char*)pJson, strlen(pJson));

	free(pJson);
	cJSON_Delete(pJsonRoot);

	return HI_ERR_SUCCESS;
}

static uintptr_t g_ota_kernel_upg_addr = 0x0;

hi_s32 vlink_start_fota_proc_ota_data(hi_char *databuff)
{
#define WRITE_LEN 800
	hi_s32 ret = HI_ERR_SUCCESS;
	hi_uchar writetmp[WRITE_LEN] = {0};

	cJSON* item;
	cJSON* root = cJSON_Parse(databuff); 

	if(NULL == root)                                                                                         
	{
		MLOGE("-:parseJson---Parse fail\n");
		return HI_ERR_FAILURE;
	}

	item = cJSON_GetObjectItem(root, "data");
	if(NULL != item)
	{
		cJSON *element;
		//strcpy(writetmp, item->valuestring);

		//item = cJSON_GetObjectItem(root, "len");
		hi_u32 datalen = cJSON_GetArraySize(item);
		hi_u32 i = 0;

		if (datalen == 0)
		{
			MLOGD("==success==\n");
			hi_event_send(g_wifi_ota_event_id, WIFI_OTA_SUCCESS);
			return 0;
		}

		MLOGD("-1-datalen[%d]---\n", datalen);

		if (cJSON_IsArray(item)) {
			MLOGD("-2-datalen[%d]---\n", cJSON_GetArraySize(item));
			for (i = 0; i < cJSON_GetArraySize(item); i++)
			{
				cJSON * ArrNumEle = cJSON_GetArrayItem(item, i);
				//从item获取值
				printf("value[%d] : [%02X]\n", i, ArrNumEle->valueint);
				//sprintf(writetmp[i], "%02X", ArrNumEle->valueint);
				writetmp[i] = ArrNumEle->valueint;
			}
		}
/*
		hi_u32 i = 0;
		for(i = 0; i < datalen; i++)
		{
			printf("%02X-", item->valuestring[i]);
		}
*/
		ret = hi_upg_transmit(g_ota_kernel_upg_addr, writetmp, datalen);
		if (ret != HI_ERR_SUCCESS) {
			MLOGE("==start=write fail=====ret[%X]==\n", ret);
			hi_event_send(g_wifi_ota_event_id, WIFI_OTA_FAIL);
			return -1;
		}	

		g_ota_kernel_upg_addr = g_ota_kernel_upg_addr + datalen;
		//hi_sleep(10); /* sleep 10s */

		cJSON_Delete(root);
		vlink_hi_channel_sendota_write_result(0);

	} else {
		MLOGE("-:parseJson-camera_ssid--Parse fail\n");
		hi_event_send(g_wifi_ota_event_id, WIFI_OTA_FAIL);
		cJSON_Delete(root);
		return HI_ERR_FAILURE;
	}

	//MLOGD("==start=write addr[%X]==len[%d]===\n", g_ota_kernel_upg_addr + request->req_len, request->req_len);	
	return 0;	
}

static int vlink_start_fota_process(hi_void)
{
	hi_u32 otaEvent = 0;

	hi_u32 ret = hi_event_create(&g_wifi_ota_event_id);
	if (ret != HI_ERR_SUCCESS) 
	{ 
		MLOGE("===create event failed .\n"); 
		return -1; 
	}

	g_ota_kernel_upg_addr = 0x0;

	MLOGD("===wait event===\n"); 

	sleep(3);

	vlink_hi_channel_sendota_write_result(0);

	ret = hi_event_wait(g_wifi_ota_event_id, WIFI_OTA_SUCCESS | WIFI_OTA_FAIL, &otaEvent, HI_SYS_WAIT_FOREVER, HI_EVENT_WAITMODE_OR | HI_EVENT_WAITMODE_CLR); 
	if (ret == HI_ERR_SUCCESS) 
	{ 
		if (otaEvent & WIFI_OTA_SUCCESS) 
		{
			MLOGD("===wifi ota success===\n"); 
		} else {
			MLOGE("===wifi ota fail===\n");
			vlink_hi_channel_sendota_result(0);
			return -1; 
		}
	} 
	else 
	{ 
		MLOGE("===read event fail!===ret=0X%0X, dhcpEvent = %d--\n", ret, otaEvent); 
		vlink_hi_channel_sendota_result(0);
		return -1; 
	}

	/*  4.传输完成hi_upg_transmit_finish.如果该接口返错，则停止升级流程.  */ 
	ret = hi_upg_transmit_finish(); 
	if (ret != HI_ERR_SUCCESS) { 
	/*  停止升级流程  */ 
		hi_upg_stop(); 
		MLOGE("hi_upg_transmit_finish------fail------\n");
		vlink_hi_channel_sendota_result(0);
		return -1; 
	} else {
		MLOGD("hi_upg_transmit_finish------ok------\n");
		vlink_hi_channel_sendota_result(1);
		//vlink_gpio_power_off_soc();
	}
	/*  5.升级结束hi_upg_finish.  */ 
	//hi_upg_finish();
	return 0;
}

#endif

static hi_void *update_process_main_task(hi_void *param)
{
	hi_u32 ret = 0;

	hi_unref_param(ret);
	hi_unref_param(param);

	MLOGD("update_process_main_task===============.\n");

	vlink_start_fota_process();

	while (1)
	{
		hi_sleep(10000); /* sleep 10s */
	}

	hi_task_delete(g_vlink_update_task_id);
	g_vlink_update_task_id = 0;

	return HI_NULL;
}


hi_void vlink_start_startota_task(hi_void)
{
    hi_u32 ret;

    /* Create a task to handle uart communication */
    hi_task_attr dzattr = {0};
    dzattr.stack_size = VLINK_UPGRADE_TASK_STAK_SIZE;
    dzattr.task_prio = VLINK_UPGRADE_TASK_PRIORITY;
    dzattr.task_name = (hi_char*)"update_main";
    ret = hi_task_create(&g_vlink_update_task_id, &dzattr, update_process_main_task, HI_NULL);
    if (ret != HI_ERR_SUCCESS) {
        MLOGE("Falied to create task!\n");
    }
}
