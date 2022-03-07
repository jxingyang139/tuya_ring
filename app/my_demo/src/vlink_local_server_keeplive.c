/*
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <hi_task.h>
#include <hi_types.h>
#include <hi_types_base.h>

#include <hi_reset.h>
#include <hi_time.h>
#include <hi_watchdog.h>

#include "vlink_hichannel_util.h"
#include "hi_event.h"

#include "sys/time.h"
#include "lwip/netifapi.h"
#include "lwip/tcpip.h"
#include "lwip/sockets.h"
#include "hi_cipher.h"
#include "hi_hwtimer.h"
#include "hi_cpu.h"

hi_s32 g_keepalivePrivateCxtsfd = -1;
static hi_u32 g_recvTaskID = HI_APPCOMM_U32_INVALID_VAL;
hi_s8  g_keepalivePrivaterecvTaskExit = 0;

hi_s32 g_keepaliveSendPacketEventid = 0;
hi_u32 g_keeplive_task_id = 0;
hi_u8  g_keepaliveContextfinish = 0;
hi_u32 g_keepaliveContextRTCTimer = 0;
hi_u32 g_keepaliveContextInternal = 0;

#define SERVERIP "192.168.3.116"
#define SERVERPORT 9000

static hi_bool KEEPALIVE_FindMatchFliter(hi_u8 linkID, hi_char *buf, hi_u32 bufLen, hi_u32 *index)
{
    hi_char WAKEUPSTR[] = "wakeup";
    if (strncmp((hi_char *)WAKEUPSTR, buf, strlen(WAKEUPSTR)) == 0) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

static hi_s32 KEEPALIVE_RecvLinePacket(hi_s32 sfd)
{
    struct sockaddr_in addr = { 0 };
    hi_u32 addrLen = (hi_u32)sizeof(addr);
    hi_char recvBuf[HI_KEEPALIVE_FILTER_LEN_MAX];
    hi_s32 ret;
    hi_u32 index;
    ret = memset_s(recvBuf, HI_KEEPALIVE_FILTER_LEN_MAX, 0, HI_KEEPALIVE_FILTER_LEN_MAX);
    if (ret != EOK) {
        MLOGE("memset_s fail\n");
        return HI_ERR_FAILURE;
    }
    errno = 0;
    ret = recvfrom(sfd, recvBuf, HI_KEEPALIVE_FILTER_LEN_MAX, 0, (struct sockaddr *)&addr, &addrLen);
    if (ret < 0) {
        MLOGE("sfd %d RESV FAIL\r\n", sfd);
        if ((errno != EINTR) && (errno != EAGAIN)) {
            //g_keepalivePrivateCxt.connet[linkID].linkStats = KEEPALIVE_LINK_WAIT_CLOSE;
        }
        return HI_ERR_FAILURE;
    } else if (ret == 0) {
        //g_keepalivePrivateCxt.connet[linkID].linkStats = KEEPALIVE_LINK_WAIT_CLOSE;
        return HI_ERR_FAILURE;
    }
    if (ret < HI_KEEPALIVE_FILTER_LEN_MAX) {
        hi_char ipStr[32] = {0}; /* 32 as ip string max */
        inet_ntop(AF_INET, &addr.sin_addr, ipStr, sizeof(ipStr));
        MLOGI("\r\n+sfd,%d,%d,%s,%d:%s", sfd, ret, ipStr, htons(addr.sin_port), recvBuf);
    }
    if (KEEPALIVE_FindMatchFliter(sfd, recvBuf, ret, &index) == HI_TRUE) {
	MLOGE("===========wakeup=============\r\n");
		vlink_network_wake_up_proc();
    }

    return HI_ERR_SUCCESS;
}

static hi_void KEEPALIVE_RecvPackets(fd_set *readSet)
{
    if (FD_ISSET(g_keepalivePrivateCxtsfd, readSet)) {
        if (KEEPALIVE_RecvLinePacket(g_keepalivePrivateCxtsfd) != HI_ERR_SUCCESS) {
            MLOGE("KEEPALIVE_RecvLinePacket failure\r\n");
        }
    }
    return;
}

static hi_void KEEPALIVE_SetMonitorSoc(fd_set *readSet, hi_s32 *sfdMax)
{
    hi_s32 max = 0;
    hi_u8 i;
    FD_SET(g_keepalivePrivateCxtsfd, readSet);
    *sfdMax = max;
    return;
}

static hi_void *KEEPALIVE_RecvProcess(hi_void *arg)
{
    hi_s32 sfdMax = 0;
    fd_set readSet;
    hi_s32 ret;
    MLOGI("KEEPALIVE_RecvProcess==========1============\r\n");
    g_keepalivePrivaterecvTaskExit = 0;
    while (g_keepalivePrivaterecvTaskExit == 0) {
        hi_cpup_load_check_proc(hi_task_get_current_id(), LOAD_SLEEP_TIME_DEFAULT);
		MLOGI("KEEPALIVE_RecvProcess==========11======sfd[%d]======\r\n", g_keepalivePrivateCxtsfd);
        FD_ZERO(&readSet);
        sfdMax = 0;
        //KEEPALIVE_SetMonitorSoc(&readSet, &sfdMax);
		FD_SET(g_keepalivePrivateCxtsfd, &readSet);
		sfdMax = g_keepalivePrivateCxtsfd;
        ret = lwip_select(sfdMax + 1, &readSet, 0, 0, HI_NULL);
	MLOGI("KEEPALIVE_RecvProcess===========ret[%d]=============\r\n", ret);
        if (ret < 0) {
            MLOGE("socket select failure\r\n");
            goto FAILURE;
        } else if (ret == 0) {
            continue;
        }
        /* ret > 0 means we have something to read, peer send data or new TCP connected */
	MLOGI("KEEPALIVE_RecvProcess===========KEEPALIVE_RecvPackets=============\r\n");
        KEEPALIVE_RecvPackets(&readSet);
    }
    MLOGI("KEEPALIVE_RecvProcess==========2============\r\n");
FAILURE:
    closesocket(g_keepalivePrivateCxtsfd);
    g_keepalivePrivateCxtsfd = -1;
    g_keepalivePrivaterecvTaskExit = -1;
    MLOGI("{KEEPALIVE_RecvProcess exit}\r\n");
    return HI_NULL;
}

static hi_s32 KEEPALIVE_CreateResvTask(hi_void)
{
    hi_s32 ret;
    hi_task_attr attr = { 0 };
    attr.task_prio = KEEPALIVE_TASK_PRIO;
    attr.task_name = "keepalive_trigger";
    attr.stack_size = KEEPALIVE_STACK_SIZE;
    ret = (hi_s32)hi_task_create(&g_recvTaskID, &attr, KEEPALIVE_RecvProcess, HI_NULL);
    HI_APPCOMM_LOG_IF_EXPR_FALSE(ret == HI_ERR_SUCCESS, "hi_task_create");

    return HI_ERR_SUCCESS;
}

static hi_s32 KEEPALIVE_GetValidSoc(hi_char *serverip, hi_char *port)
{
    hi_s32 tos, ret;
    hi_s32 sfd = -1;
    hi_u32 opt = 0;
    struct sockaddr_in srvAddr = { 0 };
    hi_u32 tryCnt = KEEPALIVE_CONNECT_TIME;
    MLOGI("KEEPALIVE_GetValidSoc-----------1--------ok\r\n");
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    HI_APPCOMM_RETURN_IF_EXPR_FALSE(sfd != HI_ERR_FAILURE, HI_ERR_FAILURE);
    MLOGI("KEEPALIVE_GetValidSoc-----------2--------ok\r\n");
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    tos = 128; /* 128:TOS is set 128 and tid = 4, WLAN_WME_AC_VI */
    MLOGI("KEEPALIVE_GetValidSoc-----------3--------ok\r\n");
    ret = setsockopt(sfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    HI_APPCOMM_RETURN_IF_FAIL(ret, HI_ERR_FAILURE);
    MLOGI("KEEPALIVE_GetValidSoc-----------4--------ok\r\n");
    ret = memset_s(&srvAddr, sizeof(srvAddr), 0, sizeof(srvAddr));
    if (ret != EOK) {
        MLOGE("memset_s fail\n");
        return HI_ERR_FAILURE;
    }
    MLOGI("KEEPALIVE_GetValidSoc-SERVERIP[%s]-SERVERPORT[%s]--5---ok\r\n", serverip, port);
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_addr.s_addr = inet_addr(serverip);
    srvAddr.sin_port = htons(atoi(port));
    while (tryCnt != 0) {
        ret = connect(sfd, (struct sockaddr *)&srvAddr, sizeof(srvAddr));
        if (ret != HI_ERR_SUCCESS) {
            tryCnt--;
            MLOGI("connect err, reconnect later.\n");
            usleep(KEEPALIVE_CONNECT_TIMEOUT);
            continue;
        } else {
            MLOGI("connect SUCCESS\n");
            break;
        }
    }
    if (ret != HI_ERR_SUCCESS) {
        closesocket(sfd);
        sfd = -1;
        return sfd;
    }
    return sfd;
}


hi_s32 KEEPALIVE_SendPacket(hi_void)
{
    hi_s32 sendRtn;
    hi_char sendBuf[] = "keeplive";

    if (g_keepalivePrivateCxtsfd != -1) {
        sendRtn = send(g_keepalivePrivateCxtsfd, sendBuf, strlen(sendBuf), 0);
        if ((hi_u32)sendRtn != strlen(sendBuf)) {
            MLOGE("send keepalive packet fail, return is %d}\r\n", sendRtn);
            return HI_ERR_FAILURE;
        }
    }
    return HI_ERR_SUCCESS;
}

hi_s32 KEEPALIVE_Connect(hi_char *serverip, hi_char *port)
{
    hi_s32 sfd;
    hi_s32 ret;

    sfd = KEEPALIVE_GetValidSoc(serverip, port);
    g_keepalivePrivateCxtsfd = sfd;
    if (g_recvTaskID == HI_APPCOMM_U32_INVALID_VAL) {
        ret = KEEPALIVE_CreateResvTask();
        if (ret != HI_ERR_SUCCESS) {
            closesocket(g_keepalivePrivateCxtsfd);
            g_keepalivePrivateCxtsfd = -1;
            return HI_ERR_FAILURE;
        }
    }
    KEEPALIVE_SendPacket();
    return HI_ERR_SUCCESS;
}


hi_s32 KEEPALIVE_Deinit(hi_void)
{
    TSK_INFO_S info;

    closesocket(g_keepalivePrivateCxtsfd);
    g_keepalivePrivateCxtsfd = -1;

    if (g_recvTaskID != HI_APPCOMM_U32_INVALID_VAL) {
        hi_u32 ret = LOS_TaskInfoGet(g_recvTaskID, &info);
        if (ret != LOS_ERRNO_TSK_NOT_CREATED) {
            while (ret != LOS_ERRNO_TSK_NOT_CREATED) {
                LOS_Msleep(100); /* 100 : sleep time */
                ret = LOS_TaskInfoGet(g_recvTaskID, &info);
            }
        }
    }
    g_recvTaskID = HI_APPCOMM_U32_INVALID_VAL;
    //g_keepalivePrivateCxt.resvMuxID = HI_APPCOMM_U32_INVALID_VAL;

    return HI_ERR_SUCCESS;
}

static hi_void KEEPALIVE_RTCTimeout(hi_u32 data)
{
    hi_unref_param(data);
    hi_event_send(g_keepaliveSendPacketEventid, KEEPALIVE_SEND_EVENT);
}

static hi_s32 KEEPALIVE_CreateTimer(hi_u32 intervalS)
{
    hi_s32 ret;
    if (g_keepaliveContextRTCTimer == KEEPALIVE_INVALID_EVENT_ID) {
        ret = hi_timer_create(&g_keepaliveContextRTCTimer);
        if (ret != HI_ERR_SUCCESS) {
            MLOGE("timer create fail\r\n");
            return HI_ERR_FAILURE;
        }
    }
    /* 1000 : mutipel */
    ret = hi_timer_start(g_keepaliveContextRTCTimer, HI_TIMER_TYPE_PERIOD, intervalS * 1000, KEEPALIVE_RTCTimeout, 0);
    if (ret != HI_ERR_SUCCESS) {
        MLOGE("timer start fail\r\n");
        return HI_ERR_FAILURE;
    }
    MLOGI("KEEPALIVE_CreateTimer start ok\r\n");
    return HI_ERR_SUCCESS;
}

#if 0
static hi_void *KEEPALIVE_SendPacketPoc(hi_void *arg)
{
    hi_s32 i, ret;
    hi_u32 eventRet;
    hi_u32 eventBit;
    hi_u32 mask;
    //KEEPALIVE_Init();

    while (g_keepaliveContextfinish == HI_FALSE) {
        eventBit = 0;
        mask = KEEPALIVE_SEND_EVENT | KEEPALIVE_DEINIT_EVENT;
        eventRet = hi_event_wait(g_keepaliveSendPacketEventid, mask, &eventBit, HI_SYS_WAIT_FOREVER,
                                 HI_EVENT_WAITMODE_OR | HI_EVENT_WAITMODE_CLR);
        if (eventRet == HI_ERR_EVENT_WAIT_TIME_OUT) {
            MLOGE("get wakeup event timeout\r\n");
            continue;
        }
        if (eventBit & KEEPALIVE_DEINIT_EVENT) {
            MLOGI("will break send\r\n");
            break;
        }
        /* disconnected links has high priority to reconnect  */
        //KEEPALIVE_ReConnet();

	ret = KEEPALIVE_SendPacket();
    }
    return HI_ERR_SUCCESS;
}
#else
static hi_void *KEEPALIVE_SendPacketPoc(hi_void *arg)
{
    hi_s32 i, ret;
    hi_u32 eventRet;
    hi_u32 eventBit;
    hi_u32 mask;
    //KEEPALIVE_Init();

    MLOGI("KEEPALIVE_SendPacketPoc-expire[%d]--5---ok\r\n", g_keepaliveContextInternal);
    while (g_keepaliveContextfinish == HI_FALSE) {
        eventBit = 0;
        mask = KEEPALIVE_SEND_EVENT | KEEPALIVE_DEINIT_EVENT;
        eventRet = hi_event_wait(g_keepaliveSendPacketEventid, mask, &eventBit, g_keepaliveContextInternal * 1000, //HI_SYS_WAIT_FOREVER,
                                 HI_EVENT_WAITMODE_OR | HI_EVENT_WAITMODE_CLR);
        if (eventRet == HI_ERR_EVENT_WAIT_TIME_OUT) {
            MLOGI("get wakeup event timeout\r\n");
	    ret = KEEPALIVE_SendPacket();
            continue;
        }
        if (eventBit & KEEPALIVE_DEINIT_EVENT) {
            MLOGE("will break send\r\n");
            break;
        }
        /* disconnected links has high priority to reconnect  */
        //KEEPALIVE_ReConnet();

	ret = KEEPALIVE_SendPacket();
    }
    return HI_ERR_SUCCESS;
}
#endif

hi_s32 HI_KEEPALIVE_StartKeepAlive(hi_char *serverip, hi_char *port, hi_u32 expire)
{
    hi_s32 ret;
    hi_task_attr attr = { 0 };
    //ret = KEEPALIVE_CreateTimer(expire);
    //HI_APPCOMM_RETURN_IF_FAIL(ret, ret);
    hi_event_create(&g_keepaliveSendPacketEventid);

    if (HI_ERR_SUCCESS != KEEPALIVE_Connect(serverip, port))
    {
        MLOGE("KEEPALIVE_Init fail -------\r\n");
	return HI_ERR_FAILURE;
    }
    g_keepaliveContextInternal = expire;
    g_keepaliveContextfinish = HI_FALSE;
    attr.task_prio = KEEPALIVE_TASK_PRIO;
    attr.task_name = "sendkeepalive";
    attr.stack_size = KEEPALIVE_STACK_SIZE;
    if (hi_task_create(&g_keeplive_task_id, &attr, KEEPALIVE_SendPacketPoc, NULL) != HI_ERR_SUCCESS) {
        MLOGE(RED "hi_task_create failed \n" NONE);
        return ret;
    }
    MLOGI(RED "HI_KEEPALIVE_StartKeepAlive task ok \n" NONE);
    return HI_ERR_SUCCESS;
}
