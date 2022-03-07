/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
 * Description: mcast6 shell cmd API implementation
 * Author: none
 * Create: 2020
 */

#include "lwip/nettool/mcast6.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/init.h"
#include "lwip/sockets.h"
#include "lwip/nettool/utility.h"
#include "los_config.h"
#include "lwip/tcpip.h"

#if LWIP_MPL
#include "mcast6_table.h"
#endif

#if LWIP_ENABLE_BASIC_SHELL_CMD

#define MCAST6_TEST_PORT (5000)
#define MCAST6_TEST_TASK_NAME "mcast6"
#define MCAST6_TEST_TASK_PRIORITY 25
#define MCAST6_TEST_TASK_STACK 4096
#define MCAST6_RECV_BUF_LEN (128)
#define MCAST6_TASK_DELAY (200) // ms
#define MCAST6_TASK_STOP_DELAY (1000) // ms

static int g_ser_fd = -1;
static int g_cli_fd = -1;
static u8_t g_mcast6_cli_task_finish = lwIP_FALSE;
static u8_t g_mcast6_ser_ip_type = IPADDR_TYPE_V6;

static void
os_shell_mcast6_usage(void)
{
  LWIP_PLATFORM_PRINT("mcast6\n\tser {start srcAddr | stop}\n\tser send destAddr message\n"
         "\tcli {start | stop}\n\ttable show"CRLF
         "\tesmrf {init | deinit}"CRLF);
}

static int
mcast6_ser_socket_op(struct sockaddr *sockaddr, const socklen_t addr_len)
{
  int opt, ret;
  opt = lwIP_TRUE;
  ret = setsockopt(g_ser_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (ret != ERR_OK) {
    LWIP_PLATFORM_PRINT("setsockopt fail errno = %d"CRLF, errno);
    return -1;
  }

  ret = setsockopt(g_ser_fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
  if (ret != ERR_OK) {
    LWIP_PLATFORM_PRINT("setsockopt bcast fail errno = %d"CRLF, errno);
    return -1;
  }

  opt = UDP_TTL;
  ret = setsockopt(g_ser_fd, IPPROTO_IP, IP_MULTICAST_TTL, &opt, sizeof(opt));
  if (ret != ERR_OK) {
    LWIP_PLATFORM_PRINT("setsockopt mcast ttl fail errno = %d"CRLF, errno);
    return -1;
  }

  ret = bind(g_ser_fd, sockaddr, addr_len);
  if (ret != ERR_OK) {
    LWIP_PLATFORM_PRINT("bind src_addr fail errno = %d"CRLF, errno);
    return -1;
  }
  return 0;
}

static err_t
mcast6_ser_start(const char *src_addr)
{
  int ret;
  int domain;
  struct sockaddr_in6 addr6 = {0};
  struct sockaddr_in addr = {0};
  struct sockaddr *sockaddr = NULL;
  socklen_t addr_len;
  ip_addr_t sip;

  if (g_ser_fd >= 0) {
    LWIP_PLATFORM_PRINT("ser have started"CRLF);
    return ERR_OK;
  }

  if (ipaddr_aton(src_addr, &sip) == 0) {
    LWIP_PLATFORM_PRINT("invalid addr"CRLF);
    return ERR_ARG;
  }

  if (sip.type == IPADDR_TYPE_V6) {
    domain = AF_INET6;
    addr6.sin6_family = AF_INET6;
#if LWIP_LITEOS_COMPAT
    (void)memcpy_s((&addr6.sin6_addr)->s6_addr, sizeof(struct ip6_addr),
                   (&sip.u_addr.ip6)->addr, sizeof(struct ip6_addr));
#else
    inet6_addr_from_ip6addr(&addr6.sin6_addr, &sip.u_addr.ip6);
#endif
    addr6.sin6_port = 0;
    addr6.sin6_scope_id = 0;
    sockaddr = (struct sockaddr *)&addr6;
    addr_len = sizeof(addr6);
    g_mcast6_ser_ip_type = IPADDR_TYPE_V6;
  } else {
    domain = AF_INET;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = sip.u_addr.ip4.addr;
    sockaddr = (struct sockaddr *)&addr;
    addr_len = sizeof(addr);
    g_mcast6_ser_ip_type = IPADDR_TYPE_V4;
  }

  g_ser_fd = socket(domain, SOCK_DGRAM, IPPROTO_UDP);
  if (g_ser_fd < 0) {
    LWIP_PLATFORM_PRINT("socket fail errno = %d"CRLF, errno);
    return -1;
  }

  ret = mcast6_ser_socket_op(sockaddr, addr_len);
  if (ret == -1) {
    goto failure;
  }

  return ERR_OK;
failure:
  (void)lwip_close(g_ser_fd);
  g_ser_fd = -1;
  return -1;
}

static err_t
mcast6_ser_stop(void)
{
  if (g_ser_fd >= 0) {
    (void)lwip_close(g_ser_fd);
    g_ser_fd = -1;
  }
  LWIP_PLATFORM_PRINT("stop success"CRLF);

  return ERR_OK;
}

static err_t
mcast6_ser_send(const char *groupaddr, const char *msg)
{
  struct sockaddr_in addr;
  struct sockaddr_in6 addr6 = {0};
  struct sockaddr *to = NULL;
  socklen_t tolen;
  ip_addr_t dip;
  ssize_t actual_send;
  char buf[IPADDR_STRLEN_MAX];

  if (g_ser_fd < 0) {
    LWIP_PLATFORM_PRINT("ser not started"CRLF);
    return ERR_VAL;
  }

  if (ipaddr_aton(groupaddr, &dip) == 0) {
    LWIP_PLATFORM_PRINT("invalid groupaddr %s"CRLF, groupaddr);
    return ERR_ARG;
  }
  if (dip.type != g_mcast6_ser_ip_type) {
    LWIP_PLATFORM_PRINT("invalid ip ver"CRLF);
    return ERR_ARG;
  }
  if (g_mcast6_ser_ip_type == IPADDR_TYPE_V6) {
    if (!ip6_addr_ismulticast(&dip.u_addr.ip6)) {
      LWIP_PLATFORM_PRINT("not mcast6 addr"CRLF);
      return ERR_ARG;
    }
    addr6.sin6_family = AF_INET6;
#if LWIP_LITEOS_COMPAT
    (void)memcpy_s((&addr6.sin6_addr)->s6_addr, sizeof(struct ip6_addr),
                   (&dip.u_addr.ip6)->addr, sizeof(struct ip6_addr));
#else
    inet6_addr_from_ip6addr(&addr6.sin6_addr, &dip.u_addr.ip6);
#endif
    addr6.sin6_port = htons(MCAST6_TEST_PORT);
    to = (struct sockaddr *)&addr6;
    tolen = sizeof(addr6);
  } else {
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MCAST6_TEST_PORT);
    addr.sin_addr.s_addr = dip.u_addr.ip4.addr;
    to = (struct sockaddr *)&addr;
    tolen = sizeof(addr);
  }
  (void)ipaddr_ntoa_r(&dip, buf, IPADDR_STRLEN_MAX);
  LWIP_PLATFORM_PRINT("send %s to %s"CRLF, msg, buf);

  actual_send = sendto(g_ser_fd, msg, strlen(msg), 0, to, tolen);
  LWIP_PLATFORM_PRINT("[%zu] actual_send %zd errno = %d"CRLF, strlen(msg), actual_send, errno);
  if (actual_send < 0) {
    (void)lwip_close(g_ser_fd);
    g_ser_fd = -1;
    LWIP_PLATFORM_PRINT("udp abort"CRLF);
    return ERR_NETUNREACH;
  }

  return ERR_OK;
}

static err_t
mcast6_ser_ctrl(int argc, const char **argv)
{
  err_t ret;

  if ((argc == 3) && (strcmp(argv[1], "start") == 0)) {
    ret = mcast6_ser_start(argv[2]);
  } else if (strcmp(argv[1], "stop") == 0) {
    ret = mcast6_ser_stop();
  } else if ((argc == 4) && (strcmp(argv[1], "send") == 0)) {
    ret = mcast6_ser_send(argv[2], argv[3]);
  } else {
    goto failure;
  }

  return ret;

failure:
  os_shell_mcast6_usage();
  return ERR_ARG;
}

static int
mcast_cli_task_socket_op(void)
{
  int opt;
  int ret;
  g_cli_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (g_cli_fd < 0) {
    LWIP_PLATFORM_PRINT("socket fail errno = %d"CRLF, errno);
    return -1;
  }

  opt = lwIP_TRUE;
  ret = setsockopt(g_cli_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (ret != ERR_OK) {
    LWIP_PLATFORM_PRINT("setsockopt reuse fail errno = %d"CRLF, errno);
    return -1;
  }

  ret = setsockopt(g_cli_fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
  if (ret != ERR_OK) {
    LWIP_PLATFORM_PRINT("setsockopt bcast fail errno = %d"CRLF, errno);
    return -1;
  }
  return 0;
}

static err_t
mcast6_cli_task_start(void)
{
  int ret, actual_recv;
  struct sockaddr *sockaddr = NULL;
  socklen_t addr_len;
  struct sockaddr_in6 addr6 = {0};
  char buffer[MCAST6_RECV_BUF_LEN] = {0};

  ret = mcast_cli_task_socket_op();
  if (ret == -1) {
    goto failure;
  }

  addr6.sin6_family = AF_INET6;
#if LWIP_LITEOS_COMPAT
  (void)memcpy_s((&addr6.sin6_addr)->s6_addr, sizeof(struct ip6_addr),
                 (&(IP6_ADDR_ANY->u_addr.ip6))->addr, sizeof(struct ip6_addr));
#else
  inet6_addr_from_ip6addr(&addr6.sin6_addr, &(IP6_ADDR_ANY->u_addr.ip6));
#endif
  addr6.sin6_port = htons(MCAST6_TEST_PORT);
  sockaddr = (struct sockaddr *)&addr6;
  addr_len = sizeof(addr6);

  if (bind(g_cli_fd, sockaddr, addr_len) != 0) {
    LWIP_PLATFORM_PRINT("bind fail errno = %d"CRLF, errno);
    goto failure;
  }

  LWIP_PLATFORM_PRINT("mcast6 start to recv"CRLF);
  while (g_mcast6_cli_task_finish == lwIP_FALSE) {
    actual_recv = recvfrom(g_cli_fd, buffer, MCAST6_RECV_BUF_LEN, 0, sockaddr, &addr_len);
    if (actual_recv < 0) {
      LWIP_PLATFORM_PRINT("recvfrom failed errno = %d"CRLF, errno);
      break;
    } else {
      char buf[IP6ADDR_STRLEN_MAX];
      (void)ip6addr_ntoa_r((const ip6_addr_t *)(&addr6.sin6_addr), buf, IP6ADDR_STRLEN_MAX);
      LWIP_PLATFORM_PRINT("[Mcast6CliRecv]recv len : %d, data : %.*s, from %s:%hu"CRLF,
                          actual_recv, actual_recv, buffer, buf,
                          ntohs(addr6.sin6_port));
#if (LWIP_LITEOS_COMPAT == 0)
      fflush(NULL);
#endif
    }
    sys_msleep(MCAST6_TASK_DELAY);
  }

  g_mcast6_cli_task_finish = lwIP_FALSE;
  (void)lwip_close(g_cli_fd);
  g_cli_fd = -1;
  LWIP_PLATFORM_PRINT("task exit"CRLF);
  return 0;
failure:
  if (g_cli_fd >= 0) {
    (void)lwip_close(g_cli_fd);
    g_cli_fd = -1;
  }
  return -1;
}

static err_t
mcast6_cli_stop(void)
{
  if (g_cli_fd < 0) {
    LWIP_PLATFORM_PRINT("ser have stopped"CRLF);
    return LOS_OK;
  }
  g_mcast6_cli_task_finish = lwIP_TRUE;
  LWIP_PLATFORM_PRINT("wait task to stop"CRLF);
  sys_msleep(MCAST6_TASK_STOP_DELAY);
  LWIP_PLATFORM_PRINT("task stop success"CRLF);

  return LOS_OK;
}

static err_t
mcast6_cli_start(void)
{
  u32_t ret;

  if (g_cli_fd >= 0) {
    LWIP_PLATFORM_PRINT("mcast6 cli is running"CRLF);
    return LOS_OK;
  }

  ret = sys_thread_new(MCAST6_TEST_TASK_NAME, (lwip_thread_fn)mcast6_cli_task_start, NULL, MCAST6_TEST_TASK_STACK,
                       MCAST6_TEST_TASK_PRIORITY);
  if (ret == SYS_ARCH_ERROR) {
    LWIP_PLATFORM_PRINT("create task %s failed", MCAST6_TEST_TASK_NAME);
    return LOS_NOK;
  }

  return LOS_OK;
}

static err_t
mcast6_cli_ctrl(const char **argv)
{
  err_t ret;

  if (strcmp(argv[1], "start") == 0) {
    ret = mcast6_cli_start();
  } else if (strcmp(argv[1], "stop") == 0) {
    ret = mcast6_cli_stop();
  } else {
    goto failure;
  }

  return ret;

failure:
  os_shell_mcast6_usage();
  return ERR_ARG;
}

#if LWIP_MPL
static void
mcast6_table_print(void *argv)
{
  sys_sem_t *cb_completed = (sys_sem_t *)argv;
  mcast6_table_t *list = mcast6_get_table_list();
  char buf[IP6ADDR_STRLEN_MAX];

  LWIP_PLATFORM_PRINT("%-50s%-16s"CRLF, "mcastAddr", "lifetime");
  while (list != NULL) {
    (void)ip6addr_ntoa_r((const ip6_addr_t *)(&(list->addr)), buf, IP6ADDR_STRLEN_MAX);
    LWIP_PLATFORM_PRINT("%-50s%-16u"CRLF, buf, list->lifetime);
    list = list->next;
  }

  sys_sem_signal(cb_completed);
  return;
}

static err_t
mcast6_table_ctrl(void)
{
  sys_sem_t cb_completed;
  err_t ret;

  if (sys_sem_new(&cb_completed, 0) != ERR_OK) {
    LWIP_PLATFORM_PRINT("%s: sys_sem_new fail"CRLF, __FUNCTION__);
    return LOS_NOK;
  }

  ret = tcpip_callback(mcast6_table_print, &cb_completed);
  if (ret != ERR_OK) {
    sys_sem_free(&cb_completed);
    LWIP_PLATFORM_PRINT("l2test : internal error, ret:%d"CRLF, ret);
    return LOS_NOK;
  }
  (void)sys_arch_sem_wait(&cb_completed, 0);
  sys_sem_free(&cb_completed);

  return ERR_OK;
}
#else
static err_t
mcast6_table_ctrl(void)
{
  return ERR_VAL;
}
#endif /* LWIP_MPL */

static err_t
mcast6_esmrf_ctrl(int argc, const char **argv)
{
#if LWIP_MPL
  err_t ret;

  if ((strcmp(argv[1], "init") == 0) && (argc == 2)) {
    ret = (mcast6_init() == MCAST6_OK) ? ERR_OK : ERR_ARG;
  } else if ((strcmp(argv[1], "deinit") == 0) && (argc == 2)) {
    mcast6_deinit();
    ret = ERR_OK;
  } else {
    goto failure;
  }

  return ret;

failure:
  os_shell_mcast6_usage();
  return ERR_ARG;
#else
  (void)argc;
  (void)argv;
  return ERR_ARG;
#endif
}

u32_t
os_shell_mcast6(int argc, const char **argv)
{
  int ret = -1;
  if (argv == NULL) {
    return LOS_NOK;
  }
  if (argc < 2) { /* 2 : min argc num */
    goto failure;
  }
  if (strcmp(argv[0], "ser") == 0) {
    ret = mcast6_ser_ctrl(argc, argv);
  } else if (strcmp(argv[0], "cli") == 0) {
    ret = mcast6_cli_ctrl(argv);
  } else if ((strcmp(argv[0], "table") == 0) && (strcmp(argv[1], "show") == 0)) {
    ret = mcast6_table_ctrl();
  } else if (strcmp(argv[0], "esmrf") == 0) {
    ret = mcast6_esmrf_ctrl(argc, argv);
  } else {
    goto failure;
  }
#ifdef LWIP_DEBUG_OPEN
  (void)hi_at_printf("mcast6 ret %d"CRLF, ret);
#else
  LWIP_PLATFORM_PRINT("mcast6 ret %d"CRLF, ret);
#endif
  return ((ret == LOS_OK) ? LOS_OK : LOS_NOK);

failure:
  os_shell_mcast6_usage();
  return LOS_NOK;
}

#endif /* LWIP_ENABLE_BASIC_SHELL_CMD */
