/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
 * Description: shell cmds APIs implementation about ripple
 * Author: none
 * Create: 2020
 */

#include "lwip/nettool/ripple_shell.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"
#include "lwip/nettool/utility.h"
#include "los_config.h"
#include "lwip/netifapi.h"
#include "lwip/udp.h"

#include "lwip/lwip_rpl.h"
#if LWIP_RIPPLE
#include "rpl_common.h"
#include "rpl_mgmt_api.h"
#include "of_helper.h"
#include "dag.h"
#include "pstore.h"
#include "route_mgmt.h"
#endif

#if LWIP_NAT64
#include "lwip/nat64.h"
#endif

#if LWIP_IP6IN4
#include "lwip/ip6in4.h"
#include "lwip/ip6in4_api.h"
#endif

#if LWIP_RIPPLE && LWIP_ENABLE_BASIC_SHELL_CMD

typedef struct shell_cmd {
  int argc;
  const char **argv;
  sys_sem_t cb_completed;
} shell_cmd_t;

#define RPL_INSTANCE_ID 99
#define DEFAULT_NONMESH_INTERFACE  "wlan0"
static void
rpl_lbr_start(void)
{
  uint8_t ret;
  rpl_addr_t dag_id;
  rpl_prefix_t prefix;
  struct netif *sta_netif = NULL;

  RPL_SET_ADDR(&dag_id, 0xfd00, 0, 0, 0, 0, 0, 0, 0x1000);
  RPL_SET_ADDR(&prefix.addr, 0xfd00, 0, 0, 0, 0, 0, 0, 0x0000);
  prefix.len = 64; /* 64 : ipv6 prefix len */
  prefix.lifetime = 0xffff; /* 0xffff : max ipv6 prefix lifetime */

  sta_netif = netif_find(DEFAULT_NONMESH_INTERFACE);
  if (sta_netif == NULL) {
    LWIP_PLATFORM_PRINT("no such netif named %s"CRLF, DEFAULT_NONMESH_INTERFACE);
    return;
  }

  ret = rpl_get_slaac_addr(&dag_id, rpl_config_get_lladdr());
  if (ret != RPL_OK) {
    LWIP_PLATFORM_PRINT("RplGetSlaacAddr fail"CRLF);
    return;
  }
  ret = rpl_mgmt_set_root(RPL_INSTANCE_ID, NULL, &dag_id);
  if (ret != RPL_OK) {
    LWIP_PLATFORM_PRINT("RplMgmtSetRoot fail"CRLF);
    return;
  }

  ret = rpl_mgmt_set_prefix(RPL_INSTANCE_ID, &prefix);
  if (ret != RPL_OK) {
    LWIP_PLATFORM_PRINT("RplMgmtSetPrefix fail"CRLF);
    return;
  }

  ret = rpl_mgmt_start(RPL_MODE_6LBR);
  if (ret != RPL_OK) {
    LWIP_PLATFORM_PRINT("RplMgmtStart fail"CRLF);
    return;
  }

#if LWIP_NAT64
  (void)nat64_init(sta_netif);
  (void)netif_set_default(sta_netif);
#else
  LWIP_PLATFORM_PRINT("NAT64 stateful is not started, just using mesh"CRLF);
#endif
}

static void
rpl_lr_start(void)
{
  (void)rpl_mgmt_start(RPL_MODE_6LR);

#if LWIP_NAT64 && defined(LWIP_NAT64_STATELESS)
  (void)nat64_init(NULL);
#else
  LWIP_PLATFORM_PRINT("NAT64 stateless is not started, just using ipv6 mesh"CRLF);
#endif
}

static void
rpl_cleanup(void)
{
#if LWIP_NAT64
  (void)nat64_deinit();
#endif
  rpl_mgmt_deinit();
}

static void
rpl_parent_info(rpl_parent_t *prnt)
{
  uint32_t i;
  char buf[IP6ADDR_STRLEN_MAX];
  if ((prnt == NULL)) {
    return;
  }
  (void)ip6addr_ntoa_r((const ip6_addr_t *)(&(prnt->loc_addr)), buf, IP6ADDR_STRLEN_MAX);
  LWIP_PLATFORM_PRINT("\t\tlocAddr: %s"CRLF, buf);
  LWIP_PLATFORM_PRINT("\t\tmacAddr: ");
  for (i = 0; i < prnt->mac_addr.len; i++) {
    if (i == 0) {
      LWIP_PLATFORM_PRINT("%02x", prnt->mac_addr.addr[i]);
    } else {
      LWIP_PLATFORM_PRINT(":%02x", prnt->mac_addr.addr[i]);
    }
  }
  LWIP_PLATFORM_PRINT(CRLF);
  (void)ip6addr_ntoa_r((const ip6_addr_t *)(&(prnt->global_addr)), buf, IP6ADDR_STRLEN_MAX);
  LWIP_PLATFORM_PRINT("\t\tglobalAddr: %s"CRLF, buf);

  LWIP_PLATFORM_PRINT("\t\tmetric:"CRLF);
  LWIP_PLATFORM_PRINT("\t\t\ttype: %hhu"CRLF, prnt->mc.type);
  LWIP_PLATFORM_PRINT("\t\t\tP: %hhu"CRLF, prnt->mc.p);
  LWIP_PLATFORM_PRINT("\t\t\tC: %hhu"CRLF, prnt->mc.c);
  LWIP_PLATFORM_PRINT("\t\t\tO: %hhu"CRLF, prnt->mc.o);
  LWIP_PLATFORM_PRINT("\t\t\tR: %hhu"CRLF, prnt->mc.r);
  LWIP_PLATFORM_PRINT("\t\t\tA: %hhu"CRLF, prnt->mc.a);
  LWIP_PLATFORM_PRINT("\t\t\tprec: %hhu"CRLF, prnt->mc.prec);
  LWIP_PLATFORM_PRINT("\t\t\tobj: %hu"CRLF, prnt->mc.obj.num_hops);

  LWIP_PLATFORM_PRINT("\t\trank: %hu"CRLF, prnt->rank);
  LWIP_PLATFORM_PRINT("\t\tlinkMetric: %hu"CRLF, prnt->link_metric);
  LWIP_PLATFORM_PRINT("\t\tdtsn: %hhu"CRLF, prnt->dtsn);
  LWIP_PLATFORM_PRINT("\t\tsmRssi: %hhd"CRLF, prnt->sm_rssi);
  LWIP_PLATFORM_PRINT("\t\tisResFull: %hhu"CRLF, prnt->is_res_full);
  LWIP_PLATFORM_PRINT("\t\tinuse: %hhu"CRLF, prnt->inuse);
  LWIP_PLATFORM_PRINT("\t\tisPreferred: %hhu"CRLF, prnt->is_preferred);

  LWIP_PLATFORM_PRINT("\t\tdis_timer_cnt: %hu"CRLF, prnt->dis_timer_cnt);
  LWIP_PLATFORM_PRINT("\t\tdis_timer_param: %hu"CRLF, prnt->dis_timer_param);
  LWIP_PLATFORM_PRINT("\t\tdis_retry_cnt: %hhu"CRLF, prnt->dis_retry_cnt);
  LWIP_PLATFORM_PRINT("\t\tcur_dis_state: %hhu"CRLF, prnt->cur_dis_state);

  return;
}

static void
prefix_list_info(rpl_prefix_t *list, u8_t list_len)
{
  u8_t i;
  char buf[IP6ADDR_STRLEN_MAX];

  for (i = 0; i < list_len; i++) {
    if (list[i].len == 0) {
      continue;
    }
    (void)ip6addr_ntoa_r((const ip6_addr_t *)(&(list[i].addr)), buf, IP6ADDR_STRLEN_MAX);
    LWIP_PLATFORM_PRINT("\t\t\t%s/%hhu, lifetime %u, autoAddrConf %hhu, isRouterAddr %hhu"CRLF,
                        buf, list[i].len, list[i].lifetime,
                        list[i].auto_addr_conf, list[i].is_router_addr);
  }

  return;
}

static void
rpl_instance_info(struct rpl_instance_s *inst)
{
  LWIP_PLATFORM_PRINT("\tinstID: %"RPL_INST_F CRLF, inst->inst_id);
  if (inst->obj_func) {
    LWIP_PLATFORM_PRINT("\t\tocp: %hu"CRLF, inst->obj_func->ocp);
  }
  LWIP_PLATFORM_PRINT("\t\tmode: %hhu"CRLF, inst->mode);
  LWIP_PLATFORM_PRINT("\t\tisroot: %hhu"CRLF, inst->isroot);
  LWIP_PLATFORM_PRINT("\t\ttarget:"CRLF);
  prefix_list_info(inst->target, RPL_CONF_MAX_TARGETS);
  LWIP_PLATFORM_PRINT("\t\tprefix:"CRLF);
  prefix_list_info(inst->prefix, RPL_CONF_MAX_PREFIXES);
  LWIP_PLATFORM_PRINT("\t\tcfg:"CRLF);
  LWIP_PLATFORM_PRINT("\t\t\trackTimerVal: %u"CRLF, inst->cfg.rack_timer_val);
  LWIP_PLATFORM_PRINT("\t\t\tlifetimeUnit: %hu"CRLF, inst->cfg.lifetime_unit);
  LWIP_PLATFORM_PRINT("\t\t\tminRankInc: %hu"CRLF, inst->cfg.min_rank_inc);
  LWIP_PLATFORM_PRINT("\t\t\tmaxRankInc: %hu"CRLF, inst->cfg.max_rank_inc);
  LWIP_PLATFORM_PRINT("\t\t\tocp: %hu"CRLF, inst->cfg.ocp);
  LWIP_PLATFORM_PRINT("\t\t\tlifetime: %hhu"CRLF, inst->cfg.lifetime);
  LWIP_PLATFORM_PRINT("\t\t\tdioImin: %hhu"CRLF, inst->cfg.dio_imin);
  LWIP_PLATFORM_PRINT("\t\t\tdioRed: %hhu"CRLF, inst->cfg.dio_red);
  LWIP_PLATFORM_PRINT("\t\t\tdioIdbl: %hhu"CRLF, inst->cfg.dio_idbl);
  LWIP_PLATFORM_PRINT("\t\t\tmop: %hhu"CRLF, inst->cfg.mop);
  LWIP_PLATFORM_PRINT("\t\t\trackRetry: %hhu"CRLF, inst->cfg.rack_retry);

  return;
}

static void
rpl_dag_info(rpl_dag_t *dag)
{
  int         state = 0;
  rpl_parent_t *prnt = NULL;
  char buf[IP6ADDR_STRLEN_MAX];
  if (dag == NULL) {
    return;
  }
  if (dag->inst != NULL) {
    rpl_instance_info(dag->inst);
  }
  (void)ip6addr_ntoa_r((const ip6_addr_t *)(&(dag->dodag_id)), buf, IP6ADDR_STRLEN_MAX);
  LWIP_PLATFORM_PRINT("\tdodagID: %s"CRLF, buf);
  LWIP_PLATFORM_PRINT("\tmnid: %hhu"CRLF, dag->mnid);
  LWIP_PLATFORM_PRINT("\tdaoSeq: %hhu"CRLF, dag->dao_seq);
  LWIP_PLATFORM_PRINT("\tlastJoinStatus: %hhu"CRLF, dag->last_join_status);
  LWIP_PLATFORM_PRINT("\tcurDaoState: %hhu"CRLF, dag->cur_dao_state);
  LWIP_PLATFORM_PRINT("\tdaoRetryCnt: %hhu"CRLF, dag->dao_retry_cnt);
  LWIP_PLATFORM_PRINT("\trank: %hu"CRLF, dag->rank);
  LWIP_PLATFORM_PRINT("\toldrank: %hu"CRLF, dag->old_rank);
  LWIP_PLATFORM_PRINT("\tdodagVerNum: %hhu"CRLF, dag->dodag_ver_num);
  LWIP_PLATFORM_PRINT("\tdtsnOut: %hhu"CRLF, dag->dtsn_out);
  LWIP_PLATFORM_PRINT("\tpreference: %hhu"CRLF, dag->preference);
  LWIP_PLATFORM_PRINT("\tpathSeq: %hhu"CRLF, dag->path_seq);
  LWIP_PLATFORM_PRINT("\tgrounded: %hhu"CRLF, dag->grounded);
  LWIP_PLATFORM_PRINT("\tmetricUpdated: %hhu"CRLF, dag->metric_updated);
  LWIP_PLATFORM_PRINT("\tstate: %hhu"CRLF, dag->state);
  LWIP_PLATFORM_PRINT("\tinuse: %hhu"CRLF, dag->inuse);
  LWIP_PLATFORM_PRINT("\tis_prefer: %hhu"CRLF, dag->is_prefer);
  LWIP_PLATFORM_PRINT("\tparent:"CRLF);
  while ((prnt = rpl_get_next_parent(dag, &state))) {
    LWIP_PLATFORM_PRINT("\t\t[%d]:"CRLF, state - 1);
    rpl_parent_info(prnt);
  }
  return;
}

static void
rpl_dags_info(void)
{
  rpl_dag_t *dag = NULL;
  int state = 0;
  u8_t i, j;

  i = rpl_config_get_rinited();
  j = is_rpl_running();

  LWIP_PLATFORM_PRINT("rpl status:");
  LWIP_PLATFORM_PRINT("%s ", (i == RPL_TRUE) ? "inited" : "uninit");
  LWIP_PLATFORM_PRINT("%s"CRLF, (j == RPL_TRUE) ? "running" : "stopped");
  LWIP_PLATFORM_PRINT("mg_cnt=%hu route_cnt=%hu mstat_cnt=%hhu"CRLF,
                       rpl_get_mg_cnt(), rpl_get_route_cnt(), rpl_get_msta_cnt());
  LWIP_PLATFORM_PRINT("[%s][%d] start"CRLF, __FUNCTION__, __LINE__);
  while ((dag = rpl_get_next_inuse_dag(&state))) {
    i = (uint8_t)((u32_t)state & 0x0000ffff);
    j = (uint8_t)(((u32_t)state & 0x7fff0000) >> 16);
    LWIP_PLATFORM_PRINT("[%hhu][%hhu]:"CRLF, i, (u8_t)(j - 1));
    rpl_dag_info(dag);
  }
  LWIP_PLATFORM_PRINT("[%s][%d] end"CRLF, __FUNCTION__, __LINE__);

  return;
}

static void
os_shell_rpl_internal(void *arg)
{
  struct netif *netif_p = NULL;
  int node_br;
  shell_cmd_t *rpl_cmd = (shell_cmd_t *)arg;
  int argc = rpl_cmd->argc;
  const char **argv = rpl_cmd->argv;

  if ((argc == 3) && (strcmp(argv[1], "start") == 0)) {
    netif_p = netif_find(argv[0]);
    if (netif_p == NULL) {
      LWIP_PLATFORM_PRINT("no such netif named %s"CRLF, argv[0]);
      goto usage;
    }
    node_br = !!atoi(argv[2]);
    if (RPL_OK != rpl_mgmt_init((rpl_netdev_t *)netif_p)) {
      LWIP_PLATFORM_PRINT("RplMgmtInit fail"CRLF);
      sys_sem_signal(&rpl_cmd->cb_completed);
      return;
    }

    if (node_br) {
      rpl_lbr_start();
    } else {
      rpl_lr_start();
      (void)netif_set_default(netif_p);
    }
    netif_p->flags |= NETIF_IS_RPL_UP;
  } else if ((argc == 2) && (strcmp(argv[1], "stop") == 0)) {
    netif_p = netif_find(argv[0]);
    if (netif_p == NULL) {
      goto usage;
    }
    rpl_cleanup();
    netif_p->flags &= (~NETIF_IS_RPL_UP);
  } else if ((argc == 1) && (strcmp(argv[0], "dag") == 0)) {
    rpl_dags_info();
  } else {
    goto usage;
  }

  sys_sem_signal(&rpl_cmd->cb_completed);
  return;
usage:
  LWIP_PLATFORM_PRINT("rpl"CRLF"\tifname start isBr"CRLF"\tifname stop"CRLF"\tdag\tprint dags information"CRLF);
  sys_sem_signal(&rpl_cmd->cb_completed);
  return;
}

u32_t
os_shell_rpl(int argc, const char **argv)
{
  shell_cmd_t rpl_cmd = {0};
  err_t ret;
  if (argv == NULL) {
    return LOS_NOK;
  }
  if (sys_sem_new(&rpl_cmd.cb_completed, 0) != ERR_OK) {
#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("%s: sys_sem_new fail"CRLF, __FUNCTION__);
#else
    LWIP_PLATFORM_PRINT("%s: sys_sem_new fail"CRLF, __FUNCTION__);
#endif
    return LOS_NOK;
  }

  rpl_cmd.argc = argc;
  rpl_cmd.argv = argv;

  ret = tcpip_callback(os_shell_rpl_internal, &rpl_cmd);
  if (ret != ERR_OK) {
    sys_sem_free(&rpl_cmd.cb_completed);
#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("rpl : internal error, ret:%d"CRLF, ret);
#else
    LWIP_PLATFORM_PRINT("rpl : internal error, ret:%d"CRLF, ret);
#endif
    return LOS_NOK;
  }
  (void)sys_arch_sem_wait(&rpl_cmd.cb_completed, 0);
  sys_sem_free(&rpl_cmd.cb_completed);

  return LOS_OK;
}

#define L2_TEST_PORT (12345)
#define BYTE_IN_HEX_LEN (2)
#define L2_PBUF_MSG_LEN (32)

static struct udp_pcb *g_test_serv_pcb = NULL;

static void
l2test_pbuf_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
  u16_t len = p->len;
  unsigned char *data = (unsigned char *)(p->payload);
  u8_t i;
  char buf[IP6ADDR_STRLEN_MAX];

  (void)arg;
  (void)pcb;
  (void)addr;
  (void)port;

  LWIP_PLATFORM_PRINT("recv from ");
  for (i = 0; i < NETIF_MAX_HWADDR_LEN; i++) {
    if (i == 0) {
      LWIP_PLATFORM_PRINT("%02x", p->mac_address[i]);
    } else {
      LWIP_PLATFORM_PRINT(":%02x", p->mac_address[i]);
    }
  }

  (void)ip6addr_ntoa_r(&(addr->u_addr.ip6), buf, IP6ADDR_STRLEN_MAX);
  LWIP_PLATFORM_PRINT(" %s:%hu"CRLF, buf, port);
  LWIP_PLATFORM_PRINT("RSSI : %hhd"CRLF, PBUF_GET_RSSI(p));
  LWIP_PLATFORM_PRINT("recv len : %hu, data : %.*s"CRLF, len, len, data);

  return;
}

static err_t
l2test_pbuf_stop(void)
{
  if (g_test_serv_pcb != NULL) {
    udp_remove(g_test_serv_pcb);
    g_test_serv_pcb = NULL;
  }

  return LOS_OK;
}

static err_t
l2test_pbuf_start(struct netif *netif)
{
  err_t result;

  if (g_test_serv_pcb != NULL) {
    LWIP_PLATFORM_PRINT("already start"CRLF);
    return ERR_OK;
  }
  g_test_serv_pcb = udp_new_ip6();
  if (g_test_serv_pcb == NULL) {
    LWIP_PLATFORM_PRINT("udp_new_ip6 failed"CRLF);
    return ERR_MEM;
  }
  ip_set_option(g_test_serv_pcb, SOF_BROADCAST);
  result = udp_bind(g_test_serv_pcb, IP6_ADDR_ANY, L2_TEST_PORT);
  if (result != ERR_OK) {
    LWIP_PLATFORM_PRINT("udp_bind failed"CRLF);
    udp_remove(g_test_serv_pcb);
    g_test_serv_pcb = NULL;
    return result;
  }

  result = udp_connect(g_test_serv_pcb, IP6_ADDR_ANY, L2_TEST_PORT);
  if (result != ERR_OK) {
    LWIP_PLATFORM_PRINT("udp_connect failed"CRLF);
    udp_remove(g_test_serv_pcb);
    g_test_serv_pcb = NULL;
    return result;
  }
  g_test_serv_pcb->netif_idx = netif->ifindex;
  udp_recv(g_test_serv_pcb, l2test_pbuf_recv, NULL);

  return result;
}

static err_t
l2test_pbuf_send(struct netif *netif, int argc, const char **argv)
{
  err_t err;
  ip_addr_t dst_addr = {0};
  char msg[L2_PBUF_MSG_LEN] = {0};
  struct pbuf *p_out = NULL;
  int pri;
  char buf[IP6ADDR_STRLEN_MAX];

  if (g_test_serv_pcb == NULL) {
    LWIP_PLATFORM_PRINT("pcb not init"CRLF);
    return ERR_VAL;
  }

  if (ip6addr_aton(argv[3], &(dst_addr.u_addr.ip6)) == ERR_OK) {
    LWIP_PLATFORM_PRINT("invalid ip6 addr"CRLF);
    return ERR_ARG;
  }
  (void)ip6addr_ntoa_r(&(dst_addr.u_addr.ip6), buf, IP6ADDR_STRLEN_MAX);
  LWIP_PLATFORM_PRINT("dst ip6 %s, priority %s"CRLF, buf, argv[4]);
  if (sprintf_s(msg, sizeof(msg), "send msg priority %s", argv[4]) == -1) {
    return ERR_MEM;
  }
  IP_SET_TYPE_VAL(dst_addr, IPADDR_TYPE_V6);
  p_out = pbuf_alloc(PBUF_TRANSPORT, (u16_t)(strlen(msg)), PBUF_RAM);
  if (p_out == NULL) {
    LWIP_PLATFORM_PRINT("pbuf_alloc failed"CRLF);
    return ERR_MEM;
  }
  (void)memcpy_s(p_out->payload, (u16_t)(strlen(msg)), msg, (u16_t)(strlen(msg)));
  pri = atoi(argv[4]);
  /* 3 : beacon priority */
  g_test_serv_pcb->priority = (pri > 3) ? 3 : pri;
  /* 6 argc index is six and argv is five */
  if ((argc == 6) && (strcmp(argv[5], "ctrl") == ERR_OK)) {
    p_out->flags |= PBUF_FLAG_CTRL_PKT;
  }

  pbuf_realloc(p_out, (u16_t)(strlen(msg)));

  err = udp_sendto_if(g_test_serv_pcb, p_out, &dst_addr, L2_TEST_PORT, netif);
  LWIP_PLATFORM_PRINT("send [%s] %d"CRLF, msg, err);
  (void)pbuf_free(p_out);

  return err;
}

static err_t
l2test_remove_peer(struct netif *netif, const char *mac_str)
{
  err_t ret;
  struct linklayer_addr peer_addr = {0};
  char *digit = NULL;
  u32_t mac_addr_len = strlen(mac_str) + 1;
  char tmp_str[MAX_MACADDR_STRING_LENGTH];
  char *tmp_str1 = NULL;
  char *save_ptr = NULL;
  u8_t j;

  if (mac_addr_len != MAX_MACADDR_STRING_LENGTH) {
    LWIP_PLATFORM_PRINT("wrong MAC address format"CRLF);
    return LOS_NOK;
  }

  ret = strncpy_s(tmp_str, mac_addr_len, mac_str, mac_addr_len - 1);
  if (ret != EOK) {
    LWIP_PLATFORM_PRINT("strncpy_s failed"CRLF);
    return LOS_NOK;
  }
  for (j = 0, tmp_str1 = tmp_str; j < NETIF_MAX_HWADDR_LEN; j++, tmp_str1 = NULL) {
    digit = strtok_r(tmp_str1, ":", &save_ptr);
    if ((digit == NULL) || (strlen(digit) > BYTE_IN_HEX_LEN)) {
      LWIP_PLATFORM_PRINT("wrong MAC address format"CRLF);
      return LOS_NOK;
    }
    convert_string_to_hex(digit, &peer_addr.addr[j]);
  }
  peer_addr.addrlen = NETIF_MAX_HWADDR_LEN;
  ret = netif_remove_peer(netif, &peer_addr);

  return ret;
}

static err_t
l2test_callback_status(struct netif *netif)
{
#if LWIP_IPV4 && LWIP_IGMP && LWIP_LINK_MCAST_FILTER
  LWIP_PLATFORM_PRINT("igmp_mac_filter %s"CRLF, ((netif->igmp_mac_filter == NULL) ? "null" : "not null"));
#endif /* LWIP_IPV4 && LWIP_IGMP && LWIP_LINK_MCAST_FILTER */
#if LWIP_IPV6 && LWIP_IPV6_MLD && LWIP_LINK_MCAST_FILTER
  LWIP_PLATFORM_PRINT("mld_mac_filter %s"CRLF, ((netif->mld_mac_filter == NULL) ? "null" : "not null"));
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD && LWIP_LINK_MCAST_FILTER */
  LWIP_PLATFORM_PRINT("remove_peer %s"CRLF, ((netif->remove_peer == NULL) ? "null" : "not null"));
  LWIP_PLATFORM_PRINT("set_beacon_prio %s"CRLF, ((netif->set_beacon_prio == NULL) ? "null" : "not null"));
  LWIP_PLATFORM_PRINT("set_unique_id %s"CRLF, ((netif->set_unique_id == NULL) ? "null" : "not null"));
  LWIP_PLATFORM_PRINT("linklayer_event %s"CRLF, ((netif->linklayer_event == NULL) ? "null" : "not null"));

  return LOS_OK;
}

static void
os_shell_l2test_usage(void)
{
  LWIP_PLATFORM_PRINT("l2test"CRLF);
  LWIP_PLATFORM_PRINT("\t%-32s%s"CRLF, "ifname remove mac_addr_str",
                      "disassociate peer through MAC address. {l2test wlan0 remove 11:22:33:44:55:66}");
  LWIP_PLATFORM_PRINT("\t%-32s%s"CRLF, "ifname prio priority",
                      "set beacon priority, value of priority is 0~255. {l2test wlan0 prio 56}");
  LWIP_PLATFORM_PRINT("\t%-32s%s"CRLF, "ifname mnid mnid_value",
                      "set mnid of mesh node, value of mnid is 0~127. {l2test wlan0 mnid 2}");
  LWIP_PLATFORM_PRINT("\t%-32s%s"CRLF, "ifname all",
                      "show callback functions of netif registered status. {l2test wlan0 all}");
  LWIP_PLATFORM_PRINT("\t%-32s%s"CRLF, "ifname pbuf {start | stop}", "start/stop a udp pcb");
  LWIP_PLATFORM_PRINT("\t%-32s"CRLF, "ifname pbuf send dst_ip6_ip priority_value(0,1,2,3) [ctrl]");
  LWIP_PLATFORM_PRINT("\t%-32s%s"CRLF, "", "send a message to dst_ip6_ip, priority_value can be one in (0,1,2,3), \
                      'ctrl' is optional");
  LWIP_PLATFORM_PRINT("\t%-32s"CRLF, "store {read | write} \
                      {ver | flag | dtsn | dodagVerNum | pathSeq | daoSeq | dcoSeq} [value]");
  LWIP_PLATFORM_PRINT("\t%-32s%s"CRLF, "", "range of value is 0~255");

  return;
}

static err_t
l2test_store_read_or_write(const char *nv_ctrl, u8_t *is_read)
{
  if (strcmp(nv_ctrl, "read") == ERR_OK) {
    *is_read = lwIP_TRUE;
  } else if (strcmp(nv_ctrl, "write") == ERR_OK) {
    *is_read = lwIP_FALSE;
  } else {
    os_shell_l2test_usage();
    goto failure;
  }
  return ERR_OK;
failure:
  return ERR_ARG;
}

static err_t
l2test_store_key_id(const char *nv_key, u8_t *nv_key_id)
{
  if (strcmp(nv_key, "ver") == ERR_OK) {
    *nv_key_id = PS_VER;
  } else if (strcmp(nv_key, "flag") == ERR_OK) {
    *nv_key_id = PS_FLAG;
  } else if (strcmp(nv_key, "dtsn") == ERR_OK) {
    *nv_key_id = PS_DTSN;
  } else if (strcmp(nv_key, "dodagVerNum") == ERR_OK) {
    *nv_key_id = PS_DODAGVERNUM;
  } else if (strcmp(nv_key, "pathSeq") == ERR_OK) {
    *nv_key_id = PS_PATHSEQ;
  } else if (strcmp(nv_key, "daoSeq") == ERR_OK) {
    *nv_key_id = PS_DAOSEQ;
  } else if (strcmp(nv_key, "dcoSeq") == ERR_OK) {
    *nv_key_id = PS_DCOSEQ;
  } else {
    os_shell_l2test_usage();
    goto failure;
  }
  return ERR_OK;
failure:
  return ERR_ARG;
}

static err_t
l2test_store(int argc, const char **argv)
{
  err_t ret;
  u8_t is_read = lwIP_TRUE;
  u8_t nv_key_id;
  u8_t value;
  if (argv == NULL) {
    return LOS_NOK;
  }
  ret = l2test_store_read_or_write(argv[1], &is_read);
  if (ret != ERR_OK) {
    goto failure;
  }
  if ((is_read == lwIP_FALSE) && (argc != 4)) { /* 4 ：argc index */
    os_shell_l2test_usage();
    goto failure;
  }
  ret = l2test_store_key_id(argv[2], &nv_key_id);
  if (ret != ERR_OK) {
    goto failure;
  }

  if (is_read == lwIP_TRUE) {
    ret = (rpl_pstore_read(nv_key_id, &value, sizeof(value)) == RPL_OK) ? ERR_OK : ERR_ARG;
    if (ret == ERR_OK) {
      LWIP_PLATFORM_PRINT("read %s %hhu"CRLF, argv[2], value);
    }
  } else {
    value = (u8_t)atoi(argv[3]);
    ret = (rpl_pstore_write(nv_key_id, &value, sizeof(value)) == RPL_OK) ? ERR_OK : ERR_ARG;
    if (ret == ERR_OK) {
      LWIP_PLATFORM_PRINT("write %s %hhu"CRLF, argv[2], value);
    }
  }

  return ret;
failure:
  return ERR_ARG;
}

static void
os_shell_l2test_internal(void *arg)
{
  err_t ret = ERR_VAL;
  struct netif *netif = NULL;
  u8_t prio;
  uniqid_t id;
  shell_cmd_t *l2test_cmd = (shell_cmd_t *)arg;
  int argc = l2test_cmd->argc;
  const char **argv = l2test_cmd->argv;

  if (argc < 1) {
    os_shell_l2test_usage();
    sys_sem_signal(&l2test_cmd->cb_completed);
    return;
  }
  if ((argc >= 3) && (strcmp(argv[0], "store") == ERR_OK)) {
    ret = l2test_store(argc, argv);
    goto funcRet;
  }
  netif = netif_find(argv[0]);
  if (netif == NULL) {
    LWIP_PLATFORM_PRINT("not find %s"CRLF, argv[0]);
    sys_sem_signal(&l2test_cmd->cb_completed);
    return;
  }
  if ((argc == 3) && (strcmp(argv[1], "remove") == ERR_OK)) {
    ret = l2test_remove_peer(netif, argv[2]);
  } else if ((argc == 3) && (strcmp(argv[1], "prio") == ERR_OK)) {
    /* value of priority is 0~255 */
    if ((atoi(argv[2]) < 0) || (atoi(argv[2]) > 255)) {
      LWIP_PLATFORM_PRINT("invalid prio"CRLF);
      ret = -1;
      goto funcRet;
    }
    prio = (u8_t)(atoi(argv[2]));
    ret = netif_set_beacon_prio(netif, prio);
  } else if ((argc == 3) && (strcmp(argv[1], "mnid") == ERR_OK)) {
    /* value of mnid is 0~127 */
    if ((atoi(argv[2]) < 0) || (atoi(argv[2]) > 127)) {
      LWIP_PLATFORM_PRINT("invalid mnid"CRLF);
      ret = -1;
      goto funcRet;
    }
    id = (uniqid_t)(atoi(argv[2]));
    ret = netif_set_unique_id(netif, id);
  } else if ((argc == 2) && (strcmp(argv[1], "all") == ERR_OK)) {
    ret = l2test_callback_status(netif);
  } else if ((argc >= 3) && (strcmp(argv[1], "pbuf") == ERR_OK)) {
    if (strcmp(argv[2], "start") == ERR_OK) {
      ret = l2test_pbuf_start(netif);
    } else if (strcmp(argv[2], "stop") == ERR_OK) {
      ret = l2test_pbuf_stop();
    } else if ((argc >= 5) && (strcmp(argv[2], "send") == ERR_OK)) {
      ret = l2test_pbuf_send(netif, argc, argv);
    } else {
      os_shell_l2test_usage();
    }
  } else {
    os_shell_l2test_usage();
  }

funcRet:
  LWIP_PLATFORM_PRINT("ret %d"CRLF, ret);

  sys_sem_signal(&l2test_cmd->cb_completed);
  return;
}

u32_t
os_shell_l2test(int argc, const char **argv)
{
  shell_cmd_t l2test_cmd = {0};
  err_t ret;
  if (argv == NULL) {
    return LOS_NOK;
  }
  if (sys_sem_new(&l2test_cmd.cb_completed, 0) != ERR_OK) {
#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("%s: sys_sem_new fail"CRLF, __FUNCTION__);
#else
    LWIP_PLATFORM_PRINT("%s: sys_sem_new fail"CRLF, __FUNCTION__);
#endif
    return LOS_NOK;
  }

  l2test_cmd.argc = argc;
  l2test_cmd.argv = argv;

  ret = tcpip_callback(os_shell_l2test_internal, &l2test_cmd);
  if (ret != ERR_OK) {
    sys_sem_free(&l2test_cmd.cb_completed);
#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("l2test : internal error, ret:%d"CRLF, ret);
#else
    LWIP_PLATFORM_PRINT("l2test : internal error, ret:%d"CRLF, ret);
#endif
    return LOS_NOK;
  }
  (void)sys_arch_sem_wait(&l2test_cmd.cb_completed, 0);
  sys_sem_free(&l2test_cmd.cb_completed);

  return LOS_OK;
}

u32_t
os_rte_debug(int argc, const char **argv)
{
  s32_t cnt = 0;
  ip6_addr_t ipv6_addr;
  char ac_ipv6_addr[IP6ADDR_STRLEN_MAX + 1] = {0};
  char *tmp = NULL;
  (void)argc;
  (void)argv;
  if (tcpip_init_finish == 0) {
#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("%s: tcpip_init have not been called"CRLF, __FUNCTION__);
#else
    LWIP_PLATFORM_PRINT("%s: tcpip_init have not been called"CRLF, __FUNCTION__);
#endif
    goto exit;
  }
  rpl_rte_info_t rte_info = {0};
  LOCK_TCPIP_CORE();
#ifdef LWIP_DEBUG_OPEN
  (void)hi_at_printf("%s, %s, %s, %s, %s, %s, %s"CRLF, "Idx", "RplAddrS",
                     "Nhop", "MNID", "Ltime", "con_time", "route-sync");
#else
  LWIP_PLATFORM_PRINT("%s, %s, %s, %s, %s, %s，%s"CRLF, "Idx", "RplAddrS",
                      "Nhop", "MNID", "Ltime", "con_time", "route-sync");
#endif
  while (rpl_platform_get_next_rte(&rte_info) == RPL_OK) {
#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("%d,", ++cnt);
#else
    LWIP_PLATFORM_PRINT("%d,", ++cnt);
#endif
    if (memcpy_s(ipv6_addr.addr, sizeof(ipv6_addr.addr), rte_info.tgt.a8, sizeof(rte_info.tgt.a8)) != EOK) {
#ifdef LWIP_DEBUG_OPEN
      (void)hi_at_printf("rtedebug memcpy_s fail"CRLF);
#else
      LWIP_PLATFORM_PRINT("rtedebug memcpy_s fail"CRLF);
#endif
      goto exit;
    }
    tmp = ip6addr_ntoa_r((const ip6_addr_t *)ipv6_addr.addr, ac_ipv6_addr, INET6_ADDRSTRLEN);
    if (tmp == NULL) {
#ifdef LWIP_DEBUG_OPEN
      (void)hi_at_printf("rtedebug ip6addr_ntoa_r is null"CRLF);
#else
      LWIP_PLATFORM_PRINT("rtedebug ip6addr_ntoa_r is null"CRLF);
#endif
      goto exit;
    } else {
#ifdef LWIP_DEBUG_OPEN
      (void)hi_at_printf("%s,", ac_ipv6_addr);
#else
      LWIP_PLATFORM_PRINT("%s,", ac_ipv6_addr);
#endif
    }
    if (memcpy_s(ipv6_addr.addr, sizeof(ipv6_addr.addr), rte_info.nhop.a8, sizeof(rte_info.nhop.a8)) != EOK) {
#ifdef LWIP_DEBUG_OPEN
      (void)hi_at_printf("rtedebug memcpy_s fail"CRLF);
#else
      LWIP_PLATFORM_PRINT("rtedebug memcpy_s fail"CRLF);
#endif
      goto exit;
    }
    tmp = ip6addr_ntoa_r((const ip6_addr_t *)ipv6_addr.addr, ac_ipv6_addr, INET6_ADDRSTRLEN);
    if (tmp == NULL) {
#ifdef LWIP_DEBUG_OPEN
      (void)hi_at_printf("rtedebug ip6addr_ntoa_r is null"CRLF);
#else
      LWIP_PLATFORM_PRINT("rtedebug ip6addr_ntoa_r is null"CRLF);
#endif
      goto exit;
    } else {
#ifdef LWIP_DEBUG_OPEN
      (void)hi_at_printf("%s,", ac_ipv6_addr);
#else
      LWIP_PLATFORM_PRINT("%s,", ac_ipv6_addr);
#endif
    }
#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("%hhu,", rte_info.mnid);
    (void)hi_at_printf("%hu,", rte_info.lt);
#else
    LWIP_PLATFORM_PRINT("%hhu,", rte_info.mnid);
    LWIP_PLATFORM_PRINT("%hu,", rte_info.lt);
#endif

#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("%u,", rte_info.conn_time);
#else
    LWIP_PLATFORM_PRINT("%u,", rte_info.conn_time);
#endif

#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("%hhu"CRLF, rte_info.route_sync);
#else
    LWIP_PLATFORM_PRINT("%hhu"CRLF, rte_info.route_sync);
#endif
  }
  UNLOCK_TCPIP_CORE();
exit:
  return LOS_OK;
}

#if LWIP_NAT64
u32_t
os_shell_nat64_debug(int argc, const char **argv)
{
  s32_t state = 0;
  nat64_entry_t *nate = NULL;
  char buf[IP4ADDR_STRLEN_MAX];
  (void)argc;
  (void)argv;
  if (tcpip_init_finish == 0) {
#ifdef LWIP_DEBUG_OPEN
    (void)hi_at_printf("%s: tcpip_init have not been called"CRLF, __FUNCTION__);
#else
    LWIP_PLATFORM_PRINT("%s: tcpip_init have not been called"CRLF, __FUNCTION__);
#endif
    goto exit;
  }
  LOCK_TCPIP_CORE();

#ifdef LWIP_DEBUG_OPEN
  hi_at_printf("%s, %s, %s, %s, %s, %s, %s, %s, %s, %s"CRLF,
               "Idx", "MAC", "IPv4", "Lifetime", "conTm", "dao_sn", "mnid", "orig_mnid", "state", "nat64_sync");
#else
  LWIP_PLATFORM_PRINT("%s, %s, %s, %s, %s, %s, %s, %s, %s, %s"CRLF,
                      "Idx", "MAC", "IPv4", "Lifetime", "conTm", "dao_sn", "mnid", "orig_mnid", "state", "nat64_sync");
#endif
  while ((nate = nat64_get_next_inuse_entry(&state)) != NULL) {
    (void)ip4addr_ntoa_r(&(nate->ip), buf, IP4ADDR_STRLEN_MAX);
#ifdef LWIP_DEBUG_OPEN
    hi_at_printf("%d, ", state);
    hi_at_printf("%02x%02x%02x%02x%02x%02x, ", 
                  nate->mac.addr[0], nate->mac.addr[1],
                  nate->mac.addr[2], nate->mac.addr[3],
                  nate->mac.addr[4], nate->mac.addr[5]);
    hi_at_printf("%s, ", buf);
    hi_at_printf("%u, ", nate->lifetime);
    hi_at_printf("%u, ", nate->conn_time);
    hi_at_printf("%hhu, ", nate->dao_sn);
    hi_at_printf("%hhu, ", nate->mnid);
    hi_at_printf("%hhu, ", nate->orig_mnid);
    hi_at_printf("%hhu, ", nate->state);
    hi_at_printf("%hhu"CRLF, nate->nat64_sync);
#else
    LWIP_PLATFORM_PRINT("%d, ", state);
    LWIP_PLATFORM_PRINT("%02x%02x%02x%02x%02x%02x, ", 
                        nate->mac.addr[0], nate->mac.addr[1],
                        nate->mac.addr[2], nate->mac.addr[3],
                        nate->mac.addr[4], nate->mac.addr[5]);
    LWIP_PLATFORM_PRINT("%s, ", buf);
    LWIP_PLATFORM_PRINT("%u, ", nate->lifetime);
    LWIP_PLATFORM_PRINT("%u, ", nate->conn_time);
    LWIP_PLATFORM_PRINT("%hhu, ", nate->dao_sn);
    LWIP_PLATFORM_PRINT("%hhu, ", nate->mnid);
    LWIP_PLATFORM_PRINT("%hhu, ", nate->orig_mnid);
    LWIP_PLATFORM_PRINT("%hhu, ", nate->state);
    LWIP_PLATFORM_PRINT("%hhu"CRLF, nate->nat64_sync);
#endif
  }

  UNLOCK_TCPIP_CORE();
exit:
  return LOS_OK;
}
#endif /* LWIP_NAT64 */

#if LWIP_IP6IN4
#define SHELL_IP6IN4_BUF_LEN 40
static err_t
ip6in4_info_print(struct netif *nif)
{
  int index = 0;
  uint32_t state = 0;
  ip6in4_entry_t *entry = NULL;
  char buf[IPADDR_STRLEN_MAX];

  LWIP_PLATFORM_PRINT("Index\tIp6addr\tIp4addr\tLifetime"CRLF);

  index++;
  entry = ip6in4_entry_get_next_inuse(&state);
  while (entry != NULL) {
    LWIP_PLATFORM_PRINT("%d\t", index);
    (void)ip6addr_ntoa_r(&entry->ip6, buf, IPADDR_STRLEN_MAX);
    LWIP_PLATFORM_PRINT("%s\t", buf);
    (void)ip4addr_ntoa_r(&entry->ip4, buf, IPADDR_STRLEN_MAX);
    LWIP_PLATFORM_PRINT("%s\t", buf);
    LWIP_PLATFORM_PRINT("%d"CRLF, entry->lifetime);
    entry = ip6in4_entry_get_next_inuse(&state);
    index++;
  }

  LWIP_UNUSED_ARG(nif);
  return ERR_OK;
}

u32_t
os_shell_ip6in4(int argc, const char **argv)
{
  err_t ret;
  int rc;
  char buf[SHELL_IP6IN4_BUF_LEN] = {0};
  lwip_ip6in4_entry_t local = {0};
  ip6_addr_t local_ip6;

  rc = lwip_ip6in4_entry_get(&local);
  if (rc != 0) {
    LWIP_PLATFORM_PRINT("ip6in4 is not ready."CRLF);
    return LOS_NOK;
  }

  ret = memcpy_s(local_ip6.addr, sizeof(local_ip6.addr), local.ip6, sizeof(local.ip6));
  if (ret != ERR_OK) {
    LWIP_PLATFORM_PRINT("%s: memcpy_s error."CRLF, __FUNCTION__);
    return LOS_NOK;
  }
  ip6_addr_clear_zone(&local_ip6);

  LWIP_PLATFORM_PRINT("Local entry:"CRLF);
  (void)ip6addr_ntoa_r((const ip6_addr_t *)&local_ip6, buf, sizeof(buf));
  LWIP_PLATFORM_PRINT("Ip6addr:%s"CRLF, buf);
  (void)ip4addr_ntoa_r((const ip4_addr_t *)&local.ip4, buf, sizeof(buf));
  LWIP_PLATFORM_PRINT("Ip4addr:%s"CRLF, buf);
  LWIP_PLATFORM_PRINT("Lifetime:%u"CRLF, local.lifetime);

  ret = netifapi_netif_common(NULL, NULL, ip6in4_info_print);
  if (ret != ERR_OK) {
    return LOS_NOK;
  }

  LWIP_UNUSED_ARG(argc);
  LWIP_UNUSED_ARG(argv);
  return LOS_OK;
}
#endif /* LWIP_IP6IN4 */

#endif /* LWIP_RIPPLE && LWIP_ENABLE_BASIC_SHELL_CMD */
