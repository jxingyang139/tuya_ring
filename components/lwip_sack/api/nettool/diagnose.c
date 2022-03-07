/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
 * Description: debug and display shell cmd API implementation
 * Author: none
 * Create: 2020
 */

#include "lwip/nettool/diagnose.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"
#include "lwip/ip6_addr.h"
#include "lwip/priv/nd6_priv.h"
#include "lwip/init.h"
#include "lwip/nettool/utility.h"
#include "los_config.h"
#include "lwip/memp.h"

#if LWIP_ENABLE_BASIC_SHELL_CMD

#ifdef LWIP_DEBUG_INFO
LWIP_STATIC
u32_t
netdebug_memp(int argc, char **argv)
{
  u32_t ret = LOS_OK;
  int type;

  if (argc == 2) {
    if (!strcmp("-i", argv[1])) {
      debug_memp_info();
    } else if (!strcmp("-udp", argv[1])) {
      debug_memp_type_info(MEMP_UDP_PCB);
    } else if (!strcmp("-tcp", argv[1])) {
      debug_memp_type_info(MEMP_TCP_PCB);
    }
#if LWIP_RAW
    else if (!strcmp("-raw", argv[1])) {
      debug_memp_type_info(MEMP_RAW_PCB);
    }
#endif
    else if (!strcmp("-conn", argv[1])) {
      debug_memp_type_info(MEMP_NETCONN);
    } else {
      ret = LOS_NOK;
    }
  } else if (argc == 3) {
    if (!strcmp("-d", argv[1])) {
      type = atoi(argv[2]);
      if (type >= 0) {
        debug_memp_detail(type);
      } else {
        LWIP_PLATFORM_PRINT("Error: type < 0"CRLF);
        ret = LOS_NOK;
      }
    } else {
      ret = LOS_NOK;
    }
  } else {
    ret = LOS_NOK;
  }

  return ret;
}

LWIP_STATIC
u32_t
netdebug_sock(int argc, char **argv)
{
  int idx;
  u32_t ret = LOS_NOK;

  if (argc == 2) {
    if (strcmp("-i", argv[1]) == 0) {
      /* netdebug sock -i */
      for (idx = 0; idx < (int)LWIP_CONFIG_NUM_SOCKETS; idx++) {
        debug_socket_info(idx, 1, 0);
      }
      ret = LOS_OK;
    }
  } else if (argc == 3) {
    if (strcmp("-d", argv[1]) == 0) {
      /* netdebug sock -d <idx> */
      idx = atoi(argv[2]);
      if (idx >= 0) {
        debug_socket_info(idx, 1, 1);
        ret = LOS_OK;
      } else {
        LWIP_PLATFORM_PRINT("Error: idx < 0"CRLF);
      }
    }
  }

  return ret;
}

u32_t
os_shell_netdebug(int argc, const char **argv)
{
  u32_t ret = LOS_NOK;
  if (argv == NULL) {
    return LOS_NOK;
  }
  if (argc < 1) {
    goto usage;
  }
  if (strcmp("memp", argv[0]) == 0) {
    LOCK_TCPIP_CORE();
    ret = netdebug_memp(argc, (char **)argv);
    UNLOCK_TCPIP_CORE();
    if (ret != LOS_OK) {
      goto usage_memp;
    }
  } else if (strcmp("sock", argv[0]) == 0) {
    /* netdebug sock {-i | -d <idx>} */
    LOCK_TCPIP_CORE();
    ret = netdebug_sock(argc, (char **)argv);
    UNLOCK_TCPIP_CORE();
    if (ret != LOS_OK) {
      goto usage_sock;
    }
  } else {
    goto usage;
  }
  return ret;

usage:
  /* Cmd help */
  LWIP_PLATFORM_PRINT(CRLF"Usage:"CRLF);
  LWIP_PLATFORM_PRINT("netdebug memp {-i | -d <type> | -udp | -tcp | -raw |-conn}"CRLF);
  LWIP_PLATFORM_PRINT("netdebug sock {-i | -d <idx>}"CRLF);
  return LOS_NOK;

usage_memp:
  /* netdebug memp help */
  LWIP_PLATFORM_PRINT(CRLF"Usage:"CRLF);
  LWIP_PLATFORM_PRINT("netdebug memp {-i | -d <type> | -udp | -tcp | -raw |-conn}"CRLF);
  return LOS_NOK;

usage_sock:
  /* netdebug sock help */
  LWIP_PLATFORM_PRINT(CRLF"Usage:"CRLF);
  LWIP_PLATFORM_PRINT("netdebug sock {-i | -d <idx>}"CRLF);
  return LOS_NOK;
}
#endif /* LWIP_DEBUG_INFO */

u32_t
os_shell_display_version(int argc, const char **argv)
{
  (void)argc;
  (void)argv;
#ifdef CUSTOM_AT_COMMAND
  (void)hi_at_printf("+Base LwIP %s, %s"CRLF, LWIP_VERSION_STRING, NSTACK_VERSION_STR);
  (void)hi_at_printf("OK"CRLF);
#else
  LWIP_PLATFORM_PRINT("Base LwIP %s, %s"CRLF, LWIP_VERSION_STRING, NSTACK_VERSION_STR);
#endif
  return LOS_OK;
}

#if LWIP_IPV6
static void
display_ipv6_prefix(void)
{
  u8_t i;
  char ac_ipv6_addr[IP6ADDR_STRLEN_MAX + 1] = {0};
  u8_t atleast_one_entry = 0;
  /* Display prefix */
  LWIP_PLATFORM_PRINT("================="CRLF);
  LWIP_PLATFORM_PRINT("|| Prefix List ||"CRLF);
  LWIP_PLATFORM_PRINT("================="CRLF);
  LWIP_PLATFORM_PRINT("%-50s %-16s %-20s"CRLF,
         "Prefix", "netif", "validLifetime");
  LWIP_PLATFORM_PRINT("---------------------------------------------------------------------------------"CRLF);
  /* Display neighbour Cache Entry */
  for (i = 0; i < LWIP_ND6_NUM_PREFIXES; i++) {
    if (prefix_list[i].netif != NULL && prefix_list[i].invalidation_timer > 0) {
      atleast_one_entry = 1;
      (void)ip6addr_ntoa_r((const ip6_addr_t *)(&prefix_list[i].prefix), (ac_ipv6_addr), INET6_ADDRSTRLEN);
      LWIP_PLATFORM_PRINT("%-50s ", ac_ipv6_addr);
      LWIP_PLATFORM_PRINT("%s%-13hhu ", prefix_list[i].netif->name, prefix_list[i].netif->num);
      LWIP_PLATFORM_PRINT("%-20u"CRLF, prefix_list[i].invalidation_timer);
    }
  }
  if (atleast_one_entry == 0) {
    LWIP_PLATFORM_PRINT("**** NO VALID PREFIXES FOUND CONFIGURED ****"CRLF);
  }
  LWIP_PLATFORM_PRINT("---------------------------------------------------------------------------------"CRLF);
}

static void
display_ipv6_neighbor_cache_entry(void)
{
  u8_t i;
  u8_t atleast_one_entry = 0;
  char ac_ipv6_addr[IP6ADDR_STRLEN_MAX + 1] = {0};
  char aclladdr[20] = {0};
  const char *ac_states[] = {"NO_ENTRY", "INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE"};

  LWIP_PLATFORM_PRINT(CRLF CRLF);
  LWIP_PLATFORM_PRINT("============================"CRLF);
  LWIP_PLATFORM_PRINT("|| Neighbor Cache Entries ||"CRLF);
  LWIP_PLATFORM_PRINT("============================"CRLF);
  LWIP_PLATFORM_PRINT("%-50s %-25s %-16s %-15s %-10s"CRLF,
         "Neighbor", "MAC", "netif", "state", "IsRouter");
  LWIP_PLATFORM_PRINT("------------------------------------------------------------"
         "------------------------------------------------------------"CRLF);

  /* Display neighbour Cache Entry */
  for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++) {
    if (neighbor_cache[i].state != ND6_NO_ENTRY) {
      atleast_one_entry = 1;
      (void)ip6addr_ntoa_r((const ip6_addr_t *)(&neighbor_cache[i].next_hop_address), (ac_ipv6_addr),
                           INET6_ADDRSTRLEN);
      LWIP_PLATFORM_PRINT("%-50s ", ac_ipv6_addr);

      if (snprintf_s(aclladdr, sizeof(aclladdr), sizeof(aclladdr) - 1, "%02X:%02X:%02X:%02X:%02X:%02X",
                     neighbor_cache[i].lladdr[0], neighbor_cache[i].lladdr[1], neighbor_cache[i].lladdr[2],
                     neighbor_cache[i].lladdr[3], neighbor_cache[i].lladdr[4], neighbor_cache[i].lladdr[5]) < 0) {
        return;
      }
      LWIP_PLATFORM_PRINT("%-25s ", aclladdr);
      if (neighbor_cache[i].netif != NULL) {
        LWIP_PLATFORM_PRINT("%s%-13hhu ", neighbor_cache[i].netif->name, neighbor_cache[i].netif->num);
      } else {
        LWIP_PLATFORM_PRINT("%-17s ", "NULL");
      }
      LWIP_PLATFORM_PRINT("%-15s ", ac_states[neighbor_cache[i].state]);
      LWIP_PLATFORM_PRINT("%-10s"CRLF, neighbor_cache[i].isrouter ? "Yes" : "No");
    }
  }
  if (atleast_one_entry == 0) {
    LWIP_PLATFORM_PRINT("**** NO NEIGHBOURS FOUND ****\n");
  }
  LWIP_PLATFORM_PRINT("------------------------------------------------------------"
         "------------------------------------------------------------"CRLF);
}

static void
display_ipv6_des_cache_entry(void)
{
  u8_t i;
  u8_t atleast_one_entry = 0;
  char ac_ipv6_addr[IP6ADDR_STRLEN_MAX + 1] = {0};
  LWIP_PLATFORM_PRINT(CRLF CRLF);
  LWIP_PLATFORM_PRINT("==============================="CRLF);
  LWIP_PLATFORM_PRINT("|| Destination Cache Entries ||"CRLF);
  LWIP_PLATFORM_PRINT("==============================="CRLF);
  LWIP_PLATFORM_PRINT("%-50s %-50s %-10s %-10s"CRLF,
         "Destination", "NextHop", "PMTU", "age");
  LWIP_PLATFORM_PRINT("------------------------------------------------------------"
         "------------------------------------------------------------"CRLF);
  /* Display neighbour Cache Entry */
  for (i = 0; i < LWIP_ND6_NUM_DESTINATIONS; i++) {
    if (!ip6_addr_isany(&(destination_cache[i].destination_addr))) {
      atleast_one_entry = 1;
      (void)ip6addr_ntoa_r((const ip6_addr_t *)(&destination_cache[i].destination_addr), (ac_ipv6_addr),
                           INET6_ADDRSTRLEN);
      LWIP_PLATFORM_PRINT("%-50s ", ac_ipv6_addr);
      (void)ip6addr_ntoa_r((const ip6_addr_t *)(&destination_cache[i].next_hop_addr), (ac_ipv6_addr),
                           INET6_ADDRSTRLEN);
      LWIP_PLATFORM_PRINT("%-50s ", ac_ipv6_addr);
      LWIP_PLATFORM_PRINT("%-10hu ", destination_cache[i].pmtu);
      LWIP_PLATFORM_PRINT("%-10u"CRLF, destination_cache[i].age);
    }
  }
  if (atleast_one_entry == 0) {
    LWIP_PLATFORM_PRINT("**** NO DESTINATION CACHE FOUND ****"CRLF);
  }
  LWIP_PLATFORM_PRINT("------------------------------------------------------------"
         "------------------------------------------------------------"CRLF);
}

static void
display_default_router_entry(void)
{
  u8_t i;
  u8_t atleast_one_entry = 0;
  char ac_ipv6_addr[IP6ADDR_STRLEN_MAX + 1] = {0};
  LWIP_PLATFORM_PRINT(CRLF CRLF);
  LWIP_PLATFORM_PRINT("============================"CRLF);
  LWIP_PLATFORM_PRINT("|| Default Router Entries ||"CRLF);
  LWIP_PLATFORM_PRINT("============================"CRLF);
  LWIP_PLATFORM_PRINT("%-50s %-20s %-10s"CRLF,
         "Router", "invalidation_timer", "flags");
  LWIP_PLATFORM_PRINT("-----------------------------------------------------------------------------"CRLF);
  /* Display Default Router Cache Entry */
  for (i = 0; i < LWIP_ND6_NUM_ROUTERS; i++) {
    if (default_router_list[i].neighbor_entry) {
      atleast_one_entry = 1;
      (void)ip6addr_ntoa_r((const ip6_addr_t *)(&(default_router_list[i].neighbor_entry)->next_hop_address),
                           (ac_ipv6_addr), INET6_ADDRSTRLEN);
      LWIP_PLATFORM_PRINT("%-50s ", ac_ipv6_addr);
      LWIP_PLATFORM_PRINT("%-20u ", default_router_list[i].invalidation_timer);
      LWIP_PLATFORM_PRINT("%-10hhu"CRLF, default_router_list[i].flags);
    }
  }
  if (atleast_one_entry == 0) {
    LWIP_PLATFORM_PRINT("**** NO DEFAULT ROUTERS FOUND ****"CRLF);
  }
  LWIP_PLATFORM_PRINT("-----------------------------------------------------------------------------"CRLF);
}

u32_t
os_shell_ipdebug(int argc, const char **argv)
{
  LWIP_UNUSED_ARG(argc);
  LWIP_UNUSED_ARG(argv);

  if (tcpip_init_finish == 0) {
    LWIP_PLATFORM_PRINT("%s: tcpip_init have not been called"CRLF, __FUNCTION__);
    goto exit;
  }

  display_ipv6_prefix();
  display_ipv6_neighbor_cache_entry();
  display_ipv6_des_cache_entry();
  display_default_router_entry();

exit:
  return LOS_OK;
}

#endif /* LWIP_IPV6 */

#endif /* LWIP_ENABLE_BASIC_SHELL_CMD */
