/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
 * Description: ARP shell cmd API implementation
 * Author: none
 * Create: 2020
 */

#include "lwip/priv/nd6_priv.h"
#include "lwip/sockets.h"
#include "lwip/inet_chksum.h"
#include "lwip/raw.h"
#include "lwip/priv/api_msg.h"
#include "lwip/icmp.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/ip.h"
#include "lwip/dhcp.h"
#include "lwip/prot/dhcp.h"
#include "lwip/nettool/arp.h"
#include "lwip/etharp.h"
#include "lwip/tcpip.h"
#include "lwip/nettool/utility.h"
#include "los_config.h"

#if LWIP_ENABLE_BASIC_SHELL_CMD

/* add arp entry to arp cache */
#define ARP_OPTION_ADD      1
/* delete arp entry to arp cache */
#define ARP_OPTION_DEL      2
/* print all arp entry in arp cache */
#define ARP_OPTION_SHOW     3

struct arp_option {
  /* see the ARP_OPTION_ above */
  int             option;
  /* descriptive abbreviation of network interface */
  char            iface[NETIF_NAMESIZE];
  /* ip addr */
  unsigned int    ipaddr;
  /* hw addr */
  unsigned char ethaddr[ETH_HWADDR_LEN];
  /* when using telnet, printf to the telnet socket will result in system  */
  /* deadlock.so don't do it.cahe the data to prinf to a buf, and when     */
  /* callback returns, then printf the data out to the telnet socket       */
  sys_sem_t       cb_completed;
  char            cb_print_buf[PRINT_BUF_LEN];
  int             print_buf_len;
};

#ifndef LWIP_TESTBED
LWIP_STATIC
#endif
void
lwip_arp_show_internal(struct netif *netif, char *printf_buf, unsigned int buf_len)
{
  u8_t state, i, num;
  int ret;
  char *name = NULL;
  char *tmp = printf_buf;
  char buf[IP4ADDR_STRLEN_MAX];
  if (buf_len <= 1) {
    return;
  }
  ret = snprintf_s(tmp, buf_len, (buf_len - 1), "%-24s%-24s%-12s%-12s"CRLF, "Address", "HWaddress", "Iface", "Type");
  if ((ret <= 0) || ((unsigned int)ret >= buf_len)) {
    return;
  }
  tmp += ret;
  buf_len -= (unsigned int)ret;

  for (i = 0; i < ARP_TABLE_SIZE; ++i) {
    state = arp_table[i].state;
    if ((state >= ETHARP_STATE_STABLE) && (arp_table[i].netif != NULL)) {
      name = arp_table[i].netif->name;
      num = arp_table[i].netif->num;
      if ((netif != NULL) && ((strncmp(name, netif->name, NETIF_NAMESIZE) != 0) || (num != netif->num))) {
        continue;
      }

      (void)ip4addr_ntoa_r(&arp_table[i].ipaddr, buf, IP4ADDR_STRLEN_MAX);
      ret = snprintf_s(tmp, buf_len, (buf_len - 1),
                       "%-24s%02X:%02X:%02X:%02X:%02X:%02X       %s%u        %s"CRLF,
                       buf,
                       arp_table[i].ethaddr.addr[0], arp_table[i].ethaddr.addr[1],
                       arp_table[i].ethaddr.addr[2], arp_table[i].ethaddr.addr[3],
                       arp_table[i].ethaddr.addr[4], arp_table[i].ethaddr.addr[5],
                       name, num,
#if ETHARP_SUPPORT_STATIC_ENTRIES
                       ((state == ETHARP_STATE_STATIC) ? "static" : "dynamic")
#else
                       "dynamic"
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */
                      );
      if ((ret <= 0) || ((unsigned int)ret >= buf_len)) {
        return;
      }
      tmp += ret;
      buf_len -= (unsigned int)ret;
    }
  }
}

static int
lwip_arp_add_internal(struct netif *netif, const struct arp_option *arp_cmd)
{
  err_t ret = 0;
  struct eth_addr ethaddr;
  ip4_addr_t ipaddr;
  ipaddr.addr = arp_cmd->ipaddr;
  (void)memcpy_s(ethaddr.addr, sizeof(ethaddr.addr), arp_cmd->ethaddr, sizeof(ethaddr.addr));
  if (netif != NULL) {
    /* If  in the same subnet */
    if (ip4_addr_netcmp(&ipaddr, ip_2_ip4(&(netif->ip_addr)), ip_2_ip4(&(netif->netmask)))) {
      ret = etharp_update_arp_entry(netif, &ipaddr, &ethaddr, ETHARP_FLAG_TRY_HARD);
    } else {
      return ERR_NETUNREACH;
    }
  } else {
    for (netif = netif_list; netif != NULL; netif = netif->next) {
      /* If  in the same subnet */
      if (ip4_addr_netcmp(&ipaddr, ip_2_ip4(&(netif->ip_addr)), ip_2_ip4(&(netif->netmask)))) {
        ret = etharp_update_arp_entry(netif, &ipaddr, &ethaddr, ETHARP_FLAG_TRY_HARD);
        if (ret == ERR_OK) {
          /* only can add success one time */
          break;
        }
      }
      /* The netif is last netif and cannot add this arp entry on any netif */
      if (netif->next == NULL) {
        return ERR_NETUNREACH;
      }
    }
  }
  return ret;
}

static int
lwip_arp_del_internal(struct netif *netif, const struct arp_option *arp_cmd)
{
  err_t ret = 0;
  struct eth_addr ethaddr;
  ip4_addr_t ipaddr;
  ipaddr.addr = arp_cmd->ipaddr;
  (void)memcpy_s(ethaddr.addr, sizeof(ethaddr.addr), arp_cmd->ethaddr, sizeof(ethaddr.addr));
  if (netif != NULL) {
    ret = etharp_delete_arp_entry(netif, &ipaddr);
  } else {
    for (netif = netif_list; netif != NULL; netif = netif->next) {
      ret = etharp_delete_arp_entry(netif, &ipaddr);
      if (ret == ERR_OK) {
        /* only can del success one time */
        break;
      }
    }
  }
  return ret;
}

#ifndef LWIP_TESTBED
LWIP_STATIC
#endif
void
lwip_arp_internal(void *arg)
{
#if LWIP_IPV4
  struct arp_option *arp_cmd = (struct arp_option *)arg;
  struct netif *netif = NULL;
  err_t ret = 0;
  int type = 0;

  if (arp_cmd->iface[0] == 'd' && arp_cmd->iface[1] == 'e') {
    netif = NULL;
  } else {
    /* find the specified netif by it's name */
    netif = netif_find(arp_cmd->iface);
    if (netif == NULL) {
      (void)snprintf_s(arp_cmd->cb_print_buf, PRINT_BUF_LEN, (PRINT_BUF_LEN - 1), "No such device"CRLF);
      goto out;
    }
  }

  type = arp_cmd->option;
  switch (type) {
    case ARP_OPTION_SHOW:
      lwip_arp_show_internal(netif, arp_cmd->cb_print_buf, PRINT_BUF_LEN);
      break;

    case ARP_OPTION_ADD:
      ret = lwip_arp_add_internal(netif, arp_cmd);
      break;

    case ARP_OPTION_DEL:
      ret = lwip_arp_del_internal(netif, arp_cmd);
      break;

    default:
      (void)snprintf_s(arp_cmd->cb_print_buf, PRINT_BUF_LEN, (PRINT_BUF_LEN - 1), "Error"CRLF);
      goto out;
  }

out:
  if (type == ARP_OPTION_ADD || type == ARP_OPTION_DEL) {
    if (ret == ERR_NETUNREACH) {
      (void)snprintf_s(arp_cmd->cb_print_buf, PRINT_BUF_LEN, (PRINT_BUF_LEN - 1), "Network is unreachable"CRLF);
    } else if (ret == ERR_MEM) {
      (void)snprintf_s(arp_cmd->cb_print_buf, PRINT_BUF_LEN, (PRINT_BUF_LEN - 1), "Out of memory error"CRLF);
    } else if (ret == ERR_ARG) {
      (void)snprintf_s(arp_cmd->cb_print_buf, PRINT_BUF_LEN, (PRINT_BUF_LEN - 1), "Illegal argument"CRLF);
    } else {
      (void)snprintf_s(arp_cmd->cb_print_buf, PRINT_BUF_LEN, (PRINT_BUF_LEN - 1), "Successed"CRLF);
    }
  }
#endif

  sys_sem_signal(&arp_cmd->cb_completed);
}

LWIP_STATIC void
lwip_arp_usage(const char *cmd)
{
  LWIP_PLATFORM_PRINT("Usage:"\
         CRLF"%s"
         CRLF"%s [-i IF] -s IPADDR HWADDR"\
         CRLF"%s [-i IF] -d IPADDR"CRLF,
         cmd, cmd, cmd);
}

static void
arp_cmd_init(struct arp_option *arp_cmd_p)
{
  (void)memset_s(arp_cmd_p, sizeof(struct arp_option), 0, sizeof(struct arp_option));
  arp_cmd_p->iface[0] = 'd';
  arp_cmd_p->iface[1] = 'e';
  arp_cmd_p->iface[2] = '0';
  arp_cmd_p->option = ARP_OPTION_SHOW;
  arp_cmd_p->print_buf_len = 0;
}

static u32_t
arp_parse_get(const char *ifname, const int iface_len, struct arp_option *arp_cmd_p)
{
  if (iface_len >= NETIF_NAMESIZE) {
    LWIP_PLATFORM_PRINT("Iface name is big "CRLF);
    return LOS_NOK;
  }
  if (strncmp(ifname, "lo", (sizeof("lo") - 1)) == 0) {
    LWIP_PLATFORM_PRINT("Illegal operation\n");
    return LOS_NOK;
  }
  (void)strncpy_s(arp_cmd_p->iface, NETIF_NAMESIZE, ifname, iface_len);
  arp_cmd_p->iface[iface_len] = '\0';
  return LOS_OK;
}

static u32_t
arp_parse_add(const unsigned int ipaddr, const char *macaddr, struct arp_option *arp_cmd_p)
{
  /* arp add */
  char *digit = NULL;
  u32_t macaddrlen = strlen(macaddr) + 1;
  char tmp_str[MAX_MACADDR_STRING_LENGTH];
  char *tmp_str1 = NULL;
  char *saveptr1 = NULL;
  char *temp = NULL;
  int j;

  arp_cmd_p->option = ARP_OPTION_ADD;
  arp_cmd_p->ipaddr = ipaddr;

  if (arp_cmd_p->ipaddr == IPADDR_NONE) {
    LWIP_PLATFORM_PRINT("IP address is not correct!"CRLF);
    return LOS_NOK;
  }

  /* cannot add an arp entry of 127.*.*.* */
  if ((arp_cmd_p->ipaddr & (u32_t)0x0000007fUL) == (u32_t)0x0000007fUL) {
    LWIP_PLATFORM_PRINT("IP address is not correct!"CRLF);
    return LOS_NOK;
  }

  if (macaddrlen != MAX_MACADDR_STRING_LENGTH) {
    LWIP_PLATFORM_PRINT("Wrong MAC address length"CRLF);
    return LOS_NOK;
  }

  if (strncpy_s(tmp_str, MAX_MACADDR_STRING_LENGTH, (const char *)macaddr, macaddrlen - 1) != EOK) {
    LWIP_PLATFORM_PRINT("Wrong MAC address"CRLF);
    return LOS_NOK;
  }
  /* 6 : the : index in mac address */
  for (j = 0, tmp_str1 = tmp_str; j < 6; j++, tmp_str1 = NULL) {
    digit = strtok_r(tmp_str1, ":", &saveptr1);
    if ((digit == NULL) || (strlen(digit) > 2)) { /* 2 : Addresses are classify in two hexadecimal */
      LWIP_PLATFORM_PRINT("MAC address is not correct"CRLF);
      return LOS_NOK;
    }

    for (temp = digit; *temp != '\0'; temp++) {
      if (!isxdigit(*temp)) {
        LWIP_PLATFORM_PRINT("MAC address is not correct"CRLF);
        return LOS_NOK;
      }
    }

    convert_string_to_hex(digit, &arp_cmd_p->ethaddr[j]);
  }
  return LOS_OK;
}

static u32_t
arp_cmd_exec_callback(struct arp_option *arp_cmd_p)
{
  err_t ret;
  if (sys_sem_new(&arp_cmd_p->cb_completed, 0) != ERR_OK) {
    LWIP_PLATFORM_PRINT("%s: sys_sem_new fail\n", __FUNCTION__);
    return LOS_NOK;
  }

  if ((ret = tcpip_callback(lwip_arp_internal, arp_cmd_p)) != ERR_OK) {
    LWIP_PLATFORM_PRINT("%s : tcpip_callback failed in line %d : errnu %d", __FUNCTION__, __LINE__, ret);
    sys_sem_free(&arp_cmd_p->cb_completed);
    return LOS_NOK;
  }
  (void)sys_arch_sem_wait(&arp_cmd_p->cb_completed, 0);
  sys_sem_free(&arp_cmd_p->cb_completed);
  arp_cmd_p->cb_print_buf[PRINT_BUF_LEN - 1] = '\0';
  LWIP_PLATFORM_PRINT("%s", arp_cmd_p->cb_print_buf);
  return LOS_OK;
}

u32_t
lwip_arp(int argc, const char **argv)
{
  int i = 0;
  u32_t ret;
  char ifname[NETIF_NAMESIZE] = "";
  u16_t inf_len;
  unsigned int ipaddr;
  char macaddr[MACADDR_BUF_LEN] = "";

  if (tcpip_init_finish == 0) {
    LWIP_PLATFORM_PRINT("%s: tcpip_init have not been called"CRLF, __FUNCTION__);
    return LOS_NOK;
  }

  struct arp_option *arp_cmd = mem_malloc(sizeof(struct arp_option));
  if (arp_cmd == NULL) {
    LWIP_PLATFORM_PRINT("Not enough mem!"CRLF);
    return LOS_NOK;
  }

  arp_cmd_init(arp_cmd);

  while (argc > 0) {
    if (strcmp("-i", argv[i]) == 0 && (argc > 1)) {
      inf_len = strlen(argv[i + 1]);
      (void)strncpy_s(ifname, NETIF_NAMESIZE, argv[i + 1], inf_len);
      ret = arp_parse_get(ifname, inf_len, arp_cmd);
      if (ret == LOS_NOK) {
        goto arp_error;
      }

      i += 2;
      argc -= 2;
    } else if (strcmp("-d", argv[i]) == 0 && (argc > 1)) {
      /* arp delete */
      arp_cmd->option = ARP_OPTION_DEL;
      arp_cmd->ipaddr = inet_addr(argv[i + 1]);

      if (arp_cmd->ipaddr == IPADDR_NONE) {
        LWIP_PLATFORM_PRINT("IP address is not correct!"CRLF);
        goto arp_error;
      }

      i += 2;
      argc -= 2;
    } else if (strcmp("-s", argv[i]) == 0 && (argc > 2)) {
      ipaddr = inet_addr(argv[i + 1]);
      (void)strncpy_s((char *)macaddr, MACADDR_BUF_LEN, argv[i + 2], strlen(argv[i + 2]));
      ret = arp_parse_add(ipaddr, macaddr, arp_cmd);
      if (ret == LOS_NOK) {
        goto arp_error;
      }

      i += 3;
      argc -= 3;
    } else {
      goto arp_error;
    }
  }

  ret = arp_cmd_exec_callback(arp_cmd);
  mem_free(arp_cmd);
  return ret;

arp_error:
  mem_free(arp_cmd);
  lwip_arp_usage("arp");
  return LOS_NOK;
}

#endif /* LWIP_ENABLE_BASIC_SHELL_CMD */
