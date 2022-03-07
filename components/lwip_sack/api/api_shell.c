/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: shell cmds APIs implementation
 * Author: none
 * Create: 2020
 */

#include "lwip/opt.h"

#if LWIP_ENABLE_LOS_SHELL_CMD
#include "los_config.h"
#include "lwip/api_shell.h"

#ifdef LOSCFG_SHELL
#include "shcmd.h"
#include "shell.h"
#endif

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(ifconfig_shellcmd, CMD_TYPE_EX, "ifconfig", XARGS, (CmdCallBackFunc)lwip_ifconfig);
#endif /* LOSCFG_SHELL */

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(arp_shellcmd, CMD_TYPE_EX, "arp", 1, (CmdCallBackFunc)lwip_arp);
#endif /* LOSCFG_SHELL */

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(ping_shellcmd, CMD_TYPE_EX, "ping", XARGS, (CmdCallBackFunc)os_shell_ping);
#endif /* LOSCFG_SHELL */

#if LWIP_IPV6
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(ping6_shellcmd, CMD_TYPE_EX, "ping6", XARGS, (CmdCallBackFunc)os_shell_ping6);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_IPV6 */

#if  LWIP_SNTP
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(ntpdate_shellcmd, CMD_TYPE_EX, "ntpdate", XARGS, (CmdCallBackFunc)os_shell_ntpdate);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_SNTP*/

#ifdef LOSCFG_NET_LWIP_SACK_TFTP
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(tftp_shellcmd, CMD_TYPE_EX, "tftp", XARGS, (CmdCallBackFunc)os_shell_tftp);
#endif /* LOSCFG_SHELL */
#endif /* LOSCFG_NET_LWIP_SACK_TFTP */

#if LWIP_DNS
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(dns_shellcmd, CMD_TYPE_EX, "dns", XARGS, (CmdCallBackFunc)os_shell_dns);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_DNS */

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(netstat_shellcmd, CMD_TYPE_EX, "netstat", XARGS, (CmdCallBackFunc)os_shell_netstat);
#endif /* LOSCFG_SHELL */

#ifdef LWIP_DEBUG_TCPSERVER
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(tcpserver_shellcmd, CMD_TYPE_EX, "tcpserver", XARGS, (CmdCallBackFunc)os_tcpserver);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_DEBUG_TCPSERVER */

#ifdef LWIP_DEBUG_UDPSERVER
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(udpserver_shellcmd, CMD_TYPE_EX, "udpserver", XARGS, (CmdCallBackFunc)udpserver);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_DEBUG_UDPSERVER */

#if defined(LOSCFG_SHELL) && defined(LWIP_DEBUG_INFO)
SHELLCMD_ENTRY(netdebug_shellcmd, CMD_TYPE_EX, "netdebug", XARGS, (CmdCallBackFunc)os_shell_netdebug);
#endif /* LOSCFG_SHELL && LWIP_DEBUG_INFO */

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(ipdebug_shellcmd, CMD_TYPE_EX, "ipdebug", XARGS, (CmdCallBackFunc)os_shell_ipdebug);
#endif

#ifdef LWIP_TESTBED
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(reboot_shellcmd, CMD_TYPE_EX, "reboot", XARGS, (CmdCallBackFunc)os_shell_reboot);
#endif /* LOSCFG_SHELL */
#endif

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(netif_shellcmd, CMD_TYPE_EX, "netif_default", XARGS, (CmdCallBackFunc)os_shell_netif);
#endif /* LOSCFG_SHELL */

#if LWIP_DHCPS
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(dhcps_shellcmd, CMD_TYPE_EX, "dhcps", XARGS, (CmdCallBackFunc)os_shell_dhcps);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_DHCPS */

#if LWIP_RIPPLE
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(rpl_shellcmd, CMD_TYPE_EX, "rpl", XARGS, (CmdCallBackFunc)os_shell_rpl);
#endif /* LOSCFG_SHELL */

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(l2test_shellcmd, CMD_TYPE_EX, "l2test", XARGS, (CmdCallBackFunc)os_shell_l2test);
#endif /* LOSCFG_SHELL */

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(rte_shellcmd, CMD_TYPE_EX, "rtedebug", XARGS, (CmdCallBackFunc)os_rte_debug);
#endif /* LOSCFG_SHELL */

#if LWIP_NAT64
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(nate_shellcmd, CMD_TYPE_EX, "natedebug", XARGS, (CmdCallBackFunc)os_shell_nat64_debug);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_NAT64 */
#if LWIP_IP6IN4
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(ip6in4_shellcmd, CMD_TYPE_EX, "ip6in4", XARGS, (CmdCallBackFunc)os_shell_ip6in4);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_IP6IN4 */
#endif /* LWIP_RIPPLE */

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(lwip_version_shellcmd, CMD_TYPE_EX, "lwip_version", XARGS, (CmdCallBackFunc)os_shell_display_version);
#endif /* LOSCFG_SHELL */

#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(mcast6_shellcmd, CMD_TYPE_EX, "mcast6", XARGS, (CmdCallBackFunc)os_shell_mcast6);
#endif /* LOSCFG_SHELL */

#if LWIP_DHCP
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(dhcp_shellcmd, CMD_TYPE_EX, "dhcp", XARGS, (CmdCallBackFunc)os_shell_dhcp);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_DHCP */

#if (LWIP_IPV6 && (LWIP_IPV6_MLD || LWIP_IPV6_MLD_QUERIER))
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(mld6_shellcmd, CMD_TYPE_EX, "mld6", XARGS, (CmdCallBackFunc)os_shell_mld6);
#endif /* LOSCFG_SHELL */
#endif /* (LWIP_IPV6 && (LWIP_IPV6_MLD || LWIP_IPV6_MLD_QUERIER)) */

#if LWIP_IPV4 && LWIP_IGMP
#ifdef LOSCFG_SHELL
SHELLCMD_ENTRY(igmp_shellcmd, CMD_TYPE_EX, "igmp", XARGS, (CmdCallBackFunc)os_shell_igmp);
#endif /* LOSCFG_SHELL */
#endif /* LWIP_IPV4 && LWIP_IGMP */

#endif //LWIP_ENABLE_LOS_SHELL_CMD
