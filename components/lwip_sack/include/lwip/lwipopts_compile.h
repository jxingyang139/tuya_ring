/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * Create: 2018-01-30
 */

#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#ifdef __cplusplus
extern "C" {
#endif

#define LWIP_LITEOS_COMPAT                      0
#define LWIP_LINUX_COMPAT                       1
#define LWIP_MPU_COMPATIBLE                     0
#define LWIP_TCPIP_CORE_LOCKING                 1
#define LWIP_TCPIP_CORE_LOCKING_INPUT           1
#define SYS_LIGHTWEIGHT_PROT                    1
#define MEM_LIBC_MALLOC                         1
#define MEMP_MEM_MALLOC                         1
#define MEMP_MEM_INIT                           1
#define MEMP_OVERFLOW_CHECK                     1
#define MEMP_SANITY_CHECK                       1
#define MEM_OVERFLOW_CHECK                      1
#define MEM_SANITY_CHECK                        1
#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT  1
#define LWIP_ARP                                1
#define ARP_QUEUEING                            1
#define ETHARP_SUPPORT_VLAN                     1
#define LWIP_ETHERNET                           1
#define ETHARP_SUPPORT_STATIC_ENTRIES           1
#define LWIP_IPV4                               1
#define IP_FORWARD                              1
#define IP_REASSEMBLY                           1
#define IP_FRAG                                 1
#define IP_OPTIONS_ALLOWED                      1
#define IP_SOF_BROADCAST                        1
#define IP_SOF_BROADCAST_RECV                   1
#define LWIP_DNS64                              1
#define IP_FORWARD_ALLOW_TX_ON_RX_NETIF         1
#define LWIP_ICMP                               1
#define LWIP_BROADCAST_PING                     1
#define LWIP_MULTICAST_PING                     1
#define LWIP_RAW                                1
#define LWIP_DHCP                               1
#define LWIP_DHCPS                              1
#define LWIP_DHCP_BOOTP_FILE                    1
#define LWIP_DHCP_GET_NTP_SRV                   1
#define LWIP_AUTOIP                             1
#define LWIP_DHCP_AUTOIP_COOP                   1
#define LWIP_IGMP                               1
#define LWIP_DNS                                1
#define DNS_LOCAL_HOSTLIST                      1
#define DNS_LOCAL_HOSTLIST_IS_DYNAMIC           1
#define LWIP_DNS_SUPPORT_MDNS_QUERIES           1
#define LWIP_UDP                                1
#define LWIP_UDPLITE                            1
#define LWIP_NETBUF_RECVINFO                    1
#define LWIP_TCP                                1
#define TCP_QUEUE_OOSEQ                         1
#define LWIP_SACK                               1
#define TCP_CALCULATE_EFF_SEND_MSS              1
#define TCP_LISTEN_BACKLOG                      1
#define LWIP_TCP_TIMESTAMPS                     1
#define LWIP_NETIF_HOSTNAME                     1
#define LWIP_NETIF_API                          1
#define LWIP_NETIF_STATUS_CALLBACK              1
#define LWIP_NETIF_EXT_STATUS_CALLBACK          1
#define LWIP_NETIF_LINK_CALLBACK                1
#define LWIP_NETIF_REMOVE_CALLBACK              1
#define LWIP_NETIF_HWADDRHINT                   1
#define LWIP_NETIF_TX_SINGLE_PBUF               1
#define LWIP_LOOPIF_MULTICAST                   1
#define LWIP_NETIF_LOOPBACK                     1
#define LWIP_NETCONN                            1
#define LWIP_TCPIP_TIMEOUT                      1
#define LWIP_NETCONN_FULLDUPLEX                 1
#define LWIP_SOCKET                             1
#define LWIP_TCP_KEEPALIVE                      1
#define LWIP_SO_SNDTIMEO                        1
#define LWIP_SO_RCVTIMEO                        1
#define LWIP_SO_SNDRCVTIMEO_NONSTANDARD         1
#define LWIP_SO_RCVBUF                          1
#define LWIP_SO_LINGER                          1
#define SO_REUSE                                1
#define SO_REUSE_RXTOALL                        1
#define LWIP_FIONREAD_LINUXMODE                 1
#define LWIP_SOCKET_SELECT                      1
#define LWIP_SOCKET_POLL                        1
#define LWIP_STATS                              1
#define LWIP_STATS_DISPLAY                      1
#define LINK_STATS                              1
#define ETHARP_STATS                            1
#define IP_STATS                                1
#define IPFRAG_STATS                            1
#define ICMP_STATS                              1
#define IGMP_STATS                              1
#define UDP_STATS                               1
#define TCP_STATS                               1
#define SYS_STATS                               1
#define IP6_STATS                               1
#define ICMP6_STATS                             1
#define IP6_FRAG_STATS                          1
#define MLD6_STATS                              1
#define ND6_STATS                               1
#define MIB2_STATS                              1
#define LWIP_IPV6                               1
#define LWIP_IPV6_SCOPES                        1
#define LWIP_IPV6_SCOPES_DEBUG                  1
#define LWIP_IPV6_FORWARD                       1
#define LWIP_IPV6_FRAG                          1
#define LWIP_IPV6_REASS                         1
#define LWIP_IPV6_SEND_ROUTER_SOLICIT           1
#define LWIP_IPV6_AUTOCONFIG                    1
#define LWIP_ICMP6                              1
#define LWIP_IPV6_MLD                           1
#define LWIP_ND6_QUEUEING                       1
#define LWIP_ND6_ALLOW_RA_UPDATES               1
#define LWIP_ND6_TCP_REACHABILITY_HINTS         1
#define LWIP_IPV6_DHCP6                         1
#define LWIP_IPV6_DHCP6_STATEFUL                1
#define LWIP_IPV6_DHCP6_STATELESS               1
#define LWIP_DHCP6_GET_NTP_SRV                  1
#define LWIP_TFTP                               1
#define LWIP_SNTP                               1
#define PF_PKT_SUPPORT                          1
#define LWIP_NETIF_ETHTOOL                      1
#define LWIP_NETIF_PROMISC                      1
#define LWIP_SO_SNDBUF                          1
#define LWIP_SO_DONTROUTE                       1
#define LWIP_TCP_INFO                           1
#define LWIP_ALLOW_SOCKET_CONFIG                1
#define LWIP_DHCP_VENDOR_CLASS_IDENTIFIER       1
#define LWIP_TCP_MAXSEG                         1
#define DRIVER_STATUS_CHECK                     1
#define LWIP_EXT_POLL_SUPPORT                   0
#define DLWIP_CHKSUM_ALGORITHM                  1
#define LWIP_USE_L2_METRICS                     1
#define LWIP_DHCP_SUBSTITUTE                    1
#define LWIP_MPL                                1
#define LWIP_MPL_IPV4                           1
#define LWIP_RIPPLE                             1
#define LWIP_API_MESH                           1
#define LWIP_NAT64                              1
#define LWIP_IP6IN4                             1
#define LWIP_NAT64_IP6IN4                       1
#define WITH_LWIP                               1
#define LWIP_IPV6_MLD_QUERIER                   1
#define LWIP_ENABLE_BASIC_SHELL_CMD             1
#define LWIP_ND6_ROUTER                         1
#define LWIP_MPL_IPV4_BCAST                     1
#define PBUF_RX_RATIONING                       1
#define LWIP_RA_PREFIX_DYNAMIC                  1
#define LWIP_DHCP_LIMIT_CONCURRENT_REQUESTS     1
#define LWIP_IGMP_REPORT_TIMES                  5
#define LWIP_ARP_GRATUITOUS_REXMIT              1
#define LWIP_DHCP_SUBSTITUTE_MMBR               1
#define ETHARP_FAST_RTE                         1
#define LWIP_DHCP_REQUEST_UNICAST               1

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LWIPOPTS_H__ */

