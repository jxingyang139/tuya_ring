/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: RPL messaging common apis
 * Author: NA
 * Create: 2019-04-05
 */

#ifndef _RPL_MESSAGING_H_
#define _RPL_MESSAGING_H_

#include "rpl_common.h"
#include "route_mgmt.h"

#define ICMP6_RPL 155

/* RPL message types */
#define RPL_CODE_DIS 0x00     /* DAG Information Solicitation */
#define RPL_CODE_DIO 0x01     /* DAG Information Option */
#define RPL_CODE_DAO 0x02     /* Destination Advertisement Option */
#define RPL_CODE_DAO_ACK 0x03 /* DAO acknowledgment */
#define RPL_CODE_DCO 0x07     /* Destination Cleanup Option */
#define RPL_CODE_DCO_ACK 0x08 /* Destination Cleanup Option acknowledgment */

/* RPL control message options. */
#define OPT_PAD1 0
#define OPT_PADN 1
#define OPT_DAG_METRIC_CONTAINER 2
#define OPT_ROUTE_INFO 3
#define OPT_DAG_CONF 4
#define OPT_TARGET 5
#define OPT_TRANSIT 6
#define OPT_SOLICITED_INFO 7
#define OPT_PREFIX_INFO 8
#define OPT_TARGET_DESC 9
/* DIO should include the DNS info */
#define RPL_OPT_DNS 0xF1
/* DAO-ACK should include mnid option */
#define RPL_OPT_MNID 0xF2
#define RPL_OPT_PREFER_PARENT  0xF3
#define OPT_RESOURCE_INFO 0xF4
#define OPT_PARENT_STATUS_INFO 0xF5
/* peer connect time count. The RPL Target option MAY be followed by one this option */
#define OPT_TARGET_CONN_TIME 0xF6

/* Flags in DAO message */
#define DAO_K_FLAG 0x80
#define DAO_D_FLAG 0x40

#define DAO_RSV_NP_FLAG 0x80

/* Flags in Prefix Information Option */
#define PIO_R_FLAG 0x20
#define PIO_A_FLAG 0x40

/* Status field in DAOACK */
#define DAO_ACK_STATUS_OK 0
#define DAO_ACK_STATUS_MNID_ALLOCING 125
#define DAO_ACK_STATUS_NAT64_IP4 126
#define DAO_ACK_STATUS_TABLE_FULL 128
#define DAO_ACK_STATUS_MG_FULL 129 /* MG node is full in this dag */
#define DAO_ACK_STATUS_MNID_ALLOC_FAIL 250 /* MBR could not allocate MNID */
#define DCO_ACK_STATUS_RTENTRY_NOT_FOUND 128

#define rpl_get8b(BUF, LEN, VAL) do { \
  (VAL) = (BUF)[(LEN)++]; \
} while (0)

#define rpl_get16b(BUF, LEN, VAL) do { \
  (VAL) = (uint16_t)(((BUF)[(LEN)] << 8) | (BUF)[(LEN) + 1]); \
  (LEN) = (uint16_t)((LEN) + 2); \
} while (0)

#define rpl_get32b(BUF, LEN, VAL) do { \
  (VAL) = (uint32_t)(((BUF)[(LEN)] << 24) | ((BUF)[(LEN) + 1] << 16) | ((BUF)[(LEN) + 2] << 8) | (BUF)[(LEN) + 3]); \
  (LEN) = (uint16_t)((LEN) + 4); \
} while (0)

static inline void rpl_get_addr(const uint8_t *buf, uint16_t *len, rpl_addr_t *addr)
{
  (void)memcpy_s(addr->a8, RPL_6ADDR_1BYTES_CNT, buf + (*len), RPL_6ADDR_1BYTES_CNT);
  *len += RPL_6ADDR_1BYTES_CNT;
}

#define rpl_set8b(BUF, LEN, VAL) do { \
  (BUF)[(LEN)++] = (uint8_t)(VAL); \
} while (0)

#define rpl_set16b(BUF, LEN, VAL) do { \
  (BUF)[(LEN)++] = (uint8_t)((VAL) >> 8); \
  (BUF)[(LEN)++] = (uint8_t)((VAL) & 0xff); \
} while (0)

#define rpl_set32b(BUF, LEN, VAL) do {              \
  (BUF)[(LEN)++] = (uint8_t)((VAL) >> 24);          \
  (BUF)[(LEN)++] = (uint8_t)(((VAL) >> 16) & 0xff); \
  (BUF)[(LEN)++] = (uint8_t)(((VAL) >> 8) & 0xff);  \
  (BUF)[(LEN)++] = (uint8_t)((VAL) & 0xff);         \
} while (0)

static inline void rpl_set_addr(uint8_t *buf, uint16_t *len, const rpl_addr_t *addr)
{
  (void)memcpy_s(buf + (*len), RPL_6ADDR_1BYTES_CNT, addr->a8, RPL_6ADDR_1BYTES_CNT);
  *len += RPL_6ADDR_1BYTES_CNT;
}

#if RPL_CONF_INSTID == 1
#define rpl_set_inst_id(BUF, LEN, VAL) rpl_set8b((BUF), LEN, VAL)
#define rpl_get_inst_id(BUF, LEN, VAL) rpl_get8b((BUF), LEN, VAL)
#elif RPL_CONF_INSTID == 2
#define rpl_set_inst_id(BUF, LEN, VAL) rpl_set16b((BUF), LEN, VAL)
#define rpl_get_inst_id(BUF, LEN, VAL) rpl_get16b((BUF), LEN, VAL)
#elif RPL_CONF_INSTID == 4
#define rpl_set_inst_id(BUF, LEN, VAL) rpl_set32b((BUF), LEN, VAL)
#define rpl_get_inst_id(BUF, LEN, VAL) rpl_get32b((BUF), LEN, VAL)
#else
#error "Incorrect RPL_CONF_INSTID"
#endif

#define DIO_GROUNDED 0x80
#define DIO_MOP_SHIFT 3
#define DIO_MOP_MASK 0x3c
#define DIO_PREFERENCE_MASK 0x07

typedef struct {
  rpl_dag_t *dag;
  rpl_addr_t *ip6addr;
  rpl_addr_t *proxy_tgt_addr;
  rpl_mnode_id_t tgt_mnid;
  uint8_t path_seq;
  uint8_t status;
} rpl_daoack_proactive_t;

void rpl_dis_transmit(const rpl_addr_t *addr);
uint8_t rpl_dio_transmit(rpl_dag_t *dag, const rpl_addr_t *dst);
uint8_t rpl_dao_transmit(rpl_dag_t *dag);
uint8_t rpl_npdao_transmit(rpl_dag_t *dag, rpl_parent_t *prnt);
uint16_t rpl_get_option(uint8_t *opt_type, uint8_t *opt_len, const uint8_t *buf, uint16_t buflen);
uint8_t rpl_npdao_proxy_to_parent(rpl_dag_t *dag, const rpl_rte_t *rte, const rpl_parent_t *prnt);
void rpl_dis_target_miss(const rpl_addr_t *tgt);
uint8_t rpl_daoack_transmit_proactive(const rpl_daoack_proactive_t *daoack);

#endif /* _RPL_MESSAGING_H_ */
