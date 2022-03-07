/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: RPL Timers
 * Author: NA
 * Create: 2019-04-05
 */

#ifndef _RPL_TIMER_H_
#define _RPL_TIMER_H_

#include "dag.h"

uint8_t rpl_start_periodic_timer(void);
#if RPL_CONF_MMBR_MNID
void rpl_root_mnid_renew(rpl_dag_t *dag);
#endif

#endif /* _RPL_TIMER_H_ */
