/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Interface of app demo upg.
 * Author: Hisilicon
 * Create: 2020-03-04
 */

#ifndef _APP_DEMO_CHANNEL_H_
#define _APP_DEMO_CHANNEL_H_

unsigned int hi_channel_rx_callback(char *buf, int length);
void hi_channel_send_ip(void *dev_if);
int hi_channel_set_default_filter(void);

#endif /* _APP_DEMO_CHANNEL_H_ */

