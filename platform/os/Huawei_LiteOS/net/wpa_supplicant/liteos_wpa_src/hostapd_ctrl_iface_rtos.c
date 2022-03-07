/*
 * hostapd / UNIX domain socket -based control interface
 * Copyright (c) 2004-2014, Jouni Malinen <j@w1.fi>
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved. *
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/common.h"
#include "ap/hostapd.h"
#include "utils/eloop.h"
#include "wifi_api.h"
#include "wpa_supplicant/ctrl_iface.h"
#include "wpa_supplicant/wpa_supplicant_i.h"
#include "los_hwi.h"

int hostapd_ctrl_iface_init(struct hostapd_data *hapd)
{
	if (hapd == NULL)
		return HISI_FAIL;
	struct ctrl_iface_priv *priv = los_ctrl_iface_init(hapd);
	if (priv == NULL) {
		return HISI_FAIL;
	}
	hapd->ctrl_iface = priv;
	return HISI_OK;
}

void hostapd_ctrl_iface_deinit(const struct hostapd_data *hapd)
{
	unsigned int int_save;

	if (hapd == NULL) {
		wpa_error_log0(MSG_ERROR, "hostapd_ctrl_iface_deinit hapd is NULL");
		return;
	}

	struct ctrl_iface_priv *priv = NULL;
	struct hisi_wifi_dev *wifi_dev = wpa_get_other_existed_wpa_wifi_dev(NULL);
	priv = hapd->ctrl_iface;
	if (priv != NULL) {
		eloop_unregister_cli_event(priv->event_queue, 0); // 0:useless
		os_free(priv);
	}
	if ((wifi_dev != NULL) && (wifi_dev->priv != NULL)) {
		int_save = LOS_IntLock();
		g_ctrl_iface_data = ((struct wpa_supplicant *)(wifi_dev->priv))->ctrl_iface;
		LOS_IntRestore(int_save);
	} else {
		int_save = LOS_IntLock();
		g_ctrl_iface_data = NULL;
		LOS_IntRestore(int_save);
	}
}

int hostapd_global_ctrl_iface_init(struct hapd_interfaces *interface)
{
	(void)interface;
	return 0;
}

void hostapd_global_ctrl_iface_deinit(struct hapd_interfaces *interfaces)
{
	(void)interfaces;
}
