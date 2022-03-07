/*
 * hostapd / TKIP countermeasures
 * Copyright (c) 2002-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#ifndef HISI_CODE_CROP
#include "radius/radius.h"
#endif /* HISI_CODE_CROP */
#include "hostapd.h"
#include "sta_info.h"
#include "ap_mlme.h"
#include "wpa_auth.h"
#include "ap_drv_ops.h"
#include "tkip_countermeasures.h"

#ifndef LOS_CONFIG_HOSTAPD_TKIP_MIC
static void ieee80211_tkip_countermeasures_stop(void *eloop_ctx,
						void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	(void)timeout_ctx;
	hapd->tkip_countermeasures = 0;
#ifndef LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT
	(void)hostapd_drv_set_countermeasures(hapd, 0);
#endif /* LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT */
	hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO, "TKIP countermeasures ended");
}


static void ieee80211_tkip_countermeasures_start(struct hostapd_data *hapd)
{
	struct sta_info *sta;

	hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO, "TKIP countermeasures initiated");

	wpa_auth_countermeasures_start(hapd->wpa_auth);
	hapd->tkip_countermeasures = 1;
#ifndef LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT
	(void)hostapd_drv_set_countermeasures(hapd, 1);
#endif /* LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT */
	wpa_gtk_rekey(hapd->wpa_auth);
	(void)eloop_cancel_timeout(ieee80211_tkip_countermeasures_stop, hapd, NULL);
	(void)eloop_register_timeout(60, 0, ieee80211_tkip_countermeasures_stop,
			       hapd, NULL);
	while ((sta = hapd->sta_list)) {
#ifndef HISI_CODE_CROP
		sta->acct_terminate_cause =
			RADIUS_ACCT_TERMINATE_CAUSE_ADMIN_RESET;
#endif  /* HISI_CODE_CROP */
		if (sta->flags & WLAN_STA_AUTH) {
			mlme_deauthenticate_indication(
				hapd, sta,
				WLAN_REASON_MICHAEL_MIC_FAILURE);
		}
#ifndef HISI_CODE_CROP
		(void)hostapd_drv_sta_deauth(hapd, sta->addr,
				       WLAN_REASON_MICHAEL_MIC_FAILURE);
#endif  /* HISI_CODE_CROP */
		ap_free_sta(hapd, sta);
	}
}


void ieee80211_tkip_countermeasures_deinit(struct hostapd_data *hapd)
{
	(void)eloop_cancel_timeout(ieee80211_tkip_countermeasures_stop, hapd, NULL);
}


int michael_mic_failure(struct hostapd_data *hapd, const u8 *addr, int local)
{
	struct os_reltime now;
	int ret = 0;
#ifndef HISI_CODE_CROP
	hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO,
		       "Michael MIC failure detected in received frame%s",
		       local ? " (local)" : "");
#endif /* HISI_CODE_CROP */
	if (addr && local) {
		struct sta_info *sta = ap_get_sta(hapd, addr);
		if (sta != NULL) {
			wpa_auth_sta_local_mic_failure_report(sta->wpa_sm);
			hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_INFO,
				       "Michael MIC failure detected in "
				       "received frame");
			mlme_michaelmicfailure_indication(hapd, addr);
		} else {
			wpa_warning_log4(MSG_DEBUG,
				   "MLME-MICHAELMICFAILURE.indication "
				   "for not associated STA (" "%02x:xx:xx:%02x:%02x:%02x"
				   ") ignored", addr[0], addr[3], addr[4], addr[5]);
			return ret;
		}
	}

	os_get_reltime(&now);
	if (os_reltime_expired(&now, &hapd->michael_mic_failure, 60)) {
		hapd->michael_mic_failures = 1;
	} else {
		hapd->michael_mic_failures++;
		if (hapd->michael_mic_failures > 1) {
			ieee80211_tkip_countermeasures_start(hapd);
			ret = 1;
		}
	}
	hapd->michael_mic_failure = now;

	return ret;
}
#endif /* LOS_CONFIG_HOSTAPD_TKIP_MIC */
