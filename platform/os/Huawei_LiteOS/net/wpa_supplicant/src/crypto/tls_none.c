/*
 * SSL/TLS interface functions for no TLS case
 * Copyright (c) 2004-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "tls.h"

void * tls_init(const struct tls_config *conf)
{
	(void)conf;
	return (void *) 1;
}


void tls_deinit(void *ssl_ctx)
{
	(void)ssl_ctx;
}


int tls_get_errors(void *tls_ctx)
{
	(void)tls_ctx;
	return 0;
}


struct tls_connection * tls_connection_init(void *tls_ctx)
{
	(void)tls_ctx;
	return NULL;
}


void tls_connection_deinit(void *tls_ctx, struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
}


int tls_connection_established(void *tls_ctx, struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
	return -1;
}


char * tls_connection_peer_serial_num(void *tls_ctx,
				      struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
	return NULL;
}


int tls_connection_shutdown(void *tls_ctx, struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
	return -1;
}


int tls_connection_set_params(void *tls_ctx, struct tls_connection *conn,
			      const struct tls_connection_params *params)
{
	(void)tls_ctx;
	(void)conn;
	(void)params;
	return -1;
}


int tls_global_set_params(void *tls_ctx,
			  const struct tls_connection_params *params)
{
	(void)tls_ctx;
	(void)params;
	return -1;
}


int tls_global_set_verify(void *tls_ctx, int check_crl, int strict)
{
	(void)tls_ctx;
	(void)check_crl;
	(void)strict;
	return -1;
}


int tls_connection_set_verify(void *tls_ctx, struct tls_connection *conn,
			      int verify_peer, unsigned int flags,
			      const u8 *session_ctx, size_t session_ctx_len)
{
	(void)tls_ctx;
	(void)conn;
	(void)verify_peer;
	(void)flags;
	(void)session_ctx;
	(void)session_ctx_len;
	return -1;
}


int tls_connection_get_random(void *tls_ctx, struct tls_connection *conn,
			      struct tls_random *data)
{
	(void)tls_ctx;
	(void)conn;
	(void)data;
	return -1;
}


int tls_connection_export_key(void *tls_ctx, struct tls_connection *conn,
			      const char *label, const u8 *context,
			      size_t context_len, u8 *out, size_t out_len)
{
	(void)context;
	(void)context_len;
	(void)tls_ctx;
	(void)conn;
	(void)label;
	(void)out;
	(void)out_len;
	return -1;
}


int tls_connection_get_eap_fast_key(void *tls_ctx, struct tls_connection *conn,
				    u8 *out, size_t out_len)
{
	(void)tls_ctx;
	(void)conn;
	(void)out;
	(void)out_len;
	return -1;
}


struct wpabuf * tls_connection_handshake(void *tls_ctx,
					 struct tls_connection *conn,
					 const struct wpabuf *in_data,
					 struct wpabuf **appl_data)
{
	(void)tls_ctx;
	(void)conn;
	(void)in_data;
	(void)appl_data;
	return NULL;
}


struct wpabuf * tls_connection_server_handshake(void *tls_ctx,
						struct tls_connection *conn,
						const struct wpabuf *in_data,
						struct wpabuf **appl_data)
{
	(void)tls_ctx;
	(void)conn;
	(void)in_data;
	(void)appl_data;
	return NULL;
}


struct wpabuf * tls_connection_encrypt(void *tls_ctx,
				       struct tls_connection *conn,
				       const struct wpabuf *in_data)
{
	(void)tls_ctx;
	(void)conn;
	(void)in_data;
	return NULL;
}


struct wpabuf * tls_connection_decrypt(void *tls_ctx,
				       struct tls_connection *conn,
				       const struct wpabuf *in_data)
{
	(void)tls_ctx;
	(void)conn;
	(void)in_data;
	return NULL;
}


int tls_connection_resumed(void *tls_ctx, struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
	return 0;
}


int tls_connection_set_cipher_list(void *tls_ctx, struct tls_connection *conn,
				   u8 *ciphers)
{
	(void)tls_ctx;
	(void)conn;
	(void)ciphers;
	return -1;
}


int tls_get_version(void *ssl_ctx, struct tls_connection *conn,
		    char *buf, size_t buflen)
{
	(void)ssl_ctx;
	(void)conn;
	(void)buf;
	(void)buflen;
	return -1;
}


int tls_get_cipher(void *tls_ctx, struct tls_connection *conn,
		   char *buf, size_t buflen)
{
	(void)tls_ctx;
	(void)conn;
	(void)buf;
	(void)buflen;
	return -1;
}


int tls_connection_enable_workaround(void *tls_ctx,
				     struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
	return -1;
}


int tls_connection_client_hello_ext(void *tls_ctx, struct tls_connection *conn,
				    int ext_type, const u8 *data,
				    size_t data_len)
{
	(void)tls_ctx;
	(void)conn;
	(void)ext_type;
	(void)data;
	(void)data_len;
	return -1;
}


int tls_connection_get_failed(void *tls_ctx, struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
	return 0;
}


int tls_connection_get_read_alerts(void *tls_ctx, struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
	return 0;
}


int tls_connection_get_write_alerts(void *tls_ctx,
				    struct tls_connection *conn)
{
	(void)tls_ctx;
	(void)conn;
	return 0;
}


int tls_get_library_version(char *buf, size_t buf_len)
{
	(void)buf;
	(void)buf_len;
	return os_snprintf(buf, buf_len, "none");
}


void tls_connection_set_success_data(struct tls_connection *conn,
				     struct wpabuf *data)
{
	(void)conn;
	(void)data;
}


void tls_connection_set_success_data_resumed(struct tls_connection *conn)
{
	(void)conn;
}


const struct wpabuf *
tls_connection_get_success_data(struct tls_connection *conn)
{
	(void)conn;
	return NULL;
}


void tls_connection_remove_session(struct tls_connection *conn)
{
	(void)conn;
}
