/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: https功能
 */

#include "hi_stdlib.h"
#include "stdio.h"
#include "stdlib.h"
#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/timing.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"

// 需修改为服务器生成的ca.crt文件内容
unsigned char ca_crt[] = "";  /* the CA need add by user */

#define SERVER_PORT    "" // 需修改为服务器https的端口
#define REQUEST_GET     "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n"
#define NET_PROTO_TCP   0 /* *< The TCP transport protocol */
#define NET_PROTO_UDP   1 /* *< The UDP transport protocol */
#define SSL_HOST_NAME_LEN        256
#define SSL_HOST_PATH_LEN        256

#define SSL_CLIENT      0
#define SSL_SERVER      1

#define SSL_TRANSPORT_STREAM    0   /*!< TLS      */
#define SSL_TRANSPORT_DATAGRAM  1   /*!< DTLS     */

#define SSL_PRESET_DEFAULT      0
#define SSL_PRESET_SUITEB       2

#define SSL_VERIFY_NONE         0
#define SSL_VERIFY_OPTIONAL     1
#define SSL_VERIFY_REQUIRED     2
#define SSL_VERIFY_UNSET        3 /* Used only for sni_authmode */

static mbedtls_ssl_context g_ssl;

#define debug_printf(fmt, ...)

int SslClientTest(char *url)
{
    if (url == NULL) {
        return 0;
    }
    int ret;
    int len;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024 * 2];
    const char *pers = "ssl_client";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    int err_flag = 0;

    char *host;
    char *path = NULL;
    host = (char *)malloc(SSL_HOST_NAME_LEN);
    if (host == NULL) {
        debug_printf("malloc failed");
        goto exit;
    }
    ret = memset_s(host, SSL_HOST_NAME_LEN, 0, SSL_HOST_NAME_LEN);
    if (ret != EOK) {
        goto exit;
    }

    path = (char *)malloc(SSL_HOST_PATH_LEN);
    if (path == NULL) {
        debug_printf("malloc failed");
        goto exit;
    }
    ret = memset_s(path, SSL_HOST_PATH_LEN, 0, SSL_HOST_PATH_LEN);
    if (ret != EOK) {
        goto exit;
    }

    char *pos_start = strstr(url, "//");
    if (pos_start != NULL) {
        pos_start += 2; // 2: "//"的长度
        char *pos_end = strstr(pos_start, "/");
        if (pos_end != NULL) {
            ret = memcpy_s(host, SSL_HOST_PATH_LEN, pos_start, pos_end - pos_start);
            if (ret != EOK) {
                goto exit;
            }
            ret = strcpy_s(path, SSL_HOST_PATH_LEN, pos_end);
            if (ret != 0) {
                goto exit;
            }
            debug_printf("host info:\n\tname:%s\n\tpath:%s\n", host, path);
        }
    }
    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&g_ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    debug_printf("\n  . Seeding the random number generator...");
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char *)pers, strlen(pers))) != 0) {
        debug_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }
    debug_printf(" ok\n");

    /*
     * 1. Initialize certificates
     */
    debug_printf("  . Loading the CA root certificate...");
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)ca_crt, sizeof(ca_crt));
    if (ret < 0) {
        debug_printf(" failed\n  !  mbedtls_x509_crt_parse cacrt returned -0x%x\n\n", -ret);
        goto exit;
    }

    debug_printf(" ok (%d skipped)\n", ret);

    /*
     * 2. Start the connection
     */
    debug_printf("  . Connecting to tcp/%s/%s...", host, SERVER_PORT);
    if ((ret = mbedtls_net_connect(&server_fd, host, SERVER_PORT, NET_PROTO_TCP)) != 0) {
        debug_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }
    debug_printf(" ok\n");

    /*
     * 3. Setup stuff
     */
    debug_printf("  . Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&conf,
        SSL_CLIENT,
        SSL_TRANSPORT_STREAM,
        SSL_PRESET_DEFAULT)) != 0) {
        debug_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }
    debug_printf(" ok\n");

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&g_ssl, &conf)) != 0) {
        debug_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&g_ssl, host)) != 0) {
        debug_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&g_ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /*
     * 4. Handshake
     */
    debug_printf("  . Performing the SSL/TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(&g_ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            debug_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            err_flag = 1;
            break;
        }
    }

    if (err_flag == 1) {
        goto exit;
    }

    debug_printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    debug_printf("  . Verifying peer X.509 certificate...");
    /* In real life, we probably want to bail out when ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&g_ssl)) != 0) {
        char vrfy_buf[512];
        debug_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        debug_printf("%s\n", vrfy_buf);
    } else {
        debug_printf(" ok\n");
    }

    /* step6 ~ step7 is application data, optional */
    /*
     * 6. Write the GET request
     */
    debug_printf("  > Write to server:");
    len = sprintf_s((char *)buf, sizeof(buf), REQUEST_GET, path, host);
    while ((ret = mbedtls_ssl_write(&g_ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            debug_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            err_flag = 0;
            break;
        }
    }

    if (err_flag == 1) {
        goto exit;
    }

    len = ret;
    debug_printf(" %d bytes written\n\n%s", len, (char *)buf);
    /*
     * 7. Read the HTTP response
     */
    debug_printf("  < Read from server:");
    do {
        len = sizeof(buf) - 1;
        memset_s(buf, sizeof(buf), 0, sizeof(buf));
        ret = mbedtls_ssl_read(&g_ssl, buf, len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            break;

        if (ret < 0) {
            debug_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0) {
            debug_printf("\n\nEOF\n\n");
            break;
        }

        len = ret;
        debug_printf(" %d bytes read\n\n%s", len, (char *)buf);
    } while (1);
    debug_printf(" %d bytes read\n\n%s", len, (char *)buf);

    mbedtls_ssl_close_notify(&g_ssl);
exit:
    if (NULL != host) {
        free(host);
        host = NULL;
    }

    if (NULL != path) {
        free(path);
        path = NULL;
    }
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&g_ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return 0;
}
