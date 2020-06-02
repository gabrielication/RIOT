/*
 * Copyright (C) 2019 Gabriele Restuccia
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Example application of ADTLS 1.2 over CoAP
 *
 * @author      Gabriele Restuccia <restuccia.1548310@studenti.uniroma1.it>
 *
 * @}
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include "log.h"
#include "net/gcoap.h"
#include "mutex.h"
#include "thread.h"

#define DEBUG 1
#define VERBOSE 0

#ifdef MODULE_WOLFSSL_PSK

#define PAYLOAD_DTLS_SIZE 256

#else

#define PAYLOAD_DTLS_SIZE 1024

#endif

static int config_index = 3;
static char *config[] = {"PSK-AES128-CCM", "PSK-AES128-GCM-SHA256", "PSK-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-CCM-8", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"};

extern size_t _send(uint8_t *buf, size_t len, char *addr_str, char *port_str);

extern const unsigned char server_cert[];
extern const unsigned char server_key[];
extern unsigned int server_cert_len;
extern unsigned int server_key_len;

extern char payload_dtls[];
extern int size_payload;

extern mutex_t server_lock;
extern mutex_t server_req_lock;
extern kernel_pid_t main_pid;

static unsigned char thread_wakeup_flag = 0;

/* identity is OpenSSL testing default for openssl s_client, keep same */
static const char* kIdentityStr = "Client_identity";

#ifdef MODULE_WOLFSSL_PSK

static inline unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
        unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    if (strncmp(identity, kIdentityStr, strlen(kIdentityStr)) != 0)
        return 0;

    if (wolfSSL_GetVersion(ssl) < WOLFSSL_TLSV1_3) {
        /* test key in hex is 0x1a2b3c4d , in decimal 439,041,101 , we're using
           unsigned binary */
        key[0] = 0x1a;
        key[1] = 0x2b;
        key[2] = 0x3c;
        key[3] = 0x4d;

        return 4;   /* length of key in octets or 0 for error */
    }
    else {
        int i;
        int b = 0x01;

        for (i = 0; i < 32; i++, b += 0x22) {
            if (b >= 0x100)
                b = 0x01;
            key[i] = b;
        }

        return 32;   /* length of key in octets or 0 for error */
    }
}
#endif /* MODULE_WOLFSSL_PSK */

int server_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl;
    (void) buf;
    (void) sz;
    (void) ctx;

    int i;

    //printf("SERVER SEND... %d\n",sz);

    mutex_lock(&server_req_lock);

    if(VERBOSE){
        printf("/*-------------------- SERVER SENDING -----------------*/\n");
        for (i = 0; i < sz; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END SENDING -----------------*/\n");
    }

    memcpy(payload_dtls, buf, sz);
    size_payload = sz;

    thread_wakeup(main_pid);

    return sz;
}

int server_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl;
    (void) buf;
    (void) sz;
    (void) ctx;

    int i;
    //printf("SERVER RECV...\n");

    mutex_lock(&server_lock);

    sz = size_payload;

    //printf("sz %d payload %d\n",sz,size_payload);

    memcpy(buf, payload_dtls, size_payload);

    if(VERBOSE){
        printf("/*-------------------- SERVER RECV -----------------*/\n");
        for (i = 0; i < size_payload; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END RECV -----------------*/\n");
    }
/*
    if(ssl->options.acceptState == SERVER_HELLO_DONE){
        if(!thread_wakeup_flag){
            size_payload = 0;
            thread_wakeup_flag = 1;
            thread_wakeup(main_pid);
        }
    }
*/
    return sz;
}

WOLFSSL* Server(WOLFSSL_CTX* ctx, char* suite, int setSuite)
{
    WOLFSSL* ssl;
    int ret = -1;

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method())) == NULL) {
        printf("Error in setting server ctx\n");
        return NULL;
    }

#ifndef MODULE_WOLFSSL_PSK
    /* Load certificate file for the TLS server */
    if (wolfSSL_CTX_use_certificate_buffer(ctx, server_cert,
                server_cert_len, SSL_FILETYPE_PEM ) != SSL_SUCCESS)
    {
        LOG(LOG_ERROR, "Failed to load certificate from memory.\r\n");
        return NULL;
    }

    /* Load the private key */
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_key,
                server_key_len, SSL_FILETYPE_PEM ) != SSL_SUCCESS)
    {
        LOG(LOG_ERROR, "Failed to load private key from memory.\r\n");
        return NULL;
    }

#else
    wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    wolfSSL_CTX_use_psk_identity_hint(ctx, "hint");
#endif /* MODULE_WOLFSSL_PSK */

    if (( ret = wolfSSL_CTX_set_cipher_list(ctx, config[config_index])) != SSL_SUCCESS) {
            printf("ret = %d\n", ret);
            printf("Error :can't set cipher\n");
            wolfSSL_CTX_free(ctx);
            return NULL;
    }

    wolfSSL_SetIORecv(ctx, server_recv);
    wolfSSL_SetIOSend(ctx, server_send);

    wolfSSL_CTX_set_group_messages(ctx);

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("issue when creating ssl\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    return ssl;
}

void server_cleanup(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}

int start_dtls_server(int argc, char **argv)
{
    char buf[PAYLOAD_DTLS_SIZE];
    int ret, msgSz;
    WOLFSSL* sslServ;
    WOLFSSL_CTX* ctxServ = NULL;

    //wolfSSL_Debugging_ON();

    wolfSSL_Init();

    sslServ = Server(ctxServ, NULL, 0);

    if (sslServ == NULL){
        printf("Failed to start server. Exiting...\n");
        server_cleanup(sslServ,ctxServ);
        return -1;
    }

    ret = SSL_FAILURE;
    printf("Starting server\n");
    while (ret != SSL_SUCCESS) {
        int error;
        ret = wolfSSL_accept(sslServ);
        error = wolfSSL_get_error(sslServ, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                printf("server ssl accept failed ret = %d error = %d wr = %d\n",
                                               ret, error, SSL_ERROR_WANT_READ);
                server_cleanup(sslServ,ctxServ);
                return -1;
            }
        }

    }

    printf("SERVER CONNECTED SUCCESSFULLY!\n");
    printf("TLS version is %s\n", wolfSSL_get_version(sslServ));
    printf("Cipher Suite is %s\n",
           wolfSSL_CIPHER_get_name(wolfSSL_get_current_cipher(sslServ)));

    char reply[] = "This is ATLS server!";

    wolfSSL_read(sslServ, buf, PAYLOAD_DTLS_SIZE);
    buf[size_payload] = (char)0;

    //  TODO: probably the string isn't terminated correctly and sometimes
    //  can print random chars
    
    LOG(LOG_INFO, "Received '%s'\r\n", buf);

    /* Send reply */
    LOG(LOG_INFO, "Sending 'DTLS OK'...\r\n");
    wolfSSL_write(sslServ, reply, strlen(reply));

    /* Clean up and exit. */
    LOG(LOG_INFO, "Closing connection.\r\n");

    server_cleanup(sslServ,ctxServ);

    return 0;
}