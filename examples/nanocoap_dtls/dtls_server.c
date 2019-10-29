#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/ssl.h>

#include "log.h"

static const char Test_dtls_string[] = "DTLS OK!";

#ifdef MODULE_WOLFSSL_PSK
/* identity is OpenSSL testing default for openssl s_client, keep same */
static const char* kIdentityStr = "Client_identity";

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

int fd = 0;

int custom_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    //TODO

    (void) ssl;
    (void) buf;
    (void) sz;
    (void) ctx;

    return 0;
}

int custom_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    //TODO
    
    (void) ssl;
    (void) buf;
    (void) sz;
    (void) ctx;
    return 0;
}

WOLFSSL* create_ssl_obj(WOLFSSL_CTX* ctx, char* suite, int setSuite)
{
    WOLFSSL* ssl;
    (void) suite;
    (void) setSuite;

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method())) == NULL) {
        printf("Error in setting server ctx\n");
        return NULL;
    }

#ifndef MODULE_WOLFSSL_PSK
    /* Load certificate file for the DTLS server */
    if (wolfSSL_CTX_use_certificate_buffer(ctx, server_cert,
                server_cert_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG(LOG_ERROR, "Failed to load certificate from memory.\r\n");
        return NULL;
    }

    /* Load the private key */
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_key,
                server_key_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG(LOG_ERROR, "Failed to load private key from memory.\r\n");
        return NULL;
    }
#else
    wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    wolfSSL_CTX_use_psk_identity_hint(ctx, "hint");
#endif /* MODULE_WOLFSSL_PSK */

    wolfSSL_SetIORecv(ctx, custom_recv);
    wolfSSL_SetIOSend(ctx, custom_send);

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("issue when creating ssl\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    wolfSSL_set_fd(ssl, fd);
    wolfSSL_set_using_nonblock(ssl, fd);
    return ssl;
}

int dtls_server(void)
{
    char buf[256];
    int ret;
    WOLFSSL* sslServ;
    WOLFSSL_CTX* ctxServ = NULL;

    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    sslServ = create_ssl_obj(ctxServ, "let-wolfssl-choose", 0);

    if (sslServ == NULL) { printf("sslServ NULL\n"); return 0;}
    ret = SSL_FAILURE;
    printf("Starting DTLS SERVER\n");

    ret = wolfSSL_accept(sslServ);

    int error;
        
    error = wolfSSL_get_error(sslServ, 0);
    if (ret != SSL_SUCCESS) {
        if (error != SSL_ERROR_WANT_READ &&
            error != SSL_ERROR_WANT_WRITE) {
            wolfSSL_free(sslServ);
            wolfSSL_CTX_free(ctxServ);
            printf("server ssl accept failed ret = %d error = %d wr = %d\n",
            ret, error, SSL_ERROR_WANT_READ);
            return -1; //TODO
        }
    }

    /* Wait until data is received */
    LOG(LOG_INFO, "Connection accepted\r\n");
    ret = wolfSSL_read(sslServ, buf, 256);
    if (ret > 0) {
        buf[ret] = (char)0;
        LOG(LOG_INFO, "Received '%s'\r\n", buf);
    }

    /* Send reply */
    LOG(LOG_INFO, "Sending 'DTLS OK'...\r\n");
    wolfSSL_write(sslServ, Test_dtls_string, sizeof(Test_dtls_string));

    return 0;
}