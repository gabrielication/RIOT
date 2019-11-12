#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/ssl.h>

#include "log.h"
#include "net/gcoap.h"

#include "mutex.h"
#include "thread.h"

extern size_t _send(uint8_t *buf, size_t len, char *addr_str, char *port_str);

/* Dummy */
static int fpSend;
static int fpRecv;

#define SERVER_PORT 11111
#define DEBUG 1
extern const unsigned char server_cert[];
extern const unsigned char server_key[];
extern unsigned int server_cert_len;
extern unsigned int server_key_len;

extern char payload_dtls[];
extern int size_payload;

extern mutex_t server_lock;
extern mutex_t server_req_lock;
extern kernel_pid_t main_pid;

int count = 0;
static int offset = 0;
static int wake_flag = 0;

static const char Test_dtls_string[] = "TLS 1.2 OK!";

/* identity is OpenSSL testing default for openssl s_client, keep same */
static const char* kIdentityStr = "Client_identity";

#define APP_DTLS_BUF_SIZE 64

#define VERBOSE 1

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

#define APP_DTLS_BUF_SIZE 64

int server_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl;
    (void) buf;
    (void) sz;
    (void) ctx;

    int i;

    printf("SEND %d\n", sz);

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

    printf("READ %d\n",sz);

    if(!offset){
        mutex_lock(&server_lock);
        count += 1;
        printf("COUNT: %d\n", count);
    }

    memcpy(buf, payload_dtls+offset, sz);

    offset += sz;

    int i;

    if(VERBOSE){
        printf("/*-------------------- SERVER RECV -----------------*/\n");
        for (i = 0; i < sz; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END RECV -----------------*/\n");
    }

/*
        Why 3? This is the client's message seq ID in which the server has to do multiple recvs
        without doing any send in the middle. Since it is typically the send function in charge to wake up
        again the COAP thread which is waiting to perform a reply, we need another way. With
        this cheap trick we can reset the mutex and wake up the COAP's thread in order to perform a reply.

        TODO: here the COAP thread still sends some data in the buffer back to the client but in this
        phase that is totally unnecessary. It will be good to just send a 'success' message with an empty
        payload.
*/
    printf("size_payload %d\n",size_payload);

    if(offset == size_payload){
        printf("READ FINISHED\n");
        offset = 0;
    }

    if(count == 2 || count == 3){
        if(wake_flag){
            size_payload = 0;
            thread_wakeup(main_pid);
            wake_flag = 0;
        } else {
            wake_flag = 1;
        }
    }

    return sz;
}

WOLFSSL* Server(WOLFSSL_CTX* ctx, char* suite, int setSuite)
{
    WOLFSSL* ssl;
    int ret = -1;

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
        printf("Error in setting server ctx\n");
        return NULL;
    }

#ifndef MODULE_WOLFSSL_PSK
    /* Load certificate file for the DTLS server */
    if (wolfSSL_CTX_use_certificate_buffer(rctx, server_cert,
                server_cert_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG(LOG_ERROR, "Failed to load certificate from memory.\r\n");
        return -1;
    }

    /* Load the private key */
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_key,
                server_key_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG(LOG_ERROR, "Failed to load private key from memory.\r\n");
        return -1;
    }
#else
    wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    wolfSSL_CTX_use_psk_identity_hint(ctx, "hint");
#endif /* MODULE_WOLFSSL_PSK */

    wolfSSL_SetIORecv(ctx, server_recv);
    wolfSSL_SetIOSend(ctx, server_send);

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("issue when creating ssl\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    wolfSSL_set_fd(ssl, fpRecv);
    wolfSSL_set_using_nonblock(ssl, fpRecv);
    return ssl;
}

int start_tls_server(int argc, char **argv){

    char buf[APP_DTLS_BUF_SIZE];
    int ret, msgSz;
    WOLFSSL* sslServ;
    WOLFSSL_CTX* ctxServ = NULL;

    fpSend = 0;
    fpRecv = 0;

    wolfSSL_Init();

    sslServ = Server(ctxServ, "let-wolfssl-choose", 0);

    if (sslServ == NULL) { printf("sslServ NULL\n"); return 0;}
    ret = SSL_FAILURE;
    printf("Starting server\n");
    while (ret != SSL_SUCCESS) {
        int error;
        ret = wolfSSL_accept(sslServ);
        error = wolfSSL_get_error(sslServ, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                wolfSSL_free(sslServ);
                wolfSSL_CTX_free(ctxServ);
                printf("server ssl accept failed ret = %d error = %d wr = %d\n",
                                               ret, error, SSL_ERROR_WANT_READ);
                goto cleanup;
            }
        }

    }

    printf("CONNECTED\n");

    wolfSSL_read(sslServ, buf, APP_DTLS_BUF_SIZE);
    buf[size_payload] = (char)0;
    LOG(LOG_INFO, "Received '%s'\r\n", buf);

    char reply[APP_DTLS_BUF_SIZE] = "TLS 1.2 OK!";

    /* Send reply */
    LOG(LOG_INFO, "Sending 'TLS OK'...\r\n");
    wolfSSL_write(sslServ, reply, strlen(reply));

    /* Clean up and exit. */
    LOG(LOG_INFO, "Closing connection.\r\n");

cleanup:
    /*Probably useless*/
    memset(payload_dtls,0,2048);
    size_payload = 0;
    wolfSSL_shutdown(sslServ);
    wolfSSL_free(sslServ);
    wolfSSL_CTX_free(ctxServ);
    wolfSSL_Cleanup();

    return -1;
}