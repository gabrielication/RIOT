#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/ssl.h>

#include "log.h"
#include "net/gcoap.h"

#ifdef MODULE_WOLFSSL_PSK
/* identity is OpenSSL testing default for openssl s_client, keep same */
static const char* kIdentityStr = "Client_identity";

extern size_t _send(uint8_t *buf, size_t len, char *addr_str, char *port_str);

int fpRecv = 0;

static inline unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    strncpy(identity, kIdentityStr, id_max_len);

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
#endif

int client_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl;
    (void) sz;
    (void) ctx;

    int i;

    printf("/*-------------------- CLIENT SENDING -----------------*/\n");
        for (i = 0; i < sz; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
    printf("\n/*-------------------- CLIENT SENDING -----------------*/\n");

    //TODO
    /*
        For initializing a COAP packet we need a buffer which can contain all of the header options for
        a PDU and the eventual payload.
    */

    // The GCOAP macro is 128B because it is typically enough to hold all the header options
    // But we have to be sure it is enoguh to hold also the payload!!!
    uint8_t buf2[256]; //Probably needs more space
    coap_pkt_t pdu;
    size_t len;
    size_t paylen;

    paylen = sz; //Using strlen here is stupid. It will understand zeroes as end of a string

    gcoap_req_init(&pdu, &buf2[0], 256, 2, "/.well-known/atls"); //Probably needs more space

    coap_opt_add_format(&pdu, COAP_FORMAT_TEXT);
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);

    // The payload len tells how many bytes are free for the payload. If we have
    // enough space we can copy our message inside it.
    if (pdu.payload_len >= paylen) {
                memcpy(pdu.payload, buf, paylen);
                printf("Paylen is %d and len is %d\n",paylen,len);
                len += paylen;
    } else {
                puts("gcoap_cli: msg buffer too small");
                return -1;
    }

    if (!_send(&buf2[0], len, "fe80::705e:72ff:fe98:e983", "5683")){
        puts("gcoap_cli: msg send failed");
    }

    return sz;
}

int client_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void) ssl;
    (void) buf;
    (void) sz;
    (void) ctx;
    
    return 0;
}

WOLFSSL* Client(WOLFSSL_CTX* ctx, char* suite, int setSuite, int doVerify)
{
    WOLFSSL* ssl = NULL;
    int ret;

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method())) == NULL) {
        printf("Error in setting client ctx\n");
        return NULL;
    }

#ifndef MODULE_WOLFSSL_PSK
    /* Disable certificate validation from the client side */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    /* Load certificate file for the DTLS client */
    if (wolfSSL_CTX_use_certificate_buffer(ctx, server_cert,
                server_cert_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG(LOG_ERROR, "Error loading cert buffer\n");
        return -1;
    }

#else /* !def MODULE_WOLFSSL_PSK */
    wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
#endif

    wolfSSL_SetIORecv(ctx, client_recv);
    wolfSSL_SetIOSend(ctx, client_send);

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        printf("issue when creating ssl\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    wolfSSL_set_fd(ssl, fpRecv);
    wolfSSL_set_using_nonblock(ssl, fpRecv);

    return ssl;
}

int start_dtls_client(int argc, char **argv)
{
    WOLFSSL* sslCli;
    WOLFSSL_CTX* ctxCli = NULL;

    (void) argc;
    (void) argv;

    int ret = SSL_FAILURE;

    wolfSSL_Init();

    /* Example usage */
//    sslServ = Server(ctxServ, "ECDHE-RSA-AES128-SHA", 1);
    sslCli  = Client(ctxCli, "let-wolfssl-decide", 0, 1);

    if (sslCli == NULL) {
        printf("Failed to start client\n");
        goto cleanup;
    }

    printf("Starting client\n");
    while (ret != SSL_SUCCESS) {
        int error;

        /* client connect */
        ret |= wolfSSL_connect(sslCli);
        error = wolfSSL_get_error(sslCli, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) {
                wolfSSL_free(sslCli);
                wolfSSL_CTX_free(ctxCli);
                printf("client ssl connect failed\n");
                break;
            }
        }
        printf("Client connected successfully...\n");
    }

cleanup:
    wolfSSL_shutdown(sslCli);
    wolfSSL_free(sslCli);
    wolfSSL_CTX_free(ctxCli);
    wolfSSL_Cleanup();

    return 0;
}