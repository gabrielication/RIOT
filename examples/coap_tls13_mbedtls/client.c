/*
 * Copyright (C) 2020 Gabriele Restuccia
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
 * @brief       Demonstrating ATLS 1.3 using MbedTLS
 *
 * @author      Gabriele Restuccia <grestuccia@cnit.it>
 * @}
 */

#include <stdio.h>
#include <string.h>

//#include "mbedtls/net.h"
#include "mbedtls/config.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#ifdef MBEDTLS_PLATFORM_MEMORY
#include "mbedtls/platform.h"
#endif

#include "net/gcoap.h"
#include "mutex.h"

#include "certs.h"

#include "log.h"

#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf

#define VERBOSE 0

#define GET_REQUEST "This is ATLS client!\n"

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    // !!!CAREFUL!!! ONLY FOR TESTING PURPOSES!
    #define DFL_PSK                 "a66d258de75987d31a4537ecd1ff7a34517bf92f2c07abb20fa0fb517f2491f1"
    #define DFL_PSK_IDENTITY        "Client_identity"
    static unsigned char psk[MBEDTLS_PSK_MAX_LEN];
    static size_t psk_len = 0;
#endif

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;

extern int iface;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    static mbedtls_x509_crt cacert;

    static mbedtls_x509_crt clicert;
    static mbedtls_pk_context pkey;
#endif

//KEY_EXCHANGE_MODE_ECDHE_ECDSA
//KEY_EXCHANGE_MODE_PSK_KE
static unsigned char key_exchange_modes = KEY_EXCHANGE_MODE_ECDHE_ECDSA;
static int tls_version = MBEDTLS_SSL_MINOR_VERSION_4;

extern char payload_tls[];
extern int size_payload;

extern mutex_t client_lock;
extern mutex_t client_send_lock;

#ifdef MBEDTLS_PLATFORM_MEMORY
extern unsigned int mem_max;

extern void* MyCalloc(size_t n, size_t size);
extern void MyFree(void* ptr);
#endif

static int cipher[2];

extern size_t _send(uint8_t *buf, size_t len, char *addr_str, char *port_str);

char *addr_str;

static int offset = 0;
static int get_flag = 0;

static int send_count = 0;
static int recv_count = 0;

static void usage(const char *cmd_name)
{
    LOG(LOG_ERROR, "\nUsage: %s <server-address> <key-exchange-mode> <ciphersuite>\n\n \
        - Admitted key exchange modes:\n\n \
        psk\n \
        ecdhe_ecdsa\n\n \
        - Admitted ciphersuites: \n\n \
        TLS_AES_128_CCM_SHA256\n \
        TLS_AES_128_GCM_SHA256\n \
        TLS_AES_256_GCM_SHA384\n\n \
        (Also check that your config.h is coherent with your choice)\n", cmd_name);
}

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int coap_post(void)
{
    /*
        For initializing a COAP packet we need a buffer which can contain all of the header options for
        a PDU and the eventual payload.
    */

    // The GCOAP macro is 128B because it is typically enough to hold all the header options
    // But we have to be sure it is enoguh to hold also the payload!!!
    // We solve that by redefining it in the Makefile.
    uint8_t buf_pdu[GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;
    size_t paylen;

    //Using strlen here is stupid. It will understand zeroes as end of a string
    paylen = size_payload;

    // Code '2' is POST
    gcoap_req_init(&pdu, &buf_pdu[0], GCOAP_PDU_BUF_SIZE, COAP_POST, "/.well-known/atls");

    coap_opt_add_format(&pdu, COAP_FORMAT_TEXT);
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);

    // The payload len tells how many bytes are free for the payload. If we have
    // enough space we can copy our message inside it.
    if (pdu.payload_len >= paylen) {
                memcpy(pdu.payload, payload_tls, paylen);
                len += paylen;
    } else {
                puts("gcoap_cli: msg buffer too small");
                return -1;
    }

    if (!_send(&buf_pdu[0], len, addr_str, "5683")){
        puts("gcoap_cli: msg send failed");
        return -1;
    }

    return 0;
}

int coap_get(void)
{

    uint8_t buf_pdu[GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;

    // Code '1' is GET
    gcoap_req_init(&pdu, &buf_pdu[0], GCOAP_PDU_BUF_SIZE, COAP_GET, "/.well-known/atls");
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);

    if (!_send(&buf_pdu[0], len, addr_str, "5683")){
        puts("gcoap_cli: msg send failed");
        return -1;
    }

    return 0;
}

static int mbedtls_ssl_send(void *ctx, const unsigned char *buf, size_t len)
{

    printf("Client SEND... %d\n", send_count);
    //printf("SEND ssl state %d\n",ssl.state);
/*
    if(ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER && ssl.out_msgtype != MBEDTLS_SSL_MSG_ALERT){
        mutex_lock(&client_send_lock);
    }
*/
#if defined(MBEDTLS_CERTS_C)
    if(send_count == 2 || send_count == 3 || send_count == 4){
        mutex_lock(&client_send_lock);
    }
#else
    if(send_count == 2 || send_count == -3 || send_count == -4){
        mutex_lock(&client_send_lock);
    }
#endif

    memcpy(payload_tls,buf,len);
    size_payload = len;

    if(VERBOSE){
        int i;

        printf("/*-------------------- CLIENT SEND -----------------*/\n");
        for (i = 0; i < size_payload; i++) {
            printf("%02x ", (unsigned char) payload_tls[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END SEND -----------------*/\n");
    }

    if(coap_post() != 0){
        return -1; //POST FAILED
    }

    send_count++;

    return len;
}

static int mbedtls_ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
    unsigned int i;

    printf("Client RECV...%d\n",recv_count);
    //printf("RECV ssl state %d\n",ssl.state);
/*
    if(ssl.state > MBEDTLS_SSL_SERVER_HELLO && ssl.state < MBEDTLS_SSL_HANDSHAKE_OVER){
        if(!get_flag) coap_get();
            get_flag = 1;
    }
*/
#if defined(MBEDTLS_CERTS_C)
    if(recv_count == 1 || recv_count == 2 || recv_count == 3 || recv_count == 4 || recv_count == 5){
        if(!get_flag){
            if(coap_get() != 0) return -1;
            else get_flag = 1;
        }
    }
#else
    if(recv_count == 1 || recv_count == 2 || recv_count == -3 || recv_count == -4 || recv_count == -5){
        if(!get_flag){
            if(coap_get() != 0) return -1;
            else get_flag = 1;
        }
    }
#endif

    if(!offset) mutex_lock(&client_lock);

    memcpy(buf, payload_tls+offset, len);

    offset += len;

    if(VERBOSE){
        printf("/*-------------------- CLIENT RECV -----------------*/\n");
        for (i = 0; i < len; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END RECV -----------------*/\n");
    }

    if(offset == size_payload){
        offset = 0;
        get_flag = 0;
        recv_count++;
    }

    return len;
}

static void mbedtls_client_exit(int ret)
{

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    #if defined(MBEDTLS_X509_CRT_PARSE_C)
        mbedtls_x509_crt_free( &cacert );
    #endif

    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("Exiting mbedtls...\n");
}

int mbedtls_client_init(void)
{
    int ret;

    const char *pers = "ssl_client1";

    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return ret;
    }

    #if defined(MBEDTLS_X509_CRT_PARSE_C)

        mbedtls_x509_crt_init( &cacert );
        mbedtls_x509_crt_init( &clicert );
        mbedtls_pk_init( &pkey );

        // !!!CAREFUL!!! ONLY FOR TESTING PURPOSES!
        ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) ca_cert,
                              ca_cert_len );
        if( ret < 0 )
        {
            printf( " failed\n  !  CA mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
           return ret;
        }

        ret = mbedtls_x509_crt_parse( &clicert, (const unsigned char *) client_cert,
                                  client_cert_len );
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  !  client mbedtls_x509_crt_parse returned %d\n\n", ret );
            return ret;
        }

        ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) client_key,
                             client_key_len, NULL, 0 );
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
                return ret;
        }

    #endif

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        return ret;
    }

    mbedtls_ssl_conf_min_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, tls_version);
    mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, tls_version);

    #if defined(MBEDTLS_X509_CRT_PARSE_C)

       mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );

        if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &clicert, &pkey ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
            return ret;
        }

        /* OPTIONAL is not optimal for security,
        * but makes interop easier in this simplified example */
        mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );

    #endif

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    /*
     * Unhexify the pre-shared key if any is given
     */

    if( strlen( DFL_PSK ) )
    {
        unsigned char c;
        size_t j;

        if( strlen( DFL_PSK ) % 2 != 0 )
        {
            printf("pre-shared key not valid hex\n");
            return -1;
        }

        psk_len = strlen( DFL_PSK ) / 2;

        for( j = 0; j < strlen( DFL_PSK ); j += 2 )
        {
            c = DFL_PSK[j];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                printf("pre-shared key not valid hex\n");
                return -1;
            }
            psk[ j / 2 ] = c << 4;

            c = DFL_PSK[j + 1];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                printf("pre-shared key not valid hex\n");
                return -1;
            }
            psk[ j / 2 ] |= c;
        }
    }

    if( ( ret = mbedtls_ssl_conf_psk( &conf, psk, psk_len,
                             (const unsigned char *) DFL_PSK_IDENTITY,
                             strlen( DFL_PSK_IDENTITY ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_conf_psk returned %d\n\n", ret );
        return ret;
    }

#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

    mbedtls_ssl_conf_ke(&conf,key_exchange_modes);

/*
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher[0] );
*/
    mbedtls_ssl_conf_ciphersuites( &conf, cipher );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return ret;
    }

    #if defined(MBEDTLS_X509_CRT_PARSE_C)

        if( ( ret = mbedtls_ssl_set_hostname( &ssl, "www.prova.com" ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
            return ret;
        }
        
    #endif

    mbedtls_ssl_set_bio( &ssl, NULL, mbedtls_ssl_send, mbedtls_ssl_recv, NULL );

    return ret;
}

int start_client(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int ret;
    unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
    int len;

    if (argc < 2) {
        usage(argv[0]);
        return -1;
    }

    addr_str = argv[1];

    iface = ipv6_addr_split_iface(addr_str);

    if (argc == 4){
        if (strcmp(argv[2], "psk") == 0)
                key_exchange_modes = KEY_EXCHANGE_MODE_PSK_KE;
        else if (strcmp(argv[2], "ecdhe_ecdsa") == 0)
                key_exchange_modes = KEY_EXCHANGE_MODE_ECDHE_ECDSA;
        else{
            printf("Key exchange mode not found\n");
            usage(argv[0]);
            return -1;
        }

        cipher[0] = mbedtls_ssl_get_ciphersuite_id(argv[3]);
        cipher[1] = 0;

        if (cipher[0] == 0)
                {
                    mbedtls_printf("Forced ciphersuite not found\n");
                    usage(argv[0]);
                    return -1;
                }
    } else {
            usage(argv[0]);
            return -1;
    }

    printf("Initializing client...\n");

    //mbedtls_debug_set_threshold(3);

#ifdef MBEDTLS_PLATFORM_MEMORY
    mbedtls_platform_set_calloc_free(MyCalloc,MyFree);
#endif

    ret = mbedtls_client_init();
    if( ret != 0){
        printf("mbedtls_client_init() failed!\n");
        mbedtls_client_exit(ret);
        return ret;
    }

    
    /**
    const int *list;

    list = mbedtls_ssl_list_ciphersuites();
        while( *list )
        {
            mbedtls_printf(" %-42s", mbedtls_ssl_get_ciphersuite_name( *list ) );
            list++;
            if( !*list )
                break;
            mbedtls_printf(" %s\n", mbedtls_ssl_get_ciphersuite_name( *list ) );
            list++;
        }
    mbedtls_printf("\n");
    **/

    printf("Proceeding to handshake...\n");

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            mbedtls_client_exit(ret);
            return ret;
        }
    }

    printf("CLIENT CONNECTED SUCCESSFULLY!\n");
    printf("Protocol is %s \nCiphersuite is %s\nKey Exchange Mode is %s\n\n",
        mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl), mbedtls_ssl_get_key_exchange_name(&ssl));
/*
    len = sprintf( (char *) buf, GET_REQUEST );

    while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            mbedtls_client_exit(ret);
            return ret;
        }
    }

    len = ret;

    len = sizeof( buf ) - 1;
    memset( buf, 0, sizeof( buf ) );
    ret = mbedtls_ssl_read( &ssl, buf, len );

    len = ret;
    buf[len] = '\0';
    printf( ">>> %d bytes read\n\n%s\n", len, (char *) buf );
*/
    mbedtls_ssl_close_notify( &ssl );

#ifdef MBEDTLS_PLATFORM_MEMORY
    printf("MAX HEAP IS %d\n", mem_max);
#endif

    mbedtls_client_exit(0);

    return ret;
}