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

#include "mutex.h"
#include "thread.h"

#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf

#define VERBOSE 1

#define PAYLOAD_TLS_SIZE 1024

#define RESPONSE "This is TLS 1.3 server!\n"

//ONLY FOR TESTING PURPOSES!
#define DFL_PSK                 "a66d258de75987d31a4537ecd1ff7a34517bf92f2c07abb20fa0fb517f2491f1"
#define DFL_PSK_IDENTITY        "Client_identity"

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    static unsigned char psk[MBEDTLS_PSK_MAX_LEN];
    static size_t psk_len = 0;
#endif

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt srvcert;
static mbedtls_pk_context pkey;

extern char payload_tls[];
extern int size_payload;

extern mutex_t server_lock;
extern mutex_t server_req_lock;

extern kernel_pid_t main_pid;

int count = 0;
static int offset = 0;
static int wake_flag = 0;

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

static int mbedtls_ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
    int i;

    //printf("Server SEND... %d\n",len);

    mutex_lock(&server_req_lock);

    if(VERBOSE){
        printf("/*-------------------- SERVER SENDING -----------------*/\n");
        for (i = 0; i < len; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END SENDING -----------------*/\n");
    }

    memcpy(payload_tls, buf, len);
    size_payload = len;

    thread_wakeup(main_pid);

    return len;
}

static int mbedtls_ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
    int i;

    //printf("Server RECV... %d\n",len);

    if(!offset){
        mutex_lock(&server_lock);
        count += 1;
    }

    memcpy(buf, payload_tls+offset, len);

    offset += len;

    if(VERBOSE){
        printf("/*-------------------- SERVER RECV -----------------*/\n");
        for (i = 0; i < len; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END RECV -----------------*/\n");
    }

/*
        Why 2 and 3? This is the client's message seq ID in which the server has to do multiple recvs
        without doing any send in the middle. Since it is typically the send function in charge to wake up
        again the COAP thread which is waiting to perform a reply, we need another way. With
        this cheap trick we can reset the mutex and wake up the COAP's thread in order to perform a reply.
        TODO: it's not good practice AT ALL to have local counters. It will be a good idea to parse the seq
        numbers directly from the packets and handle eventual packet loss.
*/

    if(offset == size_payload){
        offset = 0;
    }

    if(count == 2){
        if(wake_flag){
            size_payload = 0;
            thread_wakeup(main_pid);
            wake_flag = 0;
        } else {
            wake_flag = 1;
        }
    }

    return len;
}

int mbedtls_server_init()
{
    int ret;

    unsigned char buf[1024];
    const char *pers = "ssl_server";

    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_pk_init( &pkey );

    mbedtls_entropy_init( &entropy );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return ret;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                          mbedtls_test_srv_crt_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        return ret;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        return ret;
    }

    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key,
                         mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        return ret;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        return ret;
    }

    /** TLS 1.2
    mbedtls_ssl_conf_min_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    **/

    /** TLS 1.3
    mbedtls_ssl_conf_min_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
    mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
    **/

    mbedtls_ssl_conf_min_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
    mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    /*
     * Unhexify the pre-shared key if any is given
     */

    const char *opt_psk;            /* the pre-shared key                       */
    const char *opt_psk_identity;

    opt_psk = DFL_PSK;
    opt_psk_identity = DFL_PSK_IDENTITY;

    if( strlen( opt_psk ) )
    {
        unsigned char c;
        size_t j;

        if( strlen( opt_psk ) % 2 != 0 )
        {
            printf("pre-shared key not valid hex\n");
            return -1;
        }

        psk_len = strlen( opt_psk ) / 2;

        for( j = 0; j < strlen( opt_psk ); j += 2 )
        {
            c = opt_psk[j];
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

            c = opt_psk[j + 1];
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
                             (const unsigned char *) opt_psk_identity,
                             strlen( opt_psk_identity ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_conf_psk returned %d\n\n", ret );
        return ret;
    }

#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */    

    mbedtls_ssl_conf_ke(&conf,KEY_EXCHANGE_MODE_PSK_KE);
    //mbedtls_ssl_conf_ke(&conf,KEY_EXCHANGE_MODE_ECDHE_ECDSA);

    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        return ret;
    }

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return ret;
    }

    mbedtls_ssl_session_reset( &ssl );

    mbedtls_ssl_set_bio( &ssl, NULL, mbedtls_ssl_send, mbedtls_ssl_recv, NULL );

    return ret;
}

void mbedtls_server_exit(int ret)
{
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("Exiting mbedtls...\n");
}

int start_server(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int ret;
    int len;
    unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];

    printf("Initializing server...\n");

    //mbedtls_debug_set_threshold(3);

    ret = mbedtls_server_init();
    if( ret != 0){
        printf("mbedtls_client_init() failed!\n");
        mbedtls_server_exit(ret);
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
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
            mbedtls_server_exit(ret);
            return ret;
        }
    }

    printf(">>> SERVER CONNECTED SUCCESSFULLY!\n");
    printf("Protocol is %s \nCiphersuite is %s\nKey Exchange Mode is %s\n\n",
        mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl), mbedtls_ssl_get_key_exchange_name(&ssl));

    len = sizeof(buf) - 1;
    memset( buf, 0, sizeof(buf) );
    ret = mbedtls_ssl_read( &ssl, buf, len );

    len = ret;
    buf[len] = '\0';
    printf( ">>> %d bytes read\n\n%s\n", len, (char *) buf );

    memset( buf, 0, sizeof(buf) );
    len = sprintf( (char *) buf, RESPONSE );

    ret = mbedtls_ssl_write( &ssl, buf, len );

    len = ret;

    mbedtls_ssl_close_notify( &ssl );

    printf("Exiting mbedtls...\n");

    return ret;
}