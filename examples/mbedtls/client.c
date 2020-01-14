#include <stdio.h>
#include <string.h>

//#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf

#define VERBOSE 1

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int mbedtls_ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
    if(VERBOSE){
        int i;

        printf("/*-------------------- CLIENT SEND -----------------*/\n");
        for (i = 0; i < len; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END SEND -----------------*/\n");
    }

    return 0;
}

int mbedtls_ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
    if(VERBOSE){
        int i;

        printf("/*-------------------- CLIENT RECV -----------------*/\n");
        for (i = 0; i < len; i++) {
            printf("%02x ", (unsigned char) buf[i]);
            if (i > 0 && (i % 16) == 0)
                printf("\n");
        }
        printf("\n/*-------------------- END RECV -----------------*/\n");
    }
    return 0;
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

    mbedtls_x509_crt_free( &cacert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("Exiting mbedtls...\n");
}

int mbedtls_client_init(){
    int ret;

    const char *pers = "ssl_client1";

    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return ret;
    }

    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        return ret;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        return ret;
    }

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return ret;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, "mbed TLS Server 1" ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        return ret;
    }

    //TODO read write callbacks
    mbedtls_ssl_set_bio( &ssl, NULL, mbedtls_ssl_send, mbedtls_ssl_recv, NULL );

    return ret;
}

int start_client(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int ret;

    ret = mbedtls_client_init();
    if( ret != 0){
        printf("mbedtls_client_init() failed!\n");
        mbedtls_client_exit(ret);
        return ret;
    }

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            break;
        }
    }

    mbedtls_client_exit(ret);

    return ret;
}