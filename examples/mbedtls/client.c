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

#include "net/gcoap.h"
#include "mutex.h"

#include "log.h"

#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf

#define VERBOSE 1

#define PAYLOAD_TLS_SIZE 1024

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt cacert;

extern char payload_tls[];
extern int size_payload;

extern mutex_t client_lock;
extern mutex_t client_send_lock;

extern size_t _send(uint8_t *buf, size_t len, char *addr_str, char *port_str);

char *addr_str;

int count_read = 0;
int count_send = 0;
static int offset = 0;
static int get_flag = 0;

static void usage(const char *cmd_name)
{
    LOG(LOG_ERROR, "Usage: %s <server-address>\n", cmd_name);
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
    gcoap_req_init(&pdu, &buf_pdu[0], GCOAP_PDU_BUF_SIZE, 2, "/.well-known/atls");

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
    gcoap_req_init(&pdu, &buf_pdu[0], GCOAP_PDU_BUF_SIZE, 1, "/.well-known/atls");
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);

    if (!_send(&buf_pdu[0], len, addr_str, "5683")){
        puts("gcoap_cli: msg send failed");
        return -1;
    }

    return 0;
}

static int mbedtls_ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
    count_send += 1;

    printf("Client SEND... %d count %d\n",len,count_send);

    if(count_send == -1) mutex_lock(&client_send_lock);

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

    coap_post();

    return len;
}

static int mbedtls_ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
    int i;

    /*  
        Why 2, 3 and 5? They are the server's messages seq IDs in which the client needs to do more
        reads without doing any writes between them. Without the the writes we can't have
        any call to COAP's 'send' function because we don't actually have anything to send.
        In order to have a request -> response mechanism (and in order to let the server know
        the client's ip address when replying) we adopt this cheap trick calling a 'get'.
        TODO: it's not good practice AT ALL to have local counters. It will be a good idea to parse the seq
        numbers directly from the packets and handle eventual packet loss.
    */

    if(!offset) count_read += 1;

    printf("Client RECV...%d count %d\n",len,count_read);

    if(count_read ==-1){
        if(!get_flag) coap_get();
        get_flag = 1;
    }

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

    mbedtls_x509_crt_free( &cacert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("Exiting mbedtls...\n");
}

int mbedtls_client_init()
{
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

    //mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MINOR_VERSION_4, MBEDTLS_SSL_MINOR_VERSION_4);

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    mbedtls_ssl_conf_ke(&conf,KEY_EXCHANGE_MODE_ECDHE_ECDSA);

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return ret;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, "ssl_server" ) ) != 0 )
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

    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    addr_str = argv[1];

    printf("Initializing client...\n");

    //mbedtls_debug_set_threshold(5);

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

    mbedtls_client_exit(ret);

    return ret;
}