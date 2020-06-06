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
 * @brief       Example application of ATLS 1.3 over CoAP
 *
 * @author      Gabriele Restuccia <restuccia.1548310@studenti.uniroma1.it>
 *
 * @}
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "net/gcoap.h"
#include "od.h"
#include "fmt.h"
#include "mutex.h"
#include "thread.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

#define PAYLOAD_TLS_SIZE 1256

static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context);
static void _resp_handler(unsigned req_state, coap_pkt_t* pdu,
                          sock_udp_ep_t *remote);
static ssize_t _atls_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx);

mutex_t server_lock = MUTEX_INIT_LOCKED;
mutex_t client_lock = MUTEX_INIT_LOCKED;
mutex_t server_req_lock = MUTEX_INIT_LOCKED;
mutex_t client_send_lock = MUTEX_INIT_LOCKED;

kernel_pid_t main_pid;

char payload_tls[PAYLOAD_TLS_SIZE];
int size_payload = 0;

unsigned char last_post = 0;
unsigned char last_get = 0;

/* CoAP resources. Must be sorted by path (ASCII order). */
static const coap_resource_t _resources[] = {
    { "/.well-known/atls", COAP_GET | COAP_POST, _atls_handler, NULL},
};

static const char *_link_params[] = {
    ";ct=0;rt=\"count\"",
    NULL
};

static gcoap_listener_t _listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    _encode_link,
    NULL
};

/* Retain request path to re-request if response includes block. User must not
 * start a new request (with a new path) until any blockwise transfer
 * completes or times out. */
#define _LAST_REQ_PATH_MAX (32)
static char _last_req_path[_LAST_REQ_PATH_MAX];

/* Counts requests sent by CLI. */
static uint16_t req_count = 0;

/* Adds link format params to resource list */
static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context) {
    ssize_t res = gcoap_encode_link(resource, buf, maxlen, context);
    if (res > 0) {
        if (_link_params[context->link_pos]
                && (strlen(_link_params[context->link_pos]) < (maxlen - res))) {
            if (buf) {
                memcpy(buf+res, _link_params[context->link_pos],
                       strlen(_link_params[context->link_pos]));
            }
            return res + strlen(_link_params[context->link_pos]);
        }
    }

    return res;
}

/*
 * Response callback.
 */
static void _resp_handler(unsigned req_state, coap_pkt_t* pdu,
                          sock_udp_ep_t *remote)
{
    (void)remote;       /* not interested in the source currently */

    if (req_state == GCOAP_MEMO_TIMEOUT) {
        printf("gcoap: timeout for msg ID %02u\n", coap_get_id(pdu));
        
        /*retry
        if(last_post) coap_post();
        else if (last_get) coap_get();
        */
        
        return;
    }
    else if (req_state == GCOAP_MEMO_ERR) {
        printf("gcoap: error in response\n");
        return;
    }

    coap_block1_t block;
    if (coap_get_block2(pdu, &block) && block.blknum == 0) {
        puts("--- blockwise start ---");
    }

    char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                            ? "Success" : "Error";
    printf("gcoap: response %s, code %1u.%02u\n", class_str,
                                                coap_get_code_class(pdu),
                                                coap_get_code_detail(pdu));
    if (pdu->payload_len) {
        unsigned content_type = coap_get_content_type(pdu);
        if (content_type == COAP_FORMAT_TEXT
                || content_type == COAP_FORMAT_LINK
                || coap_get_code_class(pdu) == COAP_CLASS_CLIENT_FAILURE
                || coap_get_code_class(pdu) == COAP_CLASS_SERVER_FAILURE) {
            /* Expecting diagnostic payload in failure cases */
            int i;

            // TODO: maybe we have to reset to 0 the payload everytime?
            memset(payload_tls,0,PAYLOAD_TLS_SIZE);
            memcpy(payload_tls,pdu->payload,pdu->payload_len);
            size_payload = pdu->payload_len;

            mutex_unlock(&client_lock);
        }
        else {
            printf(", %u bytes\n", pdu->payload_len);
            od_hex_dump(pdu->payload, pdu->payload_len, OD_WIDTH_DEFAULT);
        }
    }
    else {
        mutex_unlock(&client_send_lock);
        printf(", empty payload\n");
    }

    /* ask for next block if present */
    if (coap_get_block2(pdu, &block)) {
        if (block.more) {
            unsigned msg_type = coap_get_type(pdu);
            if (block.blknum == 0 && !strlen(_last_req_path)) {
                puts("Path too long; can't complete blockwise");
                return;
            }

            gcoap_req_init(pdu, (uint8_t *)pdu->hdr, GCOAP_PDU_BUF_SIZE,
                           COAP_METHOD_GET, _last_req_path);
            if (msg_type == COAP_TYPE_ACK) {
                coap_hdr_set_type(pdu->hdr, COAP_TYPE_CON);
            }
            block.blknum++;
            coap_opt_add_block2_control(pdu, &block);
            int len = coap_opt_finish(pdu, COAP_OPT_FINISH_NONE);
            gcoap_req_send((uint8_t *)pdu->hdr, len, remote, _resp_handler);
        }
        else {
            puts("--- blockwise complete ---");
        }
    }
}

// Will be used only from the server right now
static ssize_t _atls_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    size_t paylen;

    main_pid = thread_getpid();

    /* read coap method type in packet */
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    switch(method_flag) {
        case COAP_GET:
            mutex_unlock_and_sleep(&server_req_lock);
            break;
        case COAP_POST:
            memcpy(payload_tls, (char *) pdu->payload, pdu->payload_len);
            size_payload = pdu->payload_len;
            mutex_unlock(&server_req_lock);
            mutex_unlock_and_sleep(&server_lock);
            break;
    }

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CHANGED);

    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
    len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    paylen = size_payload;

    // The payload len tells how many bytes are free for the payload. If we have
    // enough space we can copy our message inside it.
    if (!paylen){
        printf("COAP replied %d bytes\n", len);
        return gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
    }
    else if (pdu->payload_len >= paylen) {
                memcpy(pdu->payload, payload_tls, paylen);
                len += paylen;
    } else {
        puts("gcoap_cli: msg buffer too small");
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }

    printf("COAP replied %d bytes\n", len);
    //NO NEED FOR GCOAP_RESPONSE, that is only for empty payloads
    return len;
}

size_t _send(uint8_t *buf, size_t len, char *addr_str, char *port_str)
{
    ipv6_addr_t addr;
    size_t bytes_sent;
    sock_udp_ep_t remote;

    remote.family = AF_INET6;

    /* parse for interface */
    int iface = ipv6_addr_split_iface(addr_str);
    if (iface == -1) {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
        else {
            remote.netif = SOCK_ADDR_ANY_NETIF;
        }
    }
    else {
        if (gnrc_netif_get_by_pid(iface) == NULL) {
            puts("gcoap_cli: interface not valid");
            return 0;
        }
        remote.netif = iface;
    }

    /* parse destination address */
    if (ipv6_addr_from_str(&addr, addr_str) == NULL) {
        puts("gcoap_cli: unable to parse destination address");
        return 0;
    }
    if ((remote.netif == SOCK_ADDR_ANY_NETIF) && ipv6_addr_is_link_local(&addr)) {
        puts("gcoap_cli: must specify interface for link local target");
        return 0;
    }
    memcpy(&remote.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));

    /* parse port */
    remote.port = atoi(port_str);
    if (remote.port == 0) {
        puts("gcoap_cli: unable to parse destination port");
        return 0;
    }

    bytes_sent = gcoap_req_send(buf, len, &remote, _resp_handler);
    if (bytes_sent > 0) {
        req_count++;
    }

    printf("COAP sent %d bytes\n", bytes_sent);

    return bytes_sent;
}

void gcoap_cli_init(void)
{
    gcoap_register_listener(&_listener);
}