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

#include <stdio.h>
#include "msg.h"

#include "net/gcoap.h"
#include "kernel_types.h"
#include "shell.h"

#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern void gcoap_cli_init(void);
extern int start_dtls_client(int argc, char **argv);
extern int start_dtls_server(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "dtlsc", "ADTLS 1.2 Client example", start_dtls_client },
    { "dtlss", "ADTLS 1.2 Server example", start_dtls_server },
    { NULL, NULL, NULL }
};

#ifdef MODULE_WOLFSSL_XUSER

unsigned int mem_count = 0;
unsigned int mem_max = 0;

void* MyMalloc(size_t size)
{
    void* p = NULL;
    unsigned int* p32;

    p32 = malloc(size + sizeof(unsigned int) * 4);

    if(p32 != NULL){
        p32[0] = (unsigned int) size;
        p = (void*)(p32 + 4);

        mem_count += size;
        if(mem_count > mem_max){
            mem_max = mem_count;
        }
    }

    //printf("Alloc: %p -> %u COUNT %d MAX IS: %d\n", p, (unsigned int) size, mem_count,mem_max);

    return p;
}

void MyFree(void* ptr)
{
    unsigned int* p32 = (unsigned int*)ptr;

    if (ptr != NULL) {
        p32 -= 4;

        mem_count -= p32[0];
        if(mem_count > mem_max){
            mem_max = mem_count;
        }

        //printf("Free: %p -> %u COUNT %d MAX %d\n", ptr, p32[0], mem_count, mem_max);
        free(p32);
    }

}

void* MyRealloc(void* ptr, size_t size)
{
    void*   newp = NULL;
    unsigned int* p32;
    unsigned int* oldp32 = NULL;
    unsigned int  oldLen;

    if (ptr != NULL) {
        oldp32 = (unsigned int*)ptr;
        oldp32 -= 4;
        oldLen = oldp32[0];
    }

    p32 = realloc(oldp32, size + sizeof(unsigned int) * 4);

    if (p32 != NULL) {
        p32[0] = (unsigned int) size;
        newp = (void*)(p32 + 4);

        //printf("REAlloc: %p -> %u\n", newp, (unsigned int) size);
        if (ptr != NULL) {
            //printf("Free: %p -> %u\n", ptr, oldLen);
        }

        mem_count -= oldLen;
        mem_count += size;

        if(mem_count > mem_max){
            mem_max = mem_count;
        }
    }

    return newp;
}

#endif

int main(void)
{
    /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    gcoap_cli_init();
    puts("ADTLS 1.2 example app");

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should never be reached */
    return 0;
}
