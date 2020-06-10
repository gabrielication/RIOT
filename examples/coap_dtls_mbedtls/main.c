#include <stdio.h>
#include <string.h>

#include "net/gcoap.h"

#include "shell.h"

#ifdef MBED_HEAP_LOG
#include "mbedtls/config.h"
#endif

#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern void gcoap_cli_init(void);

extern int start_client(int argc, char **argv);
extern int start_server(int argc, char **argv);

static const shell_command_t commands[] = {
    { "tlsc", "Start mbedtls client", start_client},
    { "tlss", "Start mbedtls server", start_server},
    { NULL, NULL, NULL }
};

#ifdef MBEDTLS_PLATFORM_MEMORY
unsigned int mem_count = 0;
unsigned int mem_max = 0;

void* MyCalloc(size_t n, size_t size)
{
    void* p = NULL;
    unsigned int* p32;

    unsigned int tot_size = (n*size);

    //printf("n %d size %d tot_size %d\n",n,size,tot_size);

    p32 = malloc(tot_size + (sizeof(unsigned int) * 4));
    memset(p32, 0, tot_size + (sizeof(unsigned int) * 4));

    if(p32 != NULL){
        p32[0] = (unsigned int) tot_size;
        p = (void*)(p32 + 4);

        mem_count += tot_size;
        if(mem_count > mem_max){
            mem_max = mem_count;
        }
    }

    //printf("Alloc: %p -> %u COUNT %d MAX IS: %d\n", p, (unsigned int) tot_size , mem_count,mem_max);

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
#endif

int main(void)
{
    /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    gcoap_cli_init();

    puts("Mbed ATLS example");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}