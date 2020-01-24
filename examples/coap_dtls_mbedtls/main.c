#include <stdio.h>
#include <string.h>

#include "net/gcoap.h"

#include "shell.h"

#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern void gcoap_cli_init(void);

extern int start_client(int argc, char **argv);
extern int start_server(int argc, char **argv);

static const shell_command_t commands[] = {
    { "dtlsc", "Start mbedtls client", start_client},
    { "dtlss", "Start mbedtls server", start_server},
    { NULL, NULL, NULL }
};

int main(void)
{
    /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    gcoap_cli_init();

    puts("Mbed ADTLS example");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}