#include <stdio.h>
#include <string.h>

#include "shell.h"

extern int start_client(int argc, char **argv);
extern int start_server(int argc, char **argv);

static const shell_command_t commands[] = {
    { "client", "Start mbedtls client", start_client},
    { "server", "Start mbedtls server", start_server},
    { NULL, NULL, NULL }
};

int main(void)
{
    puts("Mbed TLS example");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}