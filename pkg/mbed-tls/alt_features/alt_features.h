#include <stddef.h>
#include "periph/hwrng.h"

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);