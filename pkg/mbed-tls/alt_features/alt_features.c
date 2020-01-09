#include "alt_features.h"

//MBEDTLS_ENTROPY_HARDWARE_ALT

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    ((void) data);

    hwrng_read((void*) output, len);

    *olen = len;

    return 0;
}