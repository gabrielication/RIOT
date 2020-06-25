#include <stddef.h>
#include "random.h"

#ifdef MODULE_PERIPH_HWRNG
#include "periph/hwrng.h"
#endif

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);