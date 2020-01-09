#include "alt_features.h"
#include "timing_alt.h"

//MBEDTLS_ENTROPY_HARDWARE_ALT

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    ((void) data);

    hwrng_read((void*) output, len);

    *olen = len;

    return 0;
}

volatile int mbedtls_timing_alarmed = 0;

unsigned long mbedtls_timing_hardclock(void)
{
    return 0;
}

unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val, int reset)
{
    return 0;
}

void mbedtls_set_alarm(int seconds){
    return;
}

void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
    return;
}

int mbedtls_timing_get_delay(void *data)
{
    return 0;
}