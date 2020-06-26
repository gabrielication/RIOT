/*
 * Copyright (C) 2020 Gabriele Restuccia
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     pkg
 * @{
 *
 * @file
 * @brief       Alternative callbacks for Mbed TLS (1.3 prototype)
 *
 * @author      Gabriele Restuccia <grestuccia@cnit.it>
 *
 * @}
 */

#include "alt_features.h"
#include "timing_alt.h"

//MBEDTLS_ENTROPY_HARDWARE_ALT

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    ((void) data);

#ifdef MODULE_PERIPH_HWRNG
    hwrng_read((void*) output, len);
    *olen = len;
#else
    *output= random_uint32();
    *olen = 4;
#endif

    return 0;
}

//MBEDTLS_TIMING_ALT

struct _hr_time
{
    struct timeval start;
};

volatile int mbedtls_timing_alarmed = 0;

// Taken from original mbed-tls library/timing.c
unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val, int reset)
{
    unsigned long delta;
    struct timeval offset;
    struct _hr_time *t = (struct _hr_time *) val;

    gettimeofday( &offset, NULL );

    if( reset )
    {
        t->start.tv_sec  = offset.tv_sec;
        t->start.tv_usec = offset.tv_usec;
        return( 0 );
    }

    delta = ( offset.tv_sec  - t->start.tv_sec  ) * 1000
          + ( offset.tv_usec - t->start.tv_usec ) / 1000;

    return( delta );
}

#ifndef BOARD_NATIVE

static void handler(void *arg)
{
    mbedtls_timing_alarmed = 1;
}

#else

static void handler(int signum)
{
    mbedtls_timing_alarmed = 1;
    signal( signum, handler );
}

#endif


void mbedtls_set_alarm( int seconds )
{
    mbedtls_timing_alarmed = 0;
    #ifndef BOARD_NATIVE
        rtt_init();
        uint32_t ticks = rtt_get_counter() + RTT_SEC_TO_TICKS(seconds);
        rtt_set_alarm(ticks, handler, NULL);
    #else
        signal( SIGALRM, handler );
        alarm( seconds );
    #endif
}

// Taken from original mbed-tls library/timing.c
void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if( fin_ms != 0 )
        (void) mbedtls_timing_get_timer( &ctx->timer, 1 );
}

// Taken from original mbed-tls library/timing.c
int mbedtls_timing_get_delay(void *data)
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;
    unsigned long elapsed_ms;

    if( ctx->fin_ms == 0 )
        return( -1 );

    elapsed_ms = mbedtls_timing_get_timer( &ctx->timer, 0 );

    if( elapsed_ms >= ctx->fin_ms )
        return( 2 );

    if( elapsed_ms >= ctx->int_ms )
        return( 1 );

    return( 0 );
}

unsigned long mbedtls_timing_hardclock(void)
{
    //Not implemented right now
    return 0;
}