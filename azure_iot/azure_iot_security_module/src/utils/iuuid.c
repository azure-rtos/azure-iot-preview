/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "asc_security_core/utils/irand.h"
#include "asc_security_core/utils/iuuid.h"

static bool _initialized = false;
static uint64_t _xorshift128plus(uint64_t *s);

static uint64_t _seed[2];


int iuuid_generate(uint8_t *buf_out)
{
    if (!_initialized)
    {
        _seed[0] = (uint64_t)irand_int() << 32 | irand_int();
        _seed[1] = (uint64_t)irand_int() << 32 | irand_int();

        _initialized = true;
    }

    union {
        uint8_t b[16];
        uint64_t word[2];
    } s;

    /* Get random. */
    s.word[0] = _xorshift128plus(_seed);
    s.word[1] = _xorshift128plus(_seed);

    memmove(buf_out, s.b, 16);

    return 0;
}

static uint64_t _xorshift128plus(uint64_t *s)
{
    /*  http://xorshift.di.unimi.it/xorshift128plus.c */
    uint64_t s1 = s[0];
    const uint64_t s0 = s[1];
    s[0] = s0;
    s1 ^= s1 << 23;
    s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    return s[1] + s0;
}