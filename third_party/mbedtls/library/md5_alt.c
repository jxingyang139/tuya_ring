/*
 *  RFC 1321 compliant MD5 implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  This file is provided under the Apache License 2.0, or the
 *  GNU General Public License v2.0 or later.
 *
 *  **********
 *  Apache License 2.0:
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  **********
 *
 *  **********
 *  GNU General Public License v2.0 or later:
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  **********
 */
/*
 *  The MD5 algorithm was designed by Ron Rivest in 1991.
 *
 *  http://www.ietf.org/rfc/rfc1321.txt
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MD5_C)

#include "mbedtls/md5.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */
#if defined(MBEDTLS_MD5_ALT)

/*
 * 32-bit integer manipulation macros (little endian)
 */
static void GET_UINT32_LE(uint32_t* n, const unsigned char* b, size_t i)
{
    (*n) = ( (uint32_t) (b)[(i)    ]       )
        | ( (uint32_t) (b)[(i) + 1] <<  8 )
        | ( (uint32_t) (b)[(i) + 2] << 16 )
        | ( (uint32_t) (b)[(i) + 3] << 24 );
}

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

void mbedtls_md5_init( mbedtls_md5_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_md5_context ) );
}

void mbedtls_md5_free( mbedtls_md5_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_md5_context ) );
}

void mbedtls_md5_clone( mbedtls_md5_context *dst,
                        const mbedtls_md5_context *src )
{
    *dst = *src;
}

/*
 * MD5 context setup
 */
int mbedtls_md5_starts_ret( mbedtls_md5_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_starts( mbedtls_md5_context *ctx )
{
    mbedtls_md5_starts_ret( ctx );
}
#endif

#if !defined(MBEDTLS_MD5_PROCESS_ALT)
int mbedtls_internal_md5_process( mbedtls_md5_context *ctx,
                                  const unsigned char data[64] )
{
    struct
    {
        uint32_t X[16], A, B, C, D;
    } local;

    for (int i = 0; i < 16; i++)
        GET_UINT32_LE( &local.X[i], data, i * 4 );

#define S(x,n)                                                          \
    ( ( (x) << (n) ) | ( ( (x) & 0xFFFFFFFF) >> ( 32 - (n) ) ) )

#define P(a,b,c,d,k,s,t)                                                \
    do                                                                  \
    {                                                                   \
        (a) += F((b),(c),(d)) + local.X[(k)] + (t);                     \
        (a) = S((a),(s)) + (b);                                         \
    } while( 0 )

    local.A = ctx->state[0];
    local.B = ctx->state[1];
    local.C = ctx->state[2];
    local.D = ctx->state[3];

#define F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
    {
        uint32_t t[16] = {
            0xD76AA478,0xE8C7B756,0x242070DB,0xC1BDCEEE,
            0xF57C0FAF,0x4787C62A,0xA8304613,0xFD469501,
            0x698098D8,0x8B44F7AF,0xFFFF5BB1,0x895CD7BE,
            0x6B901122,0xFD987193,0xA679438E,0x49B40821
        };
        unsigned char s[4] = { 7, 12, 17, 22 };
        unsigned char i;
        for (i = 0; i < 4; i++)
        {
            P( local.A, local.B, local.C, local.D, i * 4 + 0, s[0], t[i * 4 + 0] );
            P( local.D, local.A, local.B, local.C, i * 4 + 1, s[1], t[i * 4 + 1] );
            P( local.C, local.D, local.A, local.B, i * 4 + 2, s[2], t[i * 4 + 2] );
            P( local.B, local.C, local.D, local.A, i * 4 + 3, s[3], t[i * 4 + 3] );
        }
    }
#undef F

#define F(x,y,z) ((y) ^ ((z) & ((x) ^ (y))))
    {
        uint32_t t[16] = {
            0xF61E2562,0xC040B340,0x265E5A51,0xE9B6C7AA,
            0xD62F105D,0x02441453,0xD8A1E681,0xE7D3FBC8,
            0x21E1CDE6,0xC33707D6,0xF4D50D87,0x455A14ED,
            0xA9E3E905,0xFCEFA3F8,0x676F02D9,0x8D2A4C8A
        };
        unsigned char s[4] = { 5, 9, 14, 20 };
        unsigned char i;
        for (i = 0; i < 4; i++)
        {
            P( local.A, local.B, local.C, local.D, (i * 4 + 1)  & 0xF, s[0], t[i * 4 + 0] );
            P( local.D, local.A, local.B, local.C, (i * 4 + 6)  & 0xF, s[1], t[i * 4 + 1] );
            P( local.C, local.D, local.A, local.B, (i * 4 + 11) & 0xF, s[2], t[i * 4 + 2] );
            P( local.B, local.C, local.D, local.A, (i * 4 + 0)  & 0xF, s[3], t[i * 4 + 3] );
        }
    }
#undef F

#define F(x,y,z) ((x) ^ (y) ^ (z))
    {
        uint32_t t[16] = {
            0xFFFA3942,0x8771F681,0x6D9D6122,0xFDE5380C,
            0xA4BEEA44,0x4BDECFA9,0xF6BB4B60,0xBEBFBC70,
            0x289B7EC6,0xEAA127FA,0xD4EF3085,0x04881D05,
            0xD9D4D039,0xE6DB99E5,0x1FA27CF8,0xC4AC5665
        };
        unsigned char s[4] = { 4, 11, 16, 23 };
        unsigned char i;
        for (i = 0; i < 4; i++)
        {
            P( local.A, local.B, local.C, local.D, (i * 12 + 5)  & 0xF, s[0], t[i * 4 + 0] );
            P( local.D, local.A, local.B, local.C, (i * 12 + 8)  & 0xF, s[1], t[i * 4 + 1] );
            P( local.C, local.D, local.A, local.B, (i * 12 + 11) & 0xF, s[2], t[i * 4 + 2] );
            P( local.B, local.C, local.D, local.A, (i * 12 + 14) & 0xF, s[3], t[i * 4 + 3] );
        }
    }
#undef F

#define F(x,y,z) ((y) ^ ((x) | ~(z)))
    {
        uint32_t t[16] = {
            0xF4292244,0x432AFF97,0xAB9423A7,0xFC93A039,
            0x655B59C3,0x8F0CCC92,0xFFEFF47D,0x85845DD1,
            0x6FA87E4F,0xFE2CE6E0,0xA3014314,0x4E0811A1,
            0xF7537E82,0xBD3AF235,0x2AD7D2BB,0xEB86D391
        };
        unsigned char s[4] = { 6, 10, 15, 21 };
        unsigned char i;
        for (i = 0; i < 4; i++)
        {
            P( local.A, local.B, local.C, local.D, (i * 12 + 0)  & 0xF, s[0], t[i * 4 + 0] );
            P( local.D, local.A, local.B, local.C, (i * 12 + 7)  & 0xF, s[1], t[i * 4 + 1] );
            P( local.C, local.D, local.A, local.B, (i * 12 + 14) & 0xF, s[2], t[i * 4 + 2] );
            P( local.B, local.C, local.D, local.A, (i * 12 + 5)  & 0xF, s[3], t[i * 4 + 3] );
        }
    }
#undef F

    ctx->state[0] += local.A;
    ctx->state[1] += local.B;
    ctx->state[2] += local.C;
    ctx->state[3] += local.D;

    /* Zeroise variables to clear sensitive data from memory. */
    mbedtls_platform_zeroize( &local, sizeof( local ) );

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_process( mbedtls_md5_context *ctx,
                          const unsigned char data[64] )
{
    mbedtls_internal_md5_process( ctx, data );
}
#endif
#endif /* !MBEDTLS_MD5_PROCESS_ALT */

/*
 * MD5 process buffer
 */
int mbedtls_md5_update_ret( mbedtls_md5_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{
    int ret;
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return( 0 );

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        if( ( ret = mbedtls_internal_md5_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        if( ( ret = mbedtls_internal_md5_process( ctx, input ) ) != 0 )
            return( ret );

        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left), input, ilen );
    }

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_update( mbedtls_md5_context *ctx,
                         const unsigned char *input,
                         size_t ilen )
{
    mbedtls_md5_update_ret( ctx, input, ilen );
}
#endif

/*
 * MD5 final digest
 */
int mbedtls_md5_finish_ret( mbedtls_md5_context *ctx,
                            unsigned char output[16] )
{
    int ret;
    uint32_t used;
    uint32_t high, low;

    /*
     * Add padding: 0x80 then 0x00 until 8 bytes remain for the length
     */
    used = ctx->total[0] & 0x3F;

    ctx->buffer[used++] = 0x80;

    if( used <= 56 )
    {
        /* Enough room for padding + length in current block */
        memset( ctx->buffer + used, 0, 56 - used );
    }
    else
    {
        /* We'll need an extra block */
        memset( ctx->buffer + used, 0, 64 - used );

        if( ( ret = mbedtls_internal_md5_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        memset( ctx->buffer, 0, 56 );
    }

    /*
     * Add message length
     */
    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_LE( low,  ctx->buffer, 56 );
    PUT_UINT32_LE( high, ctx->buffer, 60 );

    if( ( ret = mbedtls_internal_md5_process( ctx, ctx->buffer ) ) != 0 )
        return( ret );

    /*
     * Output final state
     */
    for (int i = 0; i <4; i++)
        PUT_UINT32_LE( ctx->state[i], output, i * 4 );

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_finish( mbedtls_md5_context *ctx,
                         unsigned char output[16] )
{
    mbedtls_md5_finish_ret( ctx, output );
}
#endif

#endif /* !MBEDTLS_MD5_ALT */

#endif /* MBEDTLS_MD5_C */
