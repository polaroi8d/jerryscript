/* Copyright JS Foundation and other contributors, http://js.foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SHA-1 standard was published by NIST in 1993.
 *
 *  http://www.itl.nist.gov/fipspubs/fip180-1.htm
 */

#ifdef JERRY_DEBUGGER

#include "jerry-debugger.h"
#include "jmem-allocator.h"

/**
 * SHA-1 context structure
 */
typedef struct
{
    uint32_t total[2];          /**< number of bytes processed  */
    uint32_t state[5];          /**< intermediate digest state  */
    uint8_t buffer[64];   /**< data block being processed */
}
jerry_sha1_context;

/* 32-bit integer manipulation macros (big endian) */

#define GET_UINT32_BE(n, b, i) \
{ \
  (n) = (((uint32_t) (b)[(i) + 0]) << 24) \
        | (((uint32_t) (b)[(i) + 1]) << 16) \
        | (((uint32_t) (b)[(i) + 2]) << 8) \
        | ((uint32_t) (b)[(i) + 3]); \
}

#define PUT_UINT32_BE(n, b, i) \
{ \
  (b)[(i) + 0] = (uint8_t) ((n) >> 24); \
  (b)[(i) + 1] = (uint8_t) ((n) >> 16); \
  (b)[(i) + 2] = (uint8_t) ((n) >> 8); \
  (b)[(i) + 3] = (uint8_t) ((n)); \
}

/**
 * Initialize SHA-1 context.
 */
static void
jerry_sha1_init (jerry_sha1_context *sha1_context_p) /**< SHA-1 context */
{
  memset (sha1_context_p, 0, sizeof (jerry_sha1_context));

  sha1_context_p->total[0] = 0;
  sha1_context_p->total[1] = 0;

  sha1_context_p->state[0] = 0x67452301;
  sha1_context_p->state[1] = 0xEFCDAB89;
  sha1_context_p->state[2] = 0x98BADCFE;
  sha1_context_p->state[3] = 0x10325476;
  sha1_context_p->state[4] = 0xC3D2E1F0;
} /* jerry_sha1_init */

/**
 * Update SHA-1 internal buffer status.
 */
static void
jerry_sha1_process (jerry_sha1_context *sha1_context_p, /**< SHA-1 context */
                    const uint8_t data[64]) /**< data buffer */
{
  uint32_t temp, W[16], A, B, C, D, E;

  GET_UINT32_BE(W[0], data, 0);
  GET_UINT32_BE(W[1], data, 4);
  GET_UINT32_BE(W[2], data, 8);
  GET_UINT32_BE(W[3], data, 12);
  GET_UINT32_BE(W[4], data, 16);
  GET_UINT32_BE(W[5], data, 20);
  GET_UINT32_BE(W[6], data, 24);
  GET_UINT32_BE(W[7], data, 28);
  GET_UINT32_BE(W[8], data, 32);
  GET_UINT32_BE(W[9], data, 36);
  GET_UINT32_BE(W[10], data, 40);
  GET_UINT32_BE(W[11], data, 44);
  GET_UINT32_BE(W[12], data, 48);
  GET_UINT32_BE(W[13], data, 52);
  GET_UINT32_BE(W[14], data, 56);
  GET_UINT32_BE(W[15], data, 60);

#define SHIFT(x, n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t) \
( \
  temp = W[(t - 3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ W[(t - 14) & 0x0F] ^ W[t & 0x0F], \
  W[t & 0x0F] = SHIFT(temp, 1) \
)

#define P(a, b, c, d, e, x) \
{ \
  e += SHIFT(a, 5) + F(b, c, d) + K + x; \
  b = SHIFT(b, 30); \
}

  A = sha1_context_p->state[0];
  B = sha1_context_p->state[1];
  C = sha1_context_p->state[2];
  D = sha1_context_p->state[3];
  E = sha1_context_p->state[4];

  uint32_t K = 0x5A827999;

#define F(x, y, z) (z ^ (x & (y ^ z)))

  P(A, B, C, D, E, W[0]);
  P(E, A, B, C, D, W[1]);
  P(D, E, A, B, C, W[2]);
  P(C, D, E, A, B, W[3]);
  P(B, C, D, E, A, W[4]);
  P(A, B, C, D, E, W[5]);
  P(E, A, B, C, D, W[6]);
  P(D, E, A, B, C, W[7]);
  P(C, D, E, A, B, W[8]);
  P(B, C, D, E, A, W[9]);
  P(A, B, C, D, E, W[10]);
  P(E, A, B, C, D, W[11]);
  P(D, E, A, B, C, W[12]);
  P(C, D, E, A, B, W[13]);
  P(B, C, D, E, A, W[14]);
  P(A, B, C, D, E, W[15]);
  P(E, A, B, C, D, R(16));
  P(D, E, A, B, C, R(17));
  P(C, D, E, A, B, R(18));
  P(B, C, D, E, A, R(19));

#undef F

  K = 0x6ED9EBA1;

#define F(x, y, z) (x ^ y ^ z)

  P(A, B, C, D, E, R(20));
  P(E, A, B, C, D, R(21));
  P(D, E, A, B, C, R(22));
  P(C, D, E, A, B, R(23));
  P(B, C, D, E, A, R(24));
  P(A, B, C, D, E, R(25));
  P(E, A, B, C, D, R(26));
  P(D, E, A, B, C, R(27));
  P(C, D, E, A, B, R(28));
  P(B, C, D, E, A, R(29));
  P(A, B, C, D, E, R(30));
  P(E, A, B, C, D, R(31));
  P(D, E, A, B, C, R(32));
  P(C, D, E, A, B, R(33));
  P(B, C, D, E, A, R(34));
  P(A, B, C, D, E, R(35));
  P(E, A, B, C, D, R(36));
  P(D, E, A, B, C, R(37));
  P(C, D, E, A, B, R(38));
  P(B, C, D, E, A, R(39));

#undef F

  K = 0x8F1BBCDC;

#define F(x, y, z) ((x & y) | (z & (x | y)))

  P(A, B, C, D, E, R(40));
  P(E, A, B, C, D, R(41));
  P(D, E, A, B, C, R(42));
  P(C, D, E, A, B, R(43));
  P(B, C, D, E, A, R(44));
  P(A, B, C, D, E, R(45));
  P(E, A, B, C, D, R(46));
  P(D, E, A, B, C, R(47));
  P(C, D, E, A, B, R(48));
  P(B, C, D, E, A, R(49));
  P(A, B, C, D, E, R(50));
  P(E, A, B, C, D, R(51));
  P(D, E, A, B, C, R(52));
  P(C, D, E, A, B, R(53));
  P(B, C, D, E, A, R(54));
  P(A, B, C, D, E, R(55));
  P(E, A, B, C, D, R(56));
  P(D, E, A, B, C, R(57));
  P(C, D, E, A, B, R(58));
  P(B, C, D, E, A, R(59));

#undef F

  K = 0xCA62C1D6;

#define F(x, y, z) (x ^ y ^ z)

  P(A, B, C, D, E, R(60));
  P(E, A, B, C, D, R(61));
  P(D, E, A, B, C, R(62));
  P(C, D, E, A, B, R(63));
  P(B, C, D, E, A, R(64));
  P(A, B, C, D, E, R(65));
  P(E, A, B, C, D, R(66));
  P(D, E, A, B, C, R(67));
  P(C, D, E, A, B, R(68));
  P(B, C, D, E, A, R(69));
  P(A, B, C, D, E, R(70));
  P(E, A, B, C, D, R(71));
  P(D, E, A, B, C, R(72));
  P(C, D, E, A, B, R(73));
  P(B, C, D, E, A, R(74));
  P(A, B, C, D, E, R(75));
  P(E, A, B, C, D, R(76));
  P(D, E, A, B, C, R(77));
  P(C, D, E, A, B, R(78));
  P(B, C, D, E, A, R(79));

#undef F

  sha1_context_p->state[0] += A;
  sha1_context_p->state[1] += B;
  sha1_context_p->state[2] += C;
  sha1_context_p->state[3] += D;
  sha1_context_p->state[4] += E;

#undef SHIFT
#undef R
#undef P
} /* jerry_sha1_process */

/**
 * SHA-1 update buffer
 */
static void
jerry_sha1_update (jerry_sha1_context *sha1_context_p, /**< SHA-1 context */
                   const uint8_t *source_p, /**< source buffer */
                   size_t source_length) /**< length of source buffer */
{
  size_t fill;
  uint32_t left;

  if (source_length == 0)
  {
    return;
  }

  left = sha1_context_p->total[0] & 0x3F;
  fill = 64 - left;

  sha1_context_p->total[0] += (uint32_t) source_length;

  /* Check overflow. */
  if (sha1_context_p->total[0] < (uint32_t) source_length)
  {
    sha1_context_p->total[1]++;
  }

  if (left && source_length >= fill)
  {
    memcpy ((void *) (sha1_context_p->buffer + left), source_p, fill);
    jerry_sha1_process (sha1_context_p, sha1_context_p->buffer);
    source_p += fill;
    source_length -= fill;
    left = 0;
  }

  while (source_length >= 64)
  {
    jerry_sha1_process (sha1_context_p, source_p);
    source_p += 64;
    source_length -= 64;
  }

  if (source_length > 0)
  {
    memcpy((void *) (sha1_context_p->buffer + left), source_p, source_length);
  }
} /* jerry_sha1_update */

/**
 * SHA-1 final digest.
 */
static void
jerry_sha1_finish (jerry_sha1_context *sha1_context_p, /**< SHA-1 context */
                   uint8_t destination_p[20]) /**< result */
{
  uint8_t buffer[16];

  uint32_t high = (sha1_context_p->total[0] >> 29) | (sha1_context_p->total[1] << 3);
  uint32_t low = (sha1_context_p->total[0] << 3);

  uint32_t last = sha1_context_p->total[0] & 0x3F;
  uint32_t padn = (last < 56) ? (56 - last) : (120 - last);

  memset (buffer, 0, sizeof(buffer));
  buffer[0] = 0x80;

  while (padn > sizeof(buffer))
  {
    jerry_sha1_update (sha1_context_p, buffer, sizeof(buffer));
    buffer[0] = 0;
    padn -= (uint32_t) sizeof(buffer);
  }

  jerry_sha1_update (sha1_context_p, buffer, padn);

  PUT_UINT32_BE (high, buffer, 0);
  PUT_UINT32_BE (low, buffer, 4);

  jerry_sha1_update (sha1_context_p, buffer, 8);

  PUT_UINT32_BE (sha1_context_p->state[0], destination_p, 0);
  PUT_UINT32_BE (sha1_context_p->state[1], destination_p, 4);
  PUT_UINT32_BE (sha1_context_p->state[2], destination_p, 8);
  PUT_UINT32_BE (sha1_context_p->state[3], destination_p, 12);
  PUT_UINT32_BE (sha1_context_p->state[4], destination_p, 16);
} /* jerry_sha1_finish */

#undef GET_UINT32_BE
#undef PUT_UINT32_BE

/*
 * Computes the SHA-1 value of the combination of the two input buffers.
 */
void
jerry_debugger_compute_sha1 (const uint8_t *source1_p, /**< first part of the input */
                             size_t source1_length, /**< length of the first part */
                             const uint8_t *source2_p, /**< second part of the input */
                             size_t source2_length, /**< length of the second part */
                             uint8_t destination_p[20]) /**< result */
{
  JMEM_DEFINE_LOCAL_ARRAY (sha1_context_p, 1, jerry_sha1_context);

  jerry_sha1_init (sha1_context_p);
  jerry_sha1_update (sha1_context_p, source1_p, source1_length);
  jerry_sha1_update (sha1_context_p, source2_p, source2_length);
  jerry_sha1_finish (sha1_context_p, destination_p);

  JMEM_FINALIZE_LOCAL_ARRAY (sha1_context_p);
} /* jerry_debugger_compute_sha1 */

#endif /* JERRY_DEBUGGER */
