/* From RFC1320 */

/* MD4C.C - RSA Data Security, Inc., MD4 message-digest algorithm
 */

/* Copyright (C) 1990-2, RSA Data Security, Inc. All rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

#ifdef USMB2_FEATURE_NTLM

#include <stdint.h>
#include <string.h>

#include "md4.h"

/* Modified for size: the three rounds are one loop, as in md5.c, and the
 * bit count only has 32 bits. The input is a password, never 512 Mbyte.
 */

/* F, G and H are basic MD4 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* Shift amounts, four for each round */
static const unsigned char S[12] = {3, 7, 11, 19,  3, 5, 9, 13,  3, 9, 11, 15};

/* The order round 3 takes the words of the block in */
static const unsigned char R3[16] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};

/* MD4 initialization. Begins an MD4 operation, writing a new context.
 */
void MD4Init(MD4_CTX *context)
{
  context->count[0] = context->count[1] = 0;

  /* Load magic initialization constants.
   */
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD4 basic transformation. Transforms state based on block.
 */
static void MD4Transform(uint32_t state[4], unsigned char block[64])
{
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16], t;
  unsigned int i, k;

  /* Decode the block into 32 bit little-endian words */
  for (i = 0; i < 16; i++, block += 4)
    x[i] = ((uint32_t)block[0]) | (((uint32_t)block[1]) << 8) |
      (((uint32_t)block[2]) << 16) | (((uint32_t)block[3]) << 24);

  for (i = 0; i < 48; i++) {
    switch (i >> 4) {
    case 0:
      t = F(b, c, d);
      k = i;
      break;
    case 1:
      t = G(b, c, d) + 0x5a827999;
      k = ((i & 3) << 2) | ((i >> 2) & 3);
      break;
    default:
      t = H(b, c, d) + 0x6ed9eba1;
      k = R3[i & 15];
      break;
    }
    /* a = (a + f(b, c, d) + x[k]) <<< s, then rotate the names a, b, c, d */
    t += a + x[k];
    a = d;
    d = c;
    c = b;
    b = ROTATE_LEFT(t, S[((i >> 2) & 0x0c) | (i & 3)]);
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

/* MD4 block update operation. Continues an MD4 message-digest
     operation, processing another message block, and updating the
     context.
 */
void MD4Update(MD4_CTX *context, unsigned char *input, unsigned int inputLen)
{
  unsigned int index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int)((context->count[0] >> 3) & 0x3F);
  /* Update number of bits */
  context->count[0] += (uint32_t)inputLen << 3;

  partLen = 64 - index;

  /* Transform as many times as possible.
   */
  while (inputLen >= partLen) {
    memcpy(&context->buffer[index], input, partLen);
    MD4Transform(context->state, context->buffer);
    input += partLen;
    inputLen -= partLen;
    index = 0;
    partLen = 64;
  }

  /* Buffer remaining input */
  memcpy(&context->buffer[index], input, inputLen);
}

/* MD4 finalization. Ends an MD4 message-digest operation, writing the
     the message digest.
 */
void MD4Final(unsigned char digest[16], MD4_CTX *context)
{
  uint32_t bits = context->count[0];
  unsigned char c = 0x80;
  unsigned int i;

  /* Pad out to 56 mod 64 with a one bit and then zeros
   */
  do {
    MD4Update(context, &c, 1);
    c = 0;
  } while (((context->count[0] >> 3) & 0x3f) != 56);

  /* Append the length in bits before padding, 64 bits little-endian */
  for (i = 0; i < 8; i++, bits >>= 8) {
    c = bits;
    MD4Update(context, &c, 1);
  }

  /* Store state in digest */
  for (i = 0; i < 16; i++)
    digest[i] = context->state[i >> 2] >> ((i & 3) << 3);
}

#endif /* USMB2_FEATURE_NTLM */
