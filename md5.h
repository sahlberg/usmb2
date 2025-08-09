/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifdef USMB2_FEATURE_NTLM

#ifndef MD5_H
#define MD5_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

struct MD5Context {
    uint64_t size;        // Size of input in bytes
    uint32_t buffer[4];   // Current accumulation of hash
    uint8_t input[64];    // Input to be used in the next step
    uint8_t digest[16];   // Result of algorithm
};

void md5Init(struct MD5Context *ctx);
void md5Update(struct MD5Context *ctx, uint8_t *input, size_t input_len);
void md5Finalize(struct MD5Context *ctx);
void md5Step(uint32_t *buffer, uint32_t *input);

#endif

#endif /* USMB2_FEATURE_NTLM */
