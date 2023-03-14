/*********************************************************************
* Filename:   jhash.h
* Author:     Bartholomew Joyce
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding JHASH implementation.
*********************************************************************/

#ifndef JHASH_H
#define JHASH_H

#include <stdio.h>
#include "sha256.h"

#ifndef jhash_alloc
    #define jhash_alloc(size) malloc(size)
#endif

#ifndef jhash_realloc
    #define jhash_realloc(ptr, size) realloc(ptr, size)
#endif

#ifndef jhash_free
    #define jhash_free(ptr) free(ptr)
#endif

#define JHASH_BLOCK_SIZE      1024   // JHASH uses a default block size of 1024
#define JHASH_MAX_COUNT       40     // A depth of 40 allows for the generation of hashes of up to 1TiB
#define JHASH_DECODE_ERR      1

typedef struct {
    SHA256_CTX sha_ctx;
    size_t length;
    unsigned char hashes[JHASH_MAX_COUNT * SHA256_BLOCK_SIZE];
    char hash_levels[JHASH_MAX_COUNT];
    int hash_count;

    FILE* output_file;
    unsigned char* output_buffer;
    size_t output_buffer_size;
    size_t output_buffer_length;
} JHASH_CTX;

typedef struct {
    size_t length;
    unsigned char payload[SHA256_BLOCK_SIZE];
} JHASH_VALUE;

void jhash_init(JHASH_CTX* ctx);
void jhash_init_with_output_file(JHASH_CTX* ctx, FILE* output_file);
void jhash_init_with_output_buffer(JHASH_CTX* ctx, unsigned char* output_buffer, size_t output_buffer_size);
void jhash_update(JHASH_CTX* ctx, const unsigned char* data, long len);
void jhash_final(JHASH_CTX* ctx, JHASH_VALUE* value);

size_t jhash_output_buffer_read(JHASH_CTX* ctx);

char* jhash_encode(const JHASH_VALUE* value);
int   jhash_decode(const char* string, JHASH_VALUE* value);

#endif // JHASH_H
