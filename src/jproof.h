/*********************************************************************
* Filename:   jproof.h
* Author:     Bartholomew Joyce
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding JPROOF implementation.
*********************************************************************/

#ifndef JPROOF_H
#define JPROOF_H

#include "jhash.h"

#define JHASH_MAX_INPUT_LENGTH (1024 * 2147483648) // Size must not exceed 2TiB

typedef int JPROOF_INST;

typedef struct {
    size_t length;
    size_t range_in_point;
    size_t range_out_point;
    size_t payload_length;
    unsigned char* payload;
} JPROOF_VALUE;

typedef struct {
    int num_hashes;
    size_t hash_offsets[JHASH_MAX_COUNT];
    size_t head_in_point, head_size;
    size_t tail_in_point, tail_size;
} JPROOF_REQUEST;

typedef struct {
    JPROOF_REQUEST request;
    JPROOF_VALUE value;
} JPROOF_GENERATE_CTX;

typedef struct {
    const JPROOF_VALUE* value;

    // General info
    int num_hashes;
    int num_blocks_total;
    int num_blocks_region;
    size_t head_in_point, head_size;
    size_t tail_in_point, tail_size;

    // Verify state
    int program_size, program_counter;
    JPROOF_INST* program;
    unsigned char stack[JHASH_MAX_COUNT * SHA256_BLOCK_SIZE];
    int stack_idx;

    int state;
    SHA256_CTX sha_ctx;
    size_t input_length;

} JPROOF_VERIFY_CTX;

void jproof_generate_init(JPROOF_GENERATE_CTX* ctx, size_t length, size_t range_in_point, size_t range_out_point);
void jproof_generate_write_head(JPROOF_GENERATE_CTX* ctx, const unsigned char* data);
void jproof_generate_write_tail(JPROOF_GENERATE_CTX* ctx, const unsigned char* data);
void jproof_generate_write_hash(JPROOF_GENERATE_CTX* ctx, int idx, const unsigned char* data);
void jproof_generate_write_head_from_file(JPROOF_GENERATE_CTX* ctx, FILE* file);
void jproof_generate_write_tail_from_file(JPROOF_GENERATE_CTX* ctx, FILE* file);
void jproof_generate_write_hash_from_file(JPROOF_GENERATE_CTX* ctx, int idx, FILE* file);
void jproof_generate_write_hashes_from_file(JPROOF_GENERATE_CTX* ctx, FILE* file);

void jproof_verify_init(JPROOF_VERIFY_CTX* ctx, const JPROOF_VALUE* value);
void jproof_verify_update(JPROOF_VERIFY_CTX* ctx, const unsigned char* data, long len);
int  jproof_verify_check_error(JPROOF_VERIFY_CTX* ctx);
int  jproof_verify_final(JPROOF_VERIFY_CTX* ctx, JHASH_VALUE* value);
void jproof_verify_free(JPROOF_VERIFY_CTX* ctx);

int jproof_decode(const char* string, JPROOF_VALUE* value);
char* jproof_encode(const JPROOF_VALUE* value);
void jproof_value_free(JPROOF_VALUE* value);

#endif // JPROOF_H
