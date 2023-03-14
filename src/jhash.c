/*********************************************************************
* Filename:   jhash.c
* Author:     Bartholomew Joyce
*********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "jhash.h"

static void jhash_push_hash(JHASH_CTX *ctx);
static void jhash_join_hashes(JHASH_CTX *ctx);

void jhash_init(JHASH_CTX *ctx) {
    sha256_init(&ctx->sha_ctx);
    ctx->length = 0;
    ctx->hash_count = 0;
    ctx->output_file = NULL;
    ctx->output_buffer = NULL;
}

void jhash_init_with_output_file(JHASH_CTX* ctx, FILE* output_file) {
    sha256_init(&ctx->sha_ctx);
    ctx->length = 0;
    ctx->hash_count = 0;
    ctx->output_file = output_file;
}

void jhash_init_with_output_buffer(JHASH_CTX* ctx, unsigned char* output_buffer, size_t output_buffer_size) {
    sha256_init(&ctx->sha_ctx);
    ctx->length = 0;
    ctx->hash_count = 0;
    ctx->output_file = NULL;
    ctx->output_buffer = output_buffer;
    ctx->output_buffer_size = output_buffer_size;
    ctx->output_buffer_length = 0;
}

void jhash_update(JHASH_CTX *ctx, const unsigned char* data, long len) {
    while (len > 0) {
        int space_remaining_in_block = JHASH_BLOCK_SIZE - ctx->length % JHASH_BLOCK_SIZE;

        // New data arriving fits in the current block
        if (len < space_remaining_in_block) {
            sha256_update(&ctx->sha_ctx, data, len);
            ctx->length += len;
            return;
        }

        // We have reached the end of the block, so we want to create the block hash
        sha256_update(&ctx->sha_ctx, data, space_remaining_in_block);
        ctx->length += space_remaining_in_block;

        len  -= space_remaining_in_block;
        data += space_remaining_in_block;

        jhash_push_hash(ctx);
        jhash_join_hashes(ctx);
    }
}

void jhash_final(JHASH_CTX* ctx, JHASH_VALUE* value) {

    // Finalise the final block, if it exists
    int final_block_size = ctx->length % JHASH_BLOCK_SIZE;
    if (final_block_size > 0) {
        jhash_push_hash(ctx);
    }

    // Tag the final hash with the highest level, and join all
    ctx->hash_levels[ctx->hash_count - 1] = JHASH_MAX_COUNT;
    jhash_join_hashes(ctx);

    // Construct result
    value->length = ctx->length;
    memcpy(value->payload, ctx->hashes, SHA256_BLOCK_SIZE);
}

size_t jhash_output_buffer_read(JHASH_CTX* ctx) {
    assert(ctx->output_buffer);
    size_t length = ctx->output_buffer_length;
    ctx->output_buffer_length = 0;
    return length;
}



void jhash_push_hash(JHASH_CTX *ctx) {
    assert(ctx->hash_count < JHASH_MAX_COUNT);
    unsigned char* hash_ptr = &ctx->hashes[ctx->hash_count * SHA256_BLOCK_SIZE];
    sha256_final(&ctx->sha_ctx, hash_ptr);
    sha256_init(&ctx->sha_ctx);
    ctx->hash_levels[ctx->hash_count] = 1;
    ctx->hash_count += 1;

    // Write to output file or buffer
    if (ctx->output_file) {
        fwrite(hash_ptr, 1, SHA256_BLOCK_SIZE, ctx->output_file);
    } else if (ctx->output_buffer) {
        assert(ctx->output_buffer_size - ctx->output_buffer_length >= SHA256_BLOCK_SIZE);
        memcpy(ctx->output_buffer + ctx->output_buffer_length, hash_ptr, SHA256_BLOCK_SIZE);
        ctx->output_buffer_length += SHA256_BLOCK_SIZE;
    }
}

void jhash_join_hashes(JHASH_CTX *ctx) {
    while (ctx->hash_count > 1) {

        // Inspect the two top most hashes, where B is the top most, and A is the one below.
        int a_level = ctx->hash_levels[ctx->hash_count - 2];
        int b_level = ctx->hash_levels[ctx->hash_count - 1];

        // If B's level is less than A's level, we cannot join these hashes
        if (b_level < a_level) {
            break;
        }

        // Hash the two top hashes together
        unsigned char* hash_ptr = &ctx->hashes[(ctx->hash_count - 2) * SHA256_BLOCK_SIZE];
        sha256_update(&ctx->sha_ctx, hash_ptr, 2 * SHA256_BLOCK_SIZE);
        sha256_final(&ctx->sha_ctx, hash_ptr);
        sha256_init(&ctx->sha_ctx);
        ctx->hash_count--;

        ctx->hash_levels[ctx->hash_count - 1] = b_level + 1;

        // Write to output file or buffer
        if (ctx->output_file) {
            fwrite(hash_ptr, 1, SHA256_BLOCK_SIZE, ctx->output_file);
        } else if (ctx->output_buffer) {
            assert(ctx->output_buffer_size - ctx->output_buffer_length >= SHA256_BLOCK_SIZE);
            memcpy(ctx->output_buffer + ctx->output_buffer_length, hash_ptr, SHA256_BLOCK_SIZE);
            ctx->output_buffer_length += SHA256_BLOCK_SIZE;
        }
    }
}
