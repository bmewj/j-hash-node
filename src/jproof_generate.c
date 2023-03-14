/*********************************************************************
* Filename:   jproof_generate.c
* Author:     Bartholomew Joyce
*********************************************************************/

#include "jproof.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void traverse_node(JPROOF_GENERATE_CTX* ctx, int node_idx, int node_from, int node_to, int target_block_from, int target_block_to);
static int  largest_second_power(int value);

void jproof_generate_init(JPROOF_GENERATE_CTX* ctx, size_t length, size_t range_in_point, size_t range_out_point) {
    assert(length < JHASH_MAX_INPUT_LENGTH);
    assert(0 < range_in_point && range_in_point < range_out_point && range_out_point <= length);

    int num_blocks_total = length / JHASH_BLOCK_SIZE;
    if (length % JHASH_BLOCK_SIZE > 0) num_blocks_total++;

    int block_from = range_in_point  / JHASH_BLOCK_SIZE;
    int block_to   = range_out_point / JHASH_BLOCK_SIZE;
    if (block_to % JHASH_BLOCK_SIZE > 0) block_to++;

    // Prepare request
    ctx->request.num_hashes = 0;
    ctx->request.head_in_point = block_from * JHASH_BLOCK_SIZE;
    ctx->request.head_size     = range_in_point - ctx->request.head_in_point;
    ctx->request.tail_in_point = range_out_point;
    ctx->request.tail_size     = block_to * JHASH_BLOCK_SIZE - range_out_point;
    if (ctx->request.tail_in_point + ctx->request.tail_size > length) {
        ctx->request.tail_size = length - ctx->request.tail_in_point;
    }

    // Traverse merkle tree, and compute all hashes that will need to be embedded in the proof
    traverse_node(ctx, 0, 0, num_blocks_total, block_from, block_to);
    
    // Prepare value
    ctx->value.length = length;
    ctx->value.range_in_point = range_in_point;
    ctx->value.range_out_point = range_out_point;
    ctx->value.payload_length = ctx->request.head_size + ctx->request.tail_size + ctx->request.num_hashes * SHA256_BLOCK_SIZE;
    ctx->value.payload = (unsigned char*)malloc(ctx->value.payload_length);
}

void jproof_generate_write_head(JPROOF_GENERATE_CTX* ctx, const unsigned char* data) {
    memcpy(&ctx->value.payload[0], data, ctx->request.head_size);
}

void jproof_generate_write_tail(JPROOF_GENERATE_CTX* ctx, const unsigned char* data) {
    memcpy(&ctx->value.payload[ctx->request.head_size], data, ctx->request.tail_size);
}

void jproof_generate_write_hash(JPROOF_GENERATE_CTX* ctx, int idx, const unsigned char* data) {
    memcpy(&ctx->value.payload[ctx->request.head_size + ctx->request.tail_size + idx * SHA256_BLOCK_SIZE], data, SHA256_BLOCK_SIZE);
}

void jproof_generate_write_head_from_file(JPROOF_GENERATE_CTX* ctx, FILE* file) {
    fread(&ctx->value.payload[0], 1, ctx->request.head_size, file);
}

void jproof_generate_write_tail_from_file(JPROOF_GENERATE_CTX* ctx, FILE* file) {
    fread(&ctx->value.payload[ctx->request.head_size], 1, ctx->request.tail_size, file);
}

void jproof_generate_write_hash_from_file(JPROOF_GENERATE_CTX* ctx, int idx, FILE* file) {
    fread(&ctx->value.payload[ctx->request.head_size + ctx->request.tail_size + idx * SHA256_BLOCK_SIZE], 1, SHA256_BLOCK_SIZE, file);
}

void jproof_generate_write_hashes_from_file(JPROOF_GENERATE_CTX* ctx, FILE* file) {
    for (int i = 0; i < ctx->request.num_hashes; ++i) {
        fseek(file, ctx->request.hash_offsets[i], SEEK_SET);
        jproof_generate_write_hash_from_file(ctx, i, file);
    }
}

void traverse_node(JPROOF_GENERATE_CTX* ctx, int node_idx, int node_from, int node_to, int target_block_from, int target_block_to) {

    if (node_to <= target_block_from || node_from >= target_block_to) {
        // This node appears either before or after the target region, push the node's hash
        int num_hashes_in_node = (node_to - node_from) * 2 - 1;
        int hash_idx = node_idx + num_hashes_in_node - 1;
        size_t hash_offset = hash_idx * SHA256_BLOCK_SIZE;
        ctx->request.hash_offsets[ctx->request.num_hashes++] = hash_offset;
        return;
    }

    if (node_from >= target_block_from && node_to <= target_block_to) {
        // The target region covers this node and all its children, so we can ignore it
        return;
    }

    // This node doesn't quite cover the target yet -> split and recurse
    int split = largest_second_power(node_to - node_from);

    int node_l_from = node_from;
    int node_l_to   = node_from + split;
    int node_l_idx  = node_idx;

    int node_r_from = node_from + split;
    int node_r_to   = node_to;
    int node_r_idx  = node_idx + (2 * split - 1);

    traverse_node(ctx, node_l_idx, node_l_from, node_l_to, target_block_from, target_block_to);
    traverse_node(ctx, node_r_idx, node_r_from, node_r_to, target_block_from, target_block_to);
}

int largest_second_power(int value) {
    // This function determines the largest power of 2 that is strictly smaller than value
    int x = 0b01000000000000000000000000000000;
    if (value <= 1 || value > x) return 0;
    while (x >= value) x >>= 1;
    return x;
}
