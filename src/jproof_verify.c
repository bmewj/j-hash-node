/*********************************************************************
* Filename:   jproof_verify.c
* Author:     Bartholomew Joyce
* 
* JPROOF verify implementation. The implementation reads a parsed
* JPROOF_VALUE struct and compiles a short bytecode program with three
* opcodes: INST_PUSH_HASH(x) indicating for a hash from the JPROOF
* payload to be pushed onto the stack, INST_COMPUTE_HASH indicating for
* the top two hashes to be popped, hashed and the result pushed back
* onto the stack, and INST_PUSH_BLOCK indicating for a block of bytes
* from the input to be hashed and pushed onto the stack.
* 
*********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "jproof.h"

#define INST_PUSH_HASH(x)  x
#define INST_COMPUTE_HASH -1
#define INST_PUSH_BLOCK   -2

#define STATE_NEED_INPUT   0
#define STATE_FINISHED     1
#define STATE_ERROR        2

static void traverse_node(JPROOF_VERIFY_CTX* ctx, int node_idx, int node_from, int node_to, int target_block_from, int target_block_to);
static void traverse_target_node(JPROOF_VERIFY_CTX* ctx, int node_from, int node_to);
static void run_program(JPROOF_VERIFY_CTX* ctx);
static int  largest_second_power(int value);

void jproof_verify_init(JPROOF_VERIFY_CTX* ctx, const JPROOF_VALUE* value) {
    assert(value->length < JHASH_MAX_INPUT_LENGTH);
    assert(0 < value->range_in_point && value->range_in_point < value->range_out_point && value->range_out_point <= value->length);

    // Prepare general state
    ctx->value = value;
    ctx->num_hashes = 0;

    ctx->num_blocks_total = value->length / JHASH_BLOCK_SIZE;
    if (value->length % JHASH_BLOCK_SIZE > 0) ctx->num_blocks_total++;

    int block_from = value->range_in_point  / JHASH_BLOCK_SIZE;
    int block_to   = value->range_out_point / JHASH_BLOCK_SIZE;
    if (block_to % JHASH_BLOCK_SIZE > 0) block_to++;
    ctx->num_blocks_region = block_to - block_from;

    ctx->head_in_point = block_from * JHASH_BLOCK_SIZE;
    ctx->head_size     = value->range_in_point - ctx->head_in_point;
    ctx->tail_in_point = value->range_out_point;
    ctx->tail_size     = block_to * JHASH_BLOCK_SIZE - value->range_out_point;
    if (ctx->tail_in_point + ctx->tail_size > ctx->value->length) {
        ctx->tail_size = ctx->value->length - ctx->tail_in_point;
    }

    // Prepare verify state
    int program_size_estimate = ctx->num_blocks_region * 2 + JHASH_MAX_COUNT;
    ctx->program_size = 0;
    ctx->program_counter = 0;
    ctx->stack_idx = 0;
    ctx->program = (JPROOF_INST*)jhash_alloc(program_size_estimate * sizeof(JPROOF_INST));

    // Traverse merkle tree, which compiles our program
    traverse_node(ctx, 0, 0, ctx->num_blocks_total, block_from, block_to);

    // Check that the proof payload is the right length
    if (ctx->value->payload_length != ctx->head_size + ctx->tail_size + ctx->num_hashes * SHA256_BLOCK_SIZE) {
        ctx->state = STATE_ERROR;
        return;
    }
    
    // Start running the program
    run_program(ctx);
    if (ctx->state == STATE_FINISHED) {
        return;
    }

    // Start processing input
    sha256_init(&ctx->sha_ctx);
    ctx->input_length = ctx->head_in_point;

    // Prepend the head
    jproof_verify_update(ctx, &ctx->value->payload[0], ctx->head_size);
}

void jproof_verify_update(JPROOF_VERIFY_CTX* ctx, const unsigned char* data, long len) {
    while (len > 0) {
        if (ctx->state != STATE_NEED_INPUT) {
            ctx->state = STATE_ERROR;
            return;
        }

        int space_remaining_in_block = JHASH_BLOCK_SIZE - ctx->input_length % JHASH_BLOCK_SIZE;
        int space_remaining_in_total = ctx->value->length - ctx->input_length;
        int space_remaining = space_remaining_in_block < space_remaining_in_total ? space_remaining_in_block : space_remaining_in_total;

        // New data arriving fits in the current block
        if (len < space_remaining) {
            sha256_update(&ctx->sha_ctx, data, len);
            ctx->input_length += len;
            return;
        }

        // We have reached the end of the block, so we want to create the block hash
        sha256_update(&ctx->sha_ctx, data, space_remaining);
        ctx->input_length += space_remaining;

        len  -= space_remaining;
        data += space_remaining;

        // Push hash onto stack and continue running program
        sha256_final(&ctx->sha_ctx, &ctx->stack[ctx->stack_idx * SHA256_BLOCK_SIZE]);
        sha256_init(&ctx->sha_ctx);
        ctx->stack_idx++;
        ctx->program_counter++;
        run_program(ctx);
    }
}

int jproof_verify_check_error(JPROOF_VERIFY_CTX* ctx) {
    return (ctx->state == STATE_ERROR);
}

int jproof_verify_final(JPROOF_VERIFY_CTX* ctx, JHASH_VALUE* value) {
    if (ctx->state == STATE_ERROR) {
        return 1;
    }

    // We didn't receive enough/the correct amount of input data
    if (ctx->input_length != ctx->tail_in_point) {
        ctx->state = STATE_ERROR;
        return 1;
    }

    // Append the tail
    jproof_verify_update(ctx, &ctx->value->payload[ctx->head_size], ctx->tail_size);

    // Verify that program has completed execution
    if (ctx->state != STATE_FINISHED) {
        ctx->state = STATE_ERROR;
        return 1;
    }

    // Construct result
    value->length = ctx->value->length;
    memcpy(value->payload, &ctx->stack[0], SHA256_BLOCK_SIZE);
    return 0;
}

void jproof_verify_free(JPROOF_VERIFY_CTX* ctx) {
    jhash_free(ctx->program);
    ctx->program = NULL;
}

void traverse_node(JPROOF_VERIFY_CTX* ctx, int node_idx, int node_from, int node_to, int target_block_from, int target_block_to) {

    if (node_to <= target_block_from || node_from >= target_block_to) {
        // This node appears either before or after the target region, push the node's hash
        ctx->program[ctx->program_size++] = INST_PUSH_HASH(ctx->num_hashes);
        ctx->num_hashes++;
        return;
    }

    if (node_from >= target_block_from && node_to <= target_block_to) {
        // The target region covers this node and all its children, explore and push all children
        traverse_target_node(ctx, node_from, node_to);
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

    ctx->program[ctx->program_size++] = INST_COMPUTE_HASH;
}

void traverse_target_node(JPROOF_VERIFY_CTX* ctx, int node_from, int node_to) {

    if (node_from + 1 == node_to) {
        ctx->program[ctx->program_size++] = INST_PUSH_BLOCK;
        return;
    }

    int split = largest_second_power(node_to - node_from);

    traverse_target_node(ctx, node_from, node_from + split);
    traverse_target_node(ctx, node_from + split, node_to);
    ctx->program[ctx->program_size++] = INST_COMPUTE_HASH;
}

void run_program(JPROOF_VERIFY_CTX* ctx) {
    for (; ctx->program_counter < ctx->program_size; ctx->program_counter++) {
        JPROOF_INST inst = ctx->program[ctx->program_counter];

        if (inst == INST_COMPUTE_HASH) {
            // Hash the top two stack items
            assert(ctx->stack_idx >= 2);
            sha256_update(&ctx->sha_ctx, &ctx->stack[(ctx->stack_idx - 2) * SHA256_BLOCK_SIZE], 2 * SHA256_BLOCK_SIZE);
            sha256_final(&ctx->sha_ctx, &ctx->stack[(ctx->stack_idx - 2) * SHA256_BLOCK_SIZE]);
            sha256_init(&ctx->sha_ctx);
            ctx->stack_idx--;

        } else if (inst == INST_PUSH_BLOCK) {
            // Push a block from input, this interrupts the execution of the program
            // as input is buffered
            ctx->state = STATE_NEED_INPUT;
            return;

        } else {
            // Push a hash from the JPROOF onto the stack
            int hash_idx = inst;
            const unsigned char* hash = &ctx->value->payload[ctx->head_size + ctx->tail_size + hash_idx * SHA256_BLOCK_SIZE];
            memcpy(&ctx->stack[ctx->stack_idx * SHA256_BLOCK_SIZE], hash, SHA256_BLOCK_SIZE);
            ctx->stack_idx++;
        }
    }

    ctx->state = STATE_FINISHED;
}

int largest_second_power(int value) {
    // This function determines the largest power of 2 that is strictly smaller than value
    int x = 0b01000000000000000000000000000000;
    if (value <= 1 || value > x) return 0;
    while (x >= value) x >>= 1;
    return x;
}
