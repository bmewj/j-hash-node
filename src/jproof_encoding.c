/*********************************************************************
* Filename:   jproof_encoding.c
* Author:     Bartholomew Joyce
*********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "jproof.h"
#include "base64.h"

char* jproof_encode(const JPROOF_VALUE* value) {

    int length_estimate = 64 + Base64encode_len(value->payload_length);
    char* buffer = jhash_alloc(length_estimate);

    long a = value->range_in_point;
    long b = value->range_out_point - a;
    long c = value->length - b;
    sprintf(buffer, "jp%d:%ld:%ld:%ld:", JHASH_BLOCK_SIZE, a, b, c);

    char* ptr = buffer + strlen(buffer);
    Base64encode(ptr, value->payload, value->payload_length);

    return buffer;
}

int jproof_decode(const char* string, JPROOF_VALUE* value) {
    int block_size;
    char buffer[strlen(string)];

    long a, b, c;
    if (sscanf(string, "jp%d:%ld:%ld:%ld:%s", &block_size, &a, &b, &c, buffer) < 5) {
        return JHASH_DECODE_ERR;
    }

    if (block_size != JHASH_BLOCK_SIZE) {
        return JHASH_DECODE_ERR;
    }

    if (a < 0 || b < 0 || c < 0) {
        return JHASH_DECODE_ERR;
    }

    value->range_in_point  = a;
    value->range_out_point = a + b;
    value->length           = a + b + c;

    value->payload_length = Base64decode_len(buffer);
    value->payload = (unsigned char*)jhash_alloc(value->payload_length);
    value->payload_length = Base64decode(value->payload, buffer);

    return 0;
}

void jproof_value_free(JPROOF_VALUE* value) {
    jhash_free(value->payload);
    value->payload = NULL;
    value->payload_length = 0;
}
