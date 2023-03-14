/*********************************************************************
* Filename:   jhash_encoding.c
* Author:     Bartholomew Joyce
*********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "jhash.h"
#include "base64.h"

#define JHASH_MAX_INPUT_LENGTH 80

char* jhash_encode(const JHASH_VALUE* value) {

    char* buffer = (char*)jhash_alloc(JHASH_MAX_INPUT_LENGTH);
    sprintf(buffer, "jh%d:%ld:", JHASH_BLOCK_SIZE, value->length);

    char* ptr = buffer + strlen(buffer);
    Base64encode(ptr, value->payload, SHA256_BLOCK_SIZE);

    return buffer;
}

int jhash_decode(const char* string, JHASH_VALUE* value) {

    if (strlen(string) > JHASH_MAX_INPUT_LENGTH) {
        return JHASH_DECODE_ERR;
    }

    int block_size;
    char buffer[JHASH_MAX_INPUT_LENGTH];

    if (sscanf(string, "jh%d:%ld:%s", &block_size, &value->length, buffer) < 3) {
        return JHASH_DECODE_ERR;
    }

    if (block_size != JHASH_BLOCK_SIZE) {
        return JHASH_DECODE_ERR;
    }

    unsigned char decoded[Base64decode_len(buffer)];
    int payload_length = Base64decode(decoded, buffer);
    if (payload_length != SHA256_BLOCK_SIZE) {
        return JHASH_DECODE_ERR;
    }
    memcpy(value->payload, decoded, SHA256_BLOCK_SIZE);

    return 0;
}
