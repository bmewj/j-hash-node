j-hash-node
===========

Node.js bindings for the [J-hash](https://github.com/bartjoyce/j-hash) C library.

J-hash is a file hashing algorithm based on SHA256 and merkle trees. It has the unique property that proofs can be generated for any arbitrary substring of a file that prove the substring authentic **without having to see the rest of the file**.

# Usage

## 1. Simple hashing

```c
JHASH_CTX ctx;
jhash_init(&ctx);

unsigned char buffer[] = { 0x6A, 0xB7, 0x2E, 0xEB, 0x9E, 0x77, 0xB0 /* ... */ };
jhash_update(&ctx, buffer, sizeof(buffer));

JHASH_VALUE result;
jhash_final(&ctx, &result);

char* hash = jhash_encode(&result);
printf("%s\n", hash); // "jh1024:1160344149:OsPiEahBd2VBEL6h6s6wOkRYrCRK0tUBM+YZFo5SaKA="

free(hash);
```

## 2. Hashing a file & writing all intermediate hashes to an output file

```c
FILE* f_in = fopen("file.mov", "rb");
FILE* f_out = fopen("file.mov.jhash", "wb");

JHASH_CTX ctx;
jhash_init_with_output_file(&ctx, f_out);

unsigned char buffer[4096];
size_t len;
while ((len = fread(buffer, 1, sizeof(buffer), f_in)) > 0) {
    jhash_update(&ctx, buffer, len);
}

JHASH_VALUE result;
jhash_final(&ctx, &result);

char* hash = jhash_encode(&result);
printf("%s\n", hash); // "jh1024:1160344149:OsPiEahBd2VBEL6h6s6wOkRYrCRK0tUBM+YZFo5SaKA="

free(hash);
fclose(f_in);
fclose(f_out);
```

The resulting `.jhash` file will contain all intermediate hashes that constitute the file's merkle tree and is needed when generating J-proofs. The file will be 6.25% the size of the original file.

## 3. Hashing a file & receiving intermediate hashes into a buffer

In case you don't want J-hash writing to a file but still need to handle the intermediate hashes you can pass in a buffer and repeatedly call `jhash_output_buffer_read()`.

```c
// ...

unsigned char output_buf[4096];

JHASH_CTX ctx;
jhash_init_with_output_buffer(&ctx, output_buf, sizeof(output_buf));

// ...
while ((len = fread(buffer, 1, sizeof(buffer), f_in)) > 0) {
    jhash_update(&ctx, buffer, len);
    
    size_t len_out = jhash_output_buffer_read(&ctx);
    if (len_out > 0) {
        // Received len_out bytes worth of intermediate hashes into output_buf
        // ... you can handle these however you want
    }
}
```

The output buffer you pass to the context should be sufficiently large to not overflow during a `jhash_update()`. On incredibly large inputs (500GB+) a single `jhash_update()` call can hypothetically produce 40 hashes *in addition to* one hash per 1024 bytes of input.

## 4. Generating a J-proof for a byte range of a file

```c
// Example scenario: serving up a sub-range of a file along with a J-proof

void fetch_range(FILE* the_file, FILE* the_hash_file, size_t file_size, size_t range_from, size_t range_to,
                 unsigned char* resp_buffer, size_t* res_length, char** proof) {
    
    JPROOF_GENERATE_CTX ctx;
    jproof_generate_init(&ctx, file_size, range_from, range_to);
    
    // The head and tail describe a certain amount of bytes preceding and following the range in and out points
    // that are needed in the proof.
    fseek(the_file, ctx.request.head_in_point, SEEK_SET);
    jproof_generate_write_head_from_file(&ctx, the_file);

    *res_length = fread(resp_buffer, 1, range_to - range_from, the_file);
    
    jproof_generate_write_tail_from_file(&ctx, the_file);
    
    // Finally, we let the generator pull in all the necessary hashes from the hash file
    jproof_generate_write_hashes_from_file(&ctx, the_hash_file);

    *proof = jproof_encode(&ctx.value);
    jproof_value_free(&ctx.value);

}
```

### Anatomy of a J-proof

A J-proof looks as follows:

```
jp1024:10000:2000:1160342149:70PpLNwys7ECFkiA71FDEFnRTrRiXVAkMppQ9llIMIyxZKKKU/
QjiEFFqg9vDCe4tFf8vxOGOPF9ncbiT1GESyogOGHQGP627YWErvZKurv/OK4f0t1yq+LWhWdv5VhFU
Mj3wAcSuUqQWPd3EnBm+oWD8K76hA6jHiPsvBquz+n1usQ6l0yLQkHkiRjhggqebjOB2T5NclniwYKP
j/Osfxf6K0J+Ml2zYUoz2n//////qZiDHv5T/dnV7P4Cz1NEasib87Ju9vvHKHDiOd/2q5llCIFaeHw
Jh043KHHroKKENeI/6hWNCoA5Oigln3YLMM+NQi/ofNpylXUaMEvq0Eb6LFyi06eaSx+vAHT7XacTAG
dF5TL5o+woVFE54c/ZCarPmhh0aL/7lR9whZFdJf4RIjOoKr8hB2OVaTsChccXoTYy/xk/K16NADDQ/
SW84cRqsxM4cHYbNjIaP+3jm/zoXvTIugpcJevYtX1I4S7nxcxLKXuI8JxikIvJlOyMrjiLFkRp3///
//H83//xnlrb1wHPu9FdUIxHRsThC262FY0awbyEiMpt/xrnry8Rr+9AnIuhezczodASNsPPXSDD/AE
+V1d4G/9m62JfLyM3xF2OYlpECy/7bYsA7mQ7zJViHcO0iXkM8MULwcwOfGkovYs02aBGG+z6eu0v6Y
1DPirccFsxV2HaQmDIzo4MgMlC+D/JOnhinB5Pwet64xaHI9mMWmbbJiH3Vj8ZtD+P50d02fhGDwy39
GmwYnmRZE9kDmNJLjiBrk8W9ByvztXl8TIpVvEsfblI44ko0FDGLyASGrinku/ROh+ehqyiqOfSo+fu
iT+UgY4VnhrGLmvD6j7cFXC9Oqks/grXkfp39eFO6O8hH3UTSu1yc5t/8o1GeZL/lPlAngnGoMUjso=
```

It consists of a prefix `jp1024`, followed by three numbers, followed by a base64 encoded payload.

The three numbers encode the in and out point of the byte range as well as the full file length.

The payload three things: head content, tail content, followed by a set of hashes from the file's
merkle tree.

In order to support file ranges that are not aligned to the 1024 byte block size
proofs include additional file data to round down and up to the nearest block. The head refers
to the range of byte data just before the range in point, and the tail refers to the range of
byte data just after the range out point. A perfectly aligned range request has no head or tail.
The worst aligned range request (e.g. `1023-4097`) will include up to 2046 bytes of additional
data.

The head and tail are followed in the payload by a set of intermediate hashes that, when
combined with the blocks of the range will produce the J-hash of the file.

```c
typedef struct {
    JPROOF_REQUEST request;
    JPROOF_VALUE value;
} JPROOF_GENERATE_CTX;

typedef struct {
    int num_hashes;
    size_t hash_offsets[JHASH_MAX_COUNT];
    size_t head_in_point, head_size;
    size_t tail_in_point, tail_size;
} JPROOF_REQUEST;

typedef struct {
    size_t length;
    size_t range_in_point;
    size_t range_out_point;
    size_t payload_length;
    unsigned char* payload;
} JPROOF_VALUE;
```

## 5. Verifying a J-proof

In the scenario where you've received a byte range of a file along with a J-proof, you can verify
the range as follows:

```c
const char* proof = "jp1024:....";
unsigned char buffer[] = { 0x6A, 0xB7, 0x2E, 0xEB, 0x9E, 0x77, 0xB0 /* ... */ };

JPROOF_VALUE value;
if (jproof_decode(value, &proof) == JHASH_DECODE_ERR) return;

JPROOF_VERIFY_CTX ctx;
jproof_verify_init(&ctx, &value);
jproof_verify_update(&ctx, buffer, sizeof(buffer);

JHASH_VALUE result;
if (jproof_verify_final(&ctx, &result) == JHASH_DECODE_ERR) return;

char* hash = jhash_encode(&result);
printf("%s\n", hash); // "jh1024:1160344149:OsPiEahBd2VBEL6h6s6wOkRYrCRK0tUBM+YZFo5SaKA="
// If this hash matches the hash of the entire file this confirms the authenticity of the byte range.

jproof_verify_free(&ctx);
free(hash);
```
