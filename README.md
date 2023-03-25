j-hash-node
===========

Node.js bindings for the [J-hash](https://github.com/bartjoyce/j-hash) C library.

J-hash is a file hashing algorithm based on SHA256 and merkle trees. It has the unique property that proofs can be generated for any arbitrary substring of a file that prove the substring authentic **without having to see the rest of the file**.

# Usage

## 1. Simple hashing

```javascript
const { JHashCtx } = require('j-hash-node');

const ctx = new JHashCtx;

const buffer = Buffer.from('Hello, world!', 'utf8');
ctx.update(buffer);

const hash = ctx.final();
console.log(hash);   // 'jh1024:1160344149:OsPiEahBd2VBEL6h6s6wOkRYrCRK0tUBM+YZFo5SaKA='
```

## 2. Hashing a file & writing all intermediate hashes to an output file

```javascript
(async() => {

    const f_in = await fs.open('file.mov', 'r');
    const f_out = await fs.open('file.mov.jhash', 'w');

    const buf_in = new Buffer.alloc(16384);
    const buf_out = new Buffer.alloc(65536);
    const THRESHOLD = buf_out.length - buf_in.length; // How full the output buffer becomes before we flush it

    const ctx = new JHashCtx(buf_out);

    while (true) {
        const { bytesRead } = await f_in.read(buf_in, 0, buf_in.length);
        if (bytesRead === 0) {
            break;
        }

        ctx.update(buf_in, bytesRead);
        if (ctx.outputBufferSize >= THRESHOLD) {
            await f_out.write(buf_out, 0, ctx.outputBufferSize);
            ctx.outputBufferFlush();
        }
    }

    const hash = ctx.final();
    console.log('Final hash', hash);

    await f_out.write(buf_out, 0, jhash.outputBufferSize);

    f_out.close();
    f_in.close();
})();
```

The resulting `.jhash` file will contain all intermediate hashes that constitute the file's merkle tree and is needed when generating J-proofs. The file will be 6.25% the size of the original file.

The output buffer you pass to the context should be sufficiently large to not overflow during a `jhash.update()`. On incredibly large inputs (500GB+) a single `jhash.update()` call can hypothetically produce 40 hashes *in addition to* one hash per 1024 bytes of input.

## 4. Generating a J-proof for a byte range of a file

```javascript
const { JProofGenerateCtx } = require('j-hash-node');

async function getFileMetadata(filename) {
    // ...
    return {
        filesize: // ...
        hashFilename: // ...
    };
}

async function readFileRanges(filename, ranges) {
    // Imagine this function to take an array of index ranges, it makes a request for the file's content
    // at the specified ranges and returns a Buffer for each range.
}

async function fileRequest(filename, rangeFrom, rangeLength) {
    const { filesize, hashFilename } = await getFileMetadata(filename);
    
    const ctx = new JProofGenerateCtx(filesize, rangeFrom, rangeFrom + rangeLength);

    const request = ctx.getRequest();
    /*
        {
          head: [ 455704576, 874 ],               <-- The offset and length of the head
          tail: [ 477129638, 90 ],                <-- The offset and length of the tail
          hashes: [
            [ 16777152, 32 ], [ 25165728, 32 ], [ 27262848, 32 ], [ 28311392, 32 ],
            [ 28442432, 32 ], [ 28475168, 32 ], [ 28479232, 32 ], [ 28481248, 32 ],
            [ 29820288, 32 ], [ 29820576, 32 ], [ 29822688, 32 ], [ 29826784, 32 ],   <-- The offset and length of the hashes we need
            [ 29834976, 32 ], [ 29851360, 32 ], [ 29884128, 32 ], [ 30408512, 32 ],
            [ 31457088, 32 ], [ 33554240, 32 ], [ 67108768, 32 ], [ 101003040, 32 ]
          ],
          payloadLength: 1604                    <-- Size of the byte payload of the proof
        }
    */

    // Request one range from the file
    const rangeIncludingHeadAndTail = [ request.head[0], request.head[1] + rangeLength + request.tail[1] ];
    const [byteRangeData] = await readFileRanges(filename, [rangeIncludingHeadAndTail]);

    // Request all the hashes from the hash file
    const hashes = await readFileRanges(hashFilename, request.hashes);
    
    // Prepare our file data
    const head    = byteRangeData.slice(0, request.head[1]);
    const content = byteRangeData.slice(request.head[1], request.head[1] + rangeLength);
    const tail    = byteRangeData.slice(request.head[1] + rangeLength);
    
    const proofPayload = Buffer.concat([head, tail, ...hashes]);
    const proof = ctx.generate(proofPayload);
    
    return { content, proof }; // Return the requested content with its proof
}
```

## 5. Verifying a J-proof

Given a Buffer `byteRangeData`, a string `proof`, and the expected `fileHash`, we can verify the byte range as follows:

```javascript
const { JProofVerifyCtx } = require('j-hash-node');

function verifyRange(byteRangeData, proof, fileHash) {

    const ctx = new JProofVerifyCtx(proof); // Pass in the "jp1024:..." proof string
    ctx.update(byteRangeData);              // Process all the data
    
    const hash = ctx.final();               // Receive the final hash
    if (hash && hash === fileHash) {
        return true;                        // Byte range & proof produce correct hash
    } else {
        return false;                       // Failure :(
    }
}

```

Byte range data can also be streamed in:

```javascript
function verifyRange(byteStream, proof, fileHash, callback) {
    const ctx = new JProofVerifyCtx(proof);
    if (ctx.hasError()) {
        callback(false); // proof parse error
    }

    byteStream.on('data', chunk => {
        jproof.update(chunk);
        if (jproof.hasError()) {
            stream.close();
            callback(false); // received more data than expected
        }
    });

    byteStream.on('end', () => {
        callback(jproof.final() === fileHash);
    });
}
```

