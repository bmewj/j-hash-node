{
  "targets": [{
    "target_name": "j-hash-node",
    "sources": [
      "./src/j-hash-node.cpp",
      "./src/jhash.c",
      "./src/jhash_encoding.c",
      "./src/jproof_generate.c",
      "./src/jproof_verify.c",
      "./src/jproof_encoding.c",
      "./src/sha256.c",
      "./src/base64.c",
    ],
    "cflags": [
      "-Wall",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wextra"
    ],
    "cflags_cc+": [
      "-std=c++0x"
    ],
    "include_dirs": [
      "/usr/local/include",
      "<!(node -e \"require('nan')\")"
    ],
  }]
}
