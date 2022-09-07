# primit

Minimal portable cryptographic primitive in 100% pure Rust.

All algorithms are designed working in *no_std* environment, without using heap memory allocate.

The build artifact less than 20KiB.

## ⚠ Security Notes

The library not aims to used in real production environment, it drops lots of protective measures for less compiled binary size, but it may suitable for your own toy projects which only used by yourself.

## Current support primitive

+ [x] MD5
+ [x] SHA-256
+ [x] HMAC-SHA256
+ [x] GHash
+ [x] Poly1305
+ [x] AES-128
+ [x] Chacha20
+ [x] AES-128-GCM
+ [x] Chacha20Poly1305
+ [x] Chacha8 based Random Number Generator
+ [x] Hexadecimal encoding/decoding
+ [x] P-256(secp256r1) for ECDHE

## Acknowledgement

This project is a part of [zkonge/husk](https://github.com/zkonge/husk), learned a lot from [BearSSL](https://bearssl.org) and [RustCrypto](https://github.com/RustCrypto).

You can easily find licenses in their websites. Some other references may be find in source code comment.


## LICENSE

MIT
