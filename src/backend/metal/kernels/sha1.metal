#include <metal_stdlib>
using namespace metal;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef float f32;

// Main logical functions for SHA1.
inline u32 f1(u32 x, u32 y, u32 z) {
    return ((x & y) | (~x & z));
}
inline u32 f2(u32 x, u32 y, u32 z) {
    return (x ^ y ^ z);
}
inline u32 f3(u32 x, u32 y, u32 z) {
    return ((x & y) | (x & z) | (y & z));
}
inline u32 f4(u32 x, u32 y, u32 z) {
    return (x ^ y ^ z);
}

// 32-bit rotate.
inline u32 ROT(u32 x, int n) {
    return ((x << n) | (x >> (32 - n)));
}

kernel void sha1(device const u8* data, device u32 hash[5], device const u64& len) {
    assert(len <= 64);

    u32 W[80] = {0};
    u32 H[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    u32 a;
    u32 b;
    u32 c;
    u32 d;
    u32 e;
    u32 f = 0;
    u32 k = 0;

    u32 didx = 0;

    u32 temp;
    u64 databits = ((u64)len) * 8;
    u32 loopcount = (len + 8) / 64 + 1;
    u32 tailbytes = 64 * loopcount - len;
    u8 datatail[128] = {0};

    /* Pre-processing of data tail (includes padding to fill out 512-bit chunk):
       Add bit '1' to end of message (big-endian)
       Add 64-bit message length in bits at very end (big-endian) */
    datatail[0] = 0x80;
    datatail[tailbytes - 8] = (u8)(databits >> 56 & 0xFF);
    datatail[tailbytes - 7] = (u8)(databits >> 48 & 0xFF);
    datatail[tailbytes - 6] = (u8)(databits >> 40 & 0xFF);
    datatail[tailbytes - 5] = (u8)(databits >> 32 & 0xFF);
    datatail[tailbytes - 4] = (u8)(databits >> 24 & 0xFF);
    datatail[tailbytes - 3] = (u8)(databits >> 16 & 0xFF);
    datatail[tailbytes - 2] = (u8)(databits >> 8 & 0xFF);
    datatail[tailbytes - 1] = (u8)(databits >> 0 & 0xFF);

    /* Break 512-bit chunk into sixteen 32-bit, big endian words */
    for (u32 widx = 0; widx < 16; widx++) {
        i32 wcount = 24;

        /* Copy byte-per byte from specified buffer */
        while (didx < len && wcount >= 0) {
            W[widx] += (((u32)data[didx]) << wcount);
            didx++;
            wcount -= 8;
        }
        /* Fill out W with padding as needed */
        while (wcount >= 0) {
            W[widx] += (((u32)datatail[didx - len]) << wcount);
            didx++;
            wcount -= 8;
        }
    }

    /* Extend the sixteen 32-bit words into eighty 32-bit words, with potential optimization
       from: "Improving the Performance of the Secure Hash Algorithm (SHA-1)" by Max Locktyukhin
     */
    for (u32 widx = 16; widx < 32; widx++)
        W[widx] = ROT((W[widx - 3] ^ W[widx - 8] ^ W[widx - 14] ^ W[widx - 16]), 1);

    for (u32 widx = 32; widx < 80; widx++)
        W[widx] = ROT((W[widx - 6] ^ W[widx - 16] ^ W[widx - 28] ^ W[widx - 32]), 2);

    /* Main loop */
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    #pragma unroll
    for (u32 idx = 0; idx < 80; idx++) {
        if (idx < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (idx >= 20 && idx <= 39) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (idx >= 40 && idx <= 59) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else if (idx >= 60 && idx <= 79) {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        temp = ROT(a, 5) + f + e + k + W[idx];
        e = d;
        d = c;
        c = ROT(b, 30);
        b = a;
        a = temp;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;

    hash[0] = __builtin_bswap32(H[0]);
    hash[1] = __builtin_bswap32(H[1]);
    hash[2] = __builtin_bswap32(H[2]);
    hash[3] = __builtin_bswap32(H[3]);
    hash[4] = __builtin_bswap32(H[4]);
}
