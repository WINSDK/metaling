#include <metal_stdlib>
using namespace metal;

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

inline u32 swap32(const u32 v) {
    return ((v & 0xff000000) >> 24) |
           ((v & 0x00ff0000) >> 8)  |
           ((v & 0x0000ff00) << 8)  |
           ((v & 0x000000ff) << 24);
}

inline void memcpy_be(thread u32* __restrict dest, const thread u32* __restrict src, u64 n_bytes) {
    for (u64 idx = 0; idx < n_bytes / 4; idx++)
        dest[idx] = swap32(src[idx]);
}

/* ---------------------- SHA1 AND HMAC START ---------------------- */

struct sha1_ctx {
    u32 h[5];

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int len;
};

struct sha1_hmac_ctx {
    sha1_ctx ipad;
    sha1_ctx opad;
};

void sha1_transform(const thread u32* w0, const thread u32* w1, const thread u32* w2, const thread u32* w3, thread u32* digest);
void sha1_init(thread sha1_ctx* ctx);
void sha1_update_64(thread sha1_ctx* ctx, thread u32* w0, thread u32* w1, thread u32* w2, thread u32* w3, const int len);
void sha1_update(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_swap(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_utf16le(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_utf16le_swap(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_utf16be(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_utf16be_swap(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_utf16beN(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_global(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_global_swap(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_global_utf16le(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_global_utf16le_swap(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_global_utf16be(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_update_global_utf16be_swap(thread sha1_ctx* ctx, const thread u32* w, const int len);
void sha1_final(thread sha1_ctx* ctx);
void sha1_hmac_init_64(thread sha1_hmac_ctx* ctx, const thread u32* w0, const thread u32* w1, const thread u32* w2, const thread u32* w3);
void sha1_hmac_init(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_init_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_init_global(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_init_global_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_init_global_utf16le_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_update_64(thread sha1_hmac_ctx* ctx, thread u32* w0, thread u32* w1, thread u32* w2, thread u32* w3, const int len);
void sha1_hmac_update(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_update_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_update_utf16le(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_update_utf16le_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_update_global(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_update_global_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_update_global_utf16le(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_update_global_utf16le_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len);
void sha1_hmac_final(thread sha1_hmac_ctx* ctx);

struct encoder {
    int pos; // source offset

    u32 cbuf; // carry buffer
    int clen; // carry length
};

void enc_init(thread encoder* enc) {
    enc->pos = 0;

    enc->cbuf = 0;
    enc->clen = 0;
}

int enc_has_next(thread encoder* enc, const int sz) {
    if (enc->pos < sz)
        return 1;

    if (enc->clen)
        return 1;

    return 0;
}

int enc_scan(const thread u32* buf, const int len) {
    if (buf[0] & 0x80808080)
        return 1;
    if (buf[1] & 0x80808080)
        return 1;
    if (buf[2] & 0x80808080)
        return 1;
    if (buf[3] & 0x80808080)
        return 1;
    if (buf[4] & 0x80808080)
        return 1;
    if (buf[5] & 0x80808080)
        return 1;

    for (int i = 24, j = 6; i < len; i += 4, j += 1) {
        if (buf[j] & 0x80808080)
            return 1;
    }

    return 0;
}

int enc_scan_global(const thread u32* buf, const int len) {
    if (buf[0] & 0x80808080)
        return 1;
    if (buf[1] & 0x80808080)
        return 1;
    if (buf[2] & 0x80808080)
        return 1;
    if (buf[3] & 0x80808080)
        return 1;
    if (buf[4] & 0x80808080)
        return 1;
    if (buf[5] & 0x80808080)
        return 1;

    for (int i = 24, j = 6; i < len; i += 4, j += 1) {
        if (buf[j] & 0x80808080)
            return 1;
    }

    return 0;
}

constant u32 offsetsFromUTF8_0 = 0x00000000;
constant u32 offsetsFromUTF8_1 = 0x00003080;
constant u32 offsetsFromUTF8_2 = 0x000E2080;
constant u32 offsetsFromUTF8_3 = 0x03C82080;
constant u32 offsetsFromUTF8_4 = 0xFA082080;
constant u32 offsetsFromUTF8_5 = 0x82082080;

constant u32 UNI_MAX_BMP = 0xFFFF;
constant u32 UNI_SUR_HIGH_START = 0xD800;
constant u32 UNI_SUR_HIGH_END = 0xDBFF;
constant u32 UNI_SUR_LOW_START = 0xDC00;
constant u32 UNI_SUR_LOW_END = 0xDFFF;

constant u32 halfShift = 10;
constant u32 halfBase = 0x0010000;
constant u32 halfMask = 0x3FF;

int enc_next_global(
    thread encoder* enc,
    const thread u32* src_buf,
    const int src_len,
    const int src_sz,
    thread u32* dst_buf,
    const int dst_sz) {
    const thread u8* src_ptr = (const thread u8*)src_buf;
    thread u8* dst_ptr = (thread u8*)dst_buf;

    int src_pos = enc->pos;
    int dst_pos = enc->clen;

    dst_buf[0] = enc->cbuf;

    enc->clen = 0;
    enc->cbuf = 0;

    while ((src_pos < src_len) && (dst_pos < dst_sz)) {
        const u8 c = src_ptr[src_pos];

        int extraBytesToRead = 0;

        if (c >= 0xf0) {
            extraBytesToRead = 3;
        } else if (c >= 0xe0) {
            extraBytesToRead = 2;
        } else if (c >= 0xc0) {
            extraBytesToRead = 1;
        }

        if ((src_pos + extraBytesToRead) >= src_sz) {
            // broken input
            enc->pos = src_len;
            return -1;
        }

        u32 ch = 0;

        switch (extraBytesToRead) {
            case 3:
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch -= offsetsFromUTF8_3;
                break;
            case 2:
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch -= offsetsFromUTF8_2;
                break;
            case 1:
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch -= offsetsFromUTF8_1;
                break;
            case 0:
                ch += src_ptr[src_pos++];
                ch -= offsetsFromUTF8_0;
                break;
        }

        /* Target is a character <= 0xFFFF */
        if (ch <= UNI_MAX_BMP) {
            dst_ptr[dst_pos++] = (ch >> 0) & 0xff;
            dst_ptr[dst_pos++] = (ch >> 8) & 0xff;
        } else {
            ch -= halfBase;

            const u32 a = ((ch >> halfShift) + UNI_SUR_HIGH_START);
            const u32 b = ((ch & halfMask) + UNI_SUR_LOW_START);

            if ((dst_pos + 2) == dst_sz) {
                // this section seems to break intel opencl runtime but is unknown why

                dst_ptr[dst_pos++] = (a >> 0) & 0xff;
                dst_ptr[dst_pos++] = (a >> 8) & 0xff;

                enc->cbuf = b & 0xffff;
                enc->clen = 2;
            } else {
                dst_ptr[dst_pos++] = (a >> 0) & 0xff;
                dst_ptr[dst_pos++] = (a >> 8) & 0xff;
                dst_ptr[dst_pos++] = (b >> 0) & 0xff;
                dst_ptr[dst_pos++] = (b >> 8) & 0xff;
            }
        }
    }

    enc->pos = src_pos;

    return dst_pos;
}

int enc_next(
    thread encoder* enc,
    const thread u32* src_buf,
    const int src_len,
    const int src_sz,
    thread u32* dst_buf,
    const int dst_sz) {
    const thread u8* src_ptr = (const thread u8*)src_buf;
    thread u8* dst_ptr = (thread u8*)dst_buf;

    int src_pos = enc->pos;

    int dst_pos = enc->clen;

    dst_buf[0] = enc->cbuf;

    enc->clen = 0;
    enc->cbuf = 0;

    while ((src_pos < src_len) && (dst_pos < dst_sz)) {
        const u8 c = src_ptr[src_pos];

        int extraBytesToRead = 0;

        if (c >= 0xf0) {
            extraBytesToRead = 3;
        } else if (c >= 0xe0) {
            extraBytesToRead = 2;
        } else if (c >= 0xc0) {
            extraBytesToRead = 1;
        }

        if ((src_pos + extraBytesToRead) >= src_sz) {
            // broken input
            enc->pos = src_len;
            return -1;
        }

        u32 ch = 0;

        switch (extraBytesToRead) {
            case 3:
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch -= offsetsFromUTF8_3;
                break;
            case 2:
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch -= offsetsFromUTF8_2;
                break;
            case 1:
                ch += src_ptr[src_pos++];
                ch <<= 6;
                ch += src_ptr[src_pos++];
                ch -= offsetsFromUTF8_1;
                break;
            case 0:
                ch += src_ptr[src_pos++];
                ch -= offsetsFromUTF8_0;
                break;
        }

        /* Target is a character <= 0xFFFF */
        if (ch <= UNI_MAX_BMP) {
            dst_ptr[dst_pos++] = (ch >> 0) & 0xff;
            dst_ptr[dst_pos++] = (ch >> 8) & 0xff;
        } else {
            ch -= halfBase;

            const u32 a = ((ch >> halfShift) + UNI_SUR_HIGH_START);
            const u32 b = ((ch & halfMask) + UNI_SUR_LOW_START);

            if ((dst_pos + 2) == dst_sz) {
                dst_ptr[dst_pos++] = (a >> 0) & 0xff;
                dst_ptr[dst_pos++] = (a >> 8) & 0xff;

                enc->cbuf = b & 0xffff;
                enc->clen = 2;
            } else {
                dst_ptr[dst_pos++] = (a >> 0) & 0xff;
                dst_ptr[dst_pos++] = (a >> 8) & 0xff;
                dst_ptr[dst_pos++] = (b >> 0) & 0xff;
                dst_ptr[dst_pos++] = (b >> 8) & 0xff;
            }
        }
    }

    enc->pos = src_pos;

    return dst_pos;
}

constant u32 SHA1C00 = 0x5a827999;
constant u32 SHA1C01 = 0x6ed9eba1;
constant u32 SHA1C02 = 0x8f1bbcdc;
constant u32 SHA1C03 = 0xca62c1d6;

constant u32 SHA1M_A = 0x67452301;
constant u32 SHA1M_B = 0xefcdab89;
constant u32 SHA1M_C = 0x98badcfe;
constant u32 SHA1M_D = 0x10325476;
constant u32 SHA1M_E = 0xc3d2e1f0;

inline u32 SHA1_F0(u32 x, u32 y, u32 z) {
    return (z ^ (x & (y ^ z)));
}

inline u32 SHA1_F1(u32 x, u32 y, u32 z) {
    return (x ^ y ^ z);
}

inline u32 SHA1_F2(u32 x, u32 y, u32 z) {
    return ((x & y) | (z & (x ^ y)));
}

inline u32 SHA1_F0o(u32 x, u32 y, u32 z) {
    return SHA1_F0(x, y, z);
}

inline u32 SHA1_F2o(u32 x, u32 y, u32 z) {
    return SHA1_F2(x, y, z);
}

inline u32 rotl32(u32 x, int n) {
    return ((x << n) | (x >> (32 - n)));
}

inline u32 add3(u32 a, u32 b, u32 c) {
    return a + b + c;
}

inline u32 bytealign_be(const u32 a, const u32 b, const int c) {
    u32 r = 0;

    const int cm = c & 3;

    if (cm == 0) {
        r = b;
    } else if (cm == 1) {
        r = (a << 24) | (b >> 8);
    } else if (cm == 2) {
        r = (a << 16) | (b >> 16);
    } else if (cm == 3) {
        r = (a << 8) | (b >> 24);
    }

    return r;
}

void make_utf16leN(const thread u32* in, thread u32* out1, thread u32* out2) {
    out2[3] = ((in[3] << 8) & 0x00FF0000) | ((in[3] >> 0) & 0x000000FF);
    out2[2] = ((in[3] >> 8) & 0x00FF0000) | ((in[3] >> 16) & 0x000000FF);
    out2[1] = ((in[2] << 8) & 0x00FF0000) | ((in[2] >> 0) & 0x000000FF);
    out2[0] = ((in[2] >> 8) & 0x00FF0000) | ((in[2] >> 16) & 0x000000FF);
    out1[3] = ((in[1] << 8) & 0x00FF0000) | ((in[1] >> 0) & 0x000000FF);
    out1[2] = ((in[1] >> 8) & 0x00FF0000) | ((in[1] >> 16) & 0x000000FF);
    out1[1] = ((in[0] << 8) & 0x00FF0000) | ((in[0] >> 0) & 0x000000FF);
    out1[0] = ((in[0] >> 8) & 0x00FF0000) | ((in[0] >> 16) & 0x000000FF);
}

void append_helper_1x4(thread u32* r, const u32 v, const thread u32* m) {
    r[0] |= v & m[0];
    r[1] |= v & m[1];
    r[2] |= v & m[2];
    r[3] |= v & m[3];
}

void set_mark_1x4(thread u32* v, const u32 offset) {
    const u32 c = (offset & 15) / 4;
    const u32 r = 0xff << ((offset & 3) * 8);

    v[0] = (c == 0) ? r : 0;
    v[1] = (c == 1) ? r : 0;
    v[2] = (c == 2) ? r : 0;
    v[3] = (c == 3) ? r : 0;
}

void append_0x80_4x4(thread u32* w0, thread u32* w1, thread u32* w2, thread u32* w3, const u32 offset) {
    u32 v[4];

    set_mark_1x4(v, offset);

    const u32 offset16 = offset / 16;

    append_helper_1x4(w0, ((offset16 == 0) ? 0x80808080 : 0), v);
    append_helper_1x4(w1, ((offset16 == 1) ? 0x80808080 : 0), v);
    append_helper_1x4(w2, ((offset16 == 2) ? 0x80808080 : 0), v);
    append_helper_1x4(w3, ((offset16 == 3) ? 0x80808080 : 0), v);
}

void make_utf16beN(const thread u32* in, thread u32* out1, thread u32* out2) {
    out2[3] = ((in[3] << 16) & 0xFF000000) | ((in[3] << 8) & 0x0000FF00);
    out2[2] = ((in[3] >> 0) & 0xFF000000) | ((in[3] >> 8) & 0x0000FF00);
    out2[1] = ((in[2] << 16) & 0xFF000000) | ((in[2] << 8) & 0x0000FF00);
    out2[0] = ((in[2] >> 0) & 0xFF000000) | ((in[2] >> 8) & 0x0000FF00);
    out1[3] = ((in[1] << 16) & 0xFF000000) | ((in[1] << 8) & 0x0000FF00);
    out1[2] = ((in[1] >> 0) & 0xFF000000) | ((in[1] >> 8) & 0x0000FF00);
    out1[1] = ((in[0] << 16) & 0xFF000000) | ((in[0] << 8) & 0x0000FF00);
    out1[0] = ((in[0] >> 0) & 0xFF000000) | ((in[0] >> 8) & 0x0000FF00);
}

void make_utf16be(const thread u32* in, thread u32* out1, thread u32* out2) {
    out2[3] = ((in[3] >> 0) & 0xFF000000) | ((in[3] >> 8) & 0x0000FF00);
    out2[2] = ((in[3] << 16) & 0xFF000000) | ((in[3] << 8) & 0x0000FF00);
    out2[1] = ((in[2] >> 0) & 0xFF000000) | ((in[2] >> 8) & 0x0000FF00);
    out2[0] = ((in[2] << 16) & 0xFF000000) | ((in[2] << 8) & 0x0000FF00);
    out1[3] = ((in[1] >> 0) & 0xFF000000) | ((in[1] >> 8) & 0x0000FF00);
    out1[2] = ((in[1] << 16) & 0xFF000000) | ((in[1] << 8) & 0x0000FF00);
    out1[1] = ((in[0] >> 0) & 0xFF000000) | ((in[0] >> 8) & 0x0000FF00);
    out1[0] = ((in[0] << 16) & 0xFF000000) | ((in[0] << 8) & 0x0000FF00);
}

void make_utf16le(const thread u32* in, thread u32* out1, thread u32* out2) {
    out2[3] = ((in[3] >> 8) & 0x00FF0000) | ((in[3] >> 16) & 0x000000FF);
    out2[2] = ((in[3] << 8) & 0x00FF0000) | ((in[3] >> 0) & 0x000000FF);
    out2[1] = ((in[2] >> 8) & 0x00FF0000) | ((in[2] >> 16) & 0x000000FF);
    out2[0] = ((in[2] << 8) & 0x00FF0000) | ((in[2] >> 0) & 0x000000FF);
    out1[3] = ((in[1] >> 8) & 0x00FF0000) | ((in[1] >> 16) & 0x000000FF);
    out1[2] = ((in[1] << 8) & 0x00FF0000) | ((in[1] >> 0) & 0x000000FF);
    out1[1] = ((in[0] >> 8) & 0x00FF0000) | ((in[0] >> 16) & 0x000000FF);
    out1[0] = ((in[0] << 8) & 0x00FF0000) | ((in[0] >> 0) & 0x000000FF);
}

void switch_buffer_by_offset_carry_be(
    thread u32* w0,
    thread u32* w1,
    thread u32* w2,
    thread u32* w3,
    thread u32* c0,
    thread u32* c1,
    thread u32* c2,
    thread u32* c3,
    const u32 offset) {
    const int offset_switch = offset / 4;

    switch (offset_switch) {
        case 0:
            c0[0] = bytealign_be(w3[3], 0, offset);
            w3[3] = bytealign_be(w3[2], w3[3], offset);
            w3[2] = bytealign_be(w3[1], w3[2], offset);
            w3[1] = bytealign_be(w3[0], w3[1], offset);
            w3[0] = bytealign_be(w2[3], w3[0], offset);
            w2[3] = bytealign_be(w2[2], w2[3], offset);
            w2[2] = bytealign_be(w2[1], w2[2], offset);
            w2[1] = bytealign_be(w2[0], w2[1], offset);
            w2[0] = bytealign_be(w1[3], w2[0], offset);
            w1[3] = bytealign_be(w1[2], w1[3], offset);
            w1[2] = bytealign_be(w1[1], w1[2], offset);
            w1[1] = bytealign_be(w1[0], w1[1], offset);
            w1[0] = bytealign_be(w0[3], w1[0], offset);
            w0[3] = bytealign_be(w0[2], w0[3], offset);
            w0[2] = bytealign_be(w0[1], w0[2], offset);
            w0[1] = bytealign_be(w0[0], w0[1], offset);
            w0[0] = bytealign_be(0, w0[0], offset);

            break;

        case 1:
            c0[1] = bytealign_be(w3[3], 0, offset);
            c0[0] = bytealign_be(w3[2], w3[3], offset);
            w3[3] = bytealign_be(w3[1], w3[2], offset);
            w3[2] = bytealign_be(w3[0], w3[1], offset);
            w3[1] = bytealign_be(w2[3], w3[0], offset);
            w3[0] = bytealign_be(w2[2], w2[3], offset);
            w2[3] = bytealign_be(w2[1], w2[2], offset);
            w2[2] = bytealign_be(w2[0], w2[1], offset);
            w2[1] = bytealign_be(w1[3], w2[0], offset);
            w2[0] = bytealign_be(w1[2], w1[3], offset);
            w1[3] = bytealign_be(w1[1], w1[2], offset);
            w1[2] = bytealign_be(w1[0], w1[1], offset);
            w1[1] = bytealign_be(w0[3], w1[0], offset);
            w1[0] = bytealign_be(w0[2], w0[3], offset);
            w0[3] = bytealign_be(w0[1], w0[2], offset);
            w0[2] = bytealign_be(w0[0], w0[1], offset);
            w0[1] = bytealign_be(0, w0[0], offset);
            w0[0] = 0;

            break;

        case 2:
            c0[2] = bytealign_be(w3[3], 0, offset);
            c0[1] = bytealign_be(w3[2], w3[3], offset);
            c0[0] = bytealign_be(w3[1], w3[2], offset);
            w3[3] = bytealign_be(w3[0], w3[1], offset);
            w3[2] = bytealign_be(w2[3], w3[0], offset);
            w3[1] = bytealign_be(w2[2], w2[3], offset);
            w3[0] = bytealign_be(w2[1], w2[2], offset);
            w2[3] = bytealign_be(w2[0], w2[1], offset);
            w2[2] = bytealign_be(w1[3], w2[0], offset);
            w2[1] = bytealign_be(w1[2], w1[3], offset);
            w2[0] = bytealign_be(w1[1], w1[2], offset);
            w1[3] = bytealign_be(w1[0], w1[1], offset);
            w1[2] = bytealign_be(w0[3], w1[0], offset);
            w1[1] = bytealign_be(w0[2], w0[3], offset);
            w1[0] = bytealign_be(w0[1], w0[2], offset);
            w0[3] = bytealign_be(w0[0], w0[1], offset);
            w0[2] = bytealign_be(0, w0[0], offset);
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 3:
            c0[3] = bytealign_be(w3[3], 0, offset);
            c0[2] = bytealign_be(w3[2], w3[3], offset);
            c0[1] = bytealign_be(w3[1], w3[2], offset);
            c0[0] = bytealign_be(w3[0], w3[1], offset);
            w3[3] = bytealign_be(w2[3], w3[0], offset);
            w3[2] = bytealign_be(w2[2], w2[3], offset);
            w3[1] = bytealign_be(w2[1], w2[2], offset);
            w3[0] = bytealign_be(w2[0], w2[1], offset);
            w2[3] = bytealign_be(w1[3], w2[0], offset);
            w2[2] = bytealign_be(w1[2], w1[3], offset);
            w2[1] = bytealign_be(w1[1], w1[2], offset);
            w2[0] = bytealign_be(w1[0], w1[1], offset);
            w1[3] = bytealign_be(w0[3], w1[0], offset);
            w1[2] = bytealign_be(w0[2], w0[3], offset);
            w1[1] = bytealign_be(w0[1], w0[2], offset);
            w1[0] = bytealign_be(w0[0], w0[1], offset);
            w0[3] = bytealign_be(0, w0[0], offset);
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 4:
            c1[0] = bytealign_be(w3[3], 0, offset);
            c0[3] = bytealign_be(w3[2], w3[3], offset);
            c0[2] = bytealign_be(w3[1], w3[2], offset);
            c0[1] = bytealign_be(w3[0], w3[1], offset);
            c0[0] = bytealign_be(w2[3], w3[0], offset);
            w3[3] = bytealign_be(w2[2], w2[3], offset);
            w3[2] = bytealign_be(w2[1], w2[2], offset);
            w3[1] = bytealign_be(w2[0], w2[1], offset);
            w3[0] = bytealign_be(w1[3], w2[0], offset);
            w2[3] = bytealign_be(w1[2], w1[3], offset);
            w2[2] = bytealign_be(w1[1], w1[2], offset);
            w2[1] = bytealign_be(w1[0], w1[1], offset);
            w2[0] = bytealign_be(w0[3], w1[0], offset);
            w1[3] = bytealign_be(w0[2], w0[3], offset);
            w1[2] = bytealign_be(w0[1], w0[2], offset);
            w1[1] = bytealign_be(w0[0], w0[1], offset);
            w1[0] = bytealign_be(0, w0[0], offset);
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 5:
            c1[1] = bytealign_be(w3[3], 0, offset);
            c1[0] = bytealign_be(w3[2], w3[3], offset);
            c0[3] = bytealign_be(w3[1], w3[2], offset);
            c0[2] = bytealign_be(w3[0], w3[1], offset);
            c0[1] = bytealign_be(w2[3], w3[0], offset);
            c0[0] = bytealign_be(w2[2], w2[3], offset);
            w3[3] = bytealign_be(w2[1], w2[2], offset);
            w3[2] = bytealign_be(w2[0], w2[1], offset);
            w3[1] = bytealign_be(w1[3], w2[0], offset);
            w3[0] = bytealign_be(w1[2], w1[3], offset);
            w2[3] = bytealign_be(w1[1], w1[2], offset);
            w2[2] = bytealign_be(w1[0], w1[1], offset);
            w2[1] = bytealign_be(w0[3], w1[0], offset);
            w2[0] = bytealign_be(w0[2], w0[3], offset);
            w1[3] = bytealign_be(w0[1], w0[2], offset);
            w1[2] = bytealign_be(w0[0], w0[1], offset);
            w1[1] = bytealign_be(0, w0[0], offset);
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 6:
            c1[2] = bytealign_be(w3[3], 0, offset);
            c1[1] = bytealign_be(w3[2], w3[3], offset);
            c1[0] = bytealign_be(w3[1], w3[2], offset);
            c0[3] = bytealign_be(w3[0], w3[1], offset);
            c0[2] = bytealign_be(w2[3], w3[0], offset);
            c0[1] = bytealign_be(w2[2], w2[3], offset);
            c0[0] = bytealign_be(w2[1], w2[2], offset);
            w3[3] = bytealign_be(w2[0], w2[1], offset);
            w3[2] = bytealign_be(w1[3], w2[0], offset);
            w3[1] = bytealign_be(w1[2], w1[3], offset);
            w3[0] = bytealign_be(w1[1], w1[2], offset);
            w2[3] = bytealign_be(w1[0], w1[1], offset);
            w2[2] = bytealign_be(w0[3], w1[0], offset);
            w2[1] = bytealign_be(w0[2], w0[3], offset);
            w2[0] = bytealign_be(w0[1], w0[2], offset);
            w1[3] = bytealign_be(w0[0], w0[1], offset);
            w1[2] = bytealign_be(0, w0[0], offset);
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 7:
            c1[3] = bytealign_be(w3[3], 0, offset);
            c1[2] = bytealign_be(w3[2], w3[3], offset);
            c1[1] = bytealign_be(w3[1], w3[2], offset);
            c1[0] = bytealign_be(w3[0], w3[1], offset);
            c0[3] = bytealign_be(w2[3], w3[0], offset);
            c0[2] = bytealign_be(w2[2], w2[3], offset);
            c0[1] = bytealign_be(w2[1], w2[2], offset);
            c0[0] = bytealign_be(w2[0], w2[1], offset);
            w3[3] = bytealign_be(w1[3], w2[0], offset);
            w3[2] = bytealign_be(w1[2], w1[3], offset);
            w3[1] = bytealign_be(w1[1], w1[2], offset);
            w3[0] = bytealign_be(w1[0], w1[1], offset);
            w2[3] = bytealign_be(w0[3], w1[0], offset);
            w2[2] = bytealign_be(w0[2], w0[3], offset);
            w2[1] = bytealign_be(w0[1], w0[2], offset);
            w2[0] = bytealign_be(w0[0], w0[1], offset);
            w1[3] = bytealign_be(0, w0[0], offset);
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 8:
            c2[0] = bytealign_be(w3[3], 0, offset);
            c1[3] = bytealign_be(w3[2], w3[3], offset);
            c1[2] = bytealign_be(w3[1], w3[2], offset);
            c1[1] = bytealign_be(w3[0], w3[1], offset);
            c1[0] = bytealign_be(w2[3], w3[0], offset);
            c0[3] = bytealign_be(w2[2], w2[3], offset);
            c0[2] = bytealign_be(w2[1], w2[2], offset);
            c0[1] = bytealign_be(w2[0], w2[1], offset);
            c0[0] = bytealign_be(w1[3], w2[0], offset);
            w3[3] = bytealign_be(w1[2], w1[3], offset);
            w3[2] = bytealign_be(w1[1], w1[2], offset);
            w3[1] = bytealign_be(w1[0], w1[1], offset);
            w3[0] = bytealign_be(w0[3], w1[0], offset);
            w2[3] = bytealign_be(w0[2], w0[3], offset);
            w2[2] = bytealign_be(w0[1], w0[2], offset);
            w2[1] = bytealign_be(w0[0], w0[1], offset);
            w2[0] = bytealign_be(0, w0[0], offset);
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 9:
            c2[1] = bytealign_be(w3[3], 0, offset);
            c2[0] = bytealign_be(w3[2], w3[3], offset);
            c1[3] = bytealign_be(w3[1], w3[2], offset);
            c1[2] = bytealign_be(w3[0], w3[1], offset);
            c1[1] = bytealign_be(w2[3], w3[0], offset);
            c1[0] = bytealign_be(w2[2], w2[3], offset);
            c0[3] = bytealign_be(w2[1], w2[2], offset);
            c0[2] = bytealign_be(w2[0], w2[1], offset);
            c0[1] = bytealign_be(w1[3], w2[0], offset);
            c0[0] = bytealign_be(w1[2], w1[3], offset);
            w3[3] = bytealign_be(w1[1], w1[2], offset);
            w3[2] = bytealign_be(w1[0], w1[1], offset);
            w3[1] = bytealign_be(w0[3], w1[0], offset);
            w3[0] = bytealign_be(w0[2], w0[3], offset);
            w2[3] = bytealign_be(w0[1], w0[2], offset);
            w2[2] = bytealign_be(w0[0], w0[1], offset);
            w2[1] = bytealign_be(0, w0[0], offset);
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 10:
            c2[2] = bytealign_be(w3[3], 0, offset);
            c2[1] = bytealign_be(w3[2], w3[3], offset);
            c2[0] = bytealign_be(w3[1], w3[2], offset);
            c1[3] = bytealign_be(w3[0], w3[1], offset);
            c1[2] = bytealign_be(w2[3], w3[0], offset);
            c1[1] = bytealign_be(w2[2], w2[3], offset);
            c1[0] = bytealign_be(w2[1], w2[2], offset);
            c0[3] = bytealign_be(w2[0], w2[1], offset);
            c0[2] = bytealign_be(w1[3], w2[0], offset);
            c0[1] = bytealign_be(w1[2], w1[3], offset);
            c0[0] = bytealign_be(w1[1], w1[2], offset);
            w3[3] = bytealign_be(w1[0], w1[1], offset);
            w3[2] = bytealign_be(w0[3], w1[0], offset);
            w3[1] = bytealign_be(w0[2], w0[3], offset);
            w3[0] = bytealign_be(w0[1], w0[2], offset);
            w2[3] = bytealign_be(w0[0], w0[1], offset);
            w2[2] = bytealign_be(0, w0[0], offset);
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 11:
            c2[3] = bytealign_be(w3[3], 0, offset);
            c2[2] = bytealign_be(w3[2], w3[3], offset);
            c2[1] = bytealign_be(w3[1], w3[2], offset);
            c2[0] = bytealign_be(w3[0], w3[1], offset);
            c1[3] = bytealign_be(w2[3], w3[0], offset);
            c1[2] = bytealign_be(w2[2], w2[3], offset);
            c1[1] = bytealign_be(w2[1], w2[2], offset);
            c1[0] = bytealign_be(w2[0], w2[1], offset);
            c0[3] = bytealign_be(w1[3], w2[0], offset);
            c0[2] = bytealign_be(w1[2], w1[3], offset);
            c0[1] = bytealign_be(w1[1], w1[2], offset);
            c0[0] = bytealign_be(w1[0], w1[1], offset);
            w3[3] = bytealign_be(w0[3], w1[0], offset);
            w3[2] = bytealign_be(w0[2], w0[3], offset);
            w3[1] = bytealign_be(w0[1], w0[2], offset);
            w3[0] = bytealign_be(w0[0], w0[1], offset);
            w2[3] = bytealign_be(0, w0[0], offset);
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 12:
            c3[0] = bytealign_be(w3[3], 0, offset);
            c2[3] = bytealign_be(w3[2], w3[3], offset);
            c2[2] = bytealign_be(w3[1], w3[2], offset);
            c2[1] = bytealign_be(w3[0], w3[1], offset);
            c2[0] = bytealign_be(w2[3], w3[0], offset);
            c1[3] = bytealign_be(w2[2], w2[3], offset);
            c1[2] = bytealign_be(w2[1], w2[2], offset);
            c1[1] = bytealign_be(w2[0], w2[1], offset);
            c1[0] = bytealign_be(w1[3], w2[0], offset);
            c0[3] = bytealign_be(w1[2], w1[3], offset);
            c0[2] = bytealign_be(w1[1], w1[2], offset);
            c0[1] = bytealign_be(w1[0], w1[1], offset);
            c0[0] = bytealign_be(w0[3], w1[0], offset);
            w3[3] = bytealign_be(w0[2], w0[3], offset);
            w3[2] = bytealign_be(w0[1], w0[2], offset);
            w3[1] = bytealign_be(w0[0], w0[1], offset);
            w3[0] = bytealign_be(0, w0[0], offset);
            w2[3] = 0;
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 13:
            c3[1] = bytealign_be(w3[3], 0, offset);
            c3[0] = bytealign_be(w3[2], w3[3], offset);
            c2[3] = bytealign_be(w3[1], w3[2], offset);
            c2[2] = bytealign_be(w3[0], w3[1], offset);
            c2[1] = bytealign_be(w2[3], w3[0], offset);
            c2[0] = bytealign_be(w2[2], w2[3], offset);
            c1[3] = bytealign_be(w2[1], w2[2], offset);
            c1[2] = bytealign_be(w2[0], w2[1], offset);
            c1[1] = bytealign_be(w1[3], w2[0], offset);
            c1[0] = bytealign_be(w1[2], w1[3], offset);
            c0[3] = bytealign_be(w1[1], w1[2], offset);
            c0[2] = bytealign_be(w1[0], w1[1], offset);
            c0[1] = bytealign_be(w0[3], w1[0], offset);
            c0[0] = bytealign_be(w0[2], w0[3], offset);
            w3[3] = bytealign_be(w0[1], w0[2], offset);
            w3[2] = bytealign_be(w0[0], w0[1], offset);
            w3[1] = bytealign_be(0, w0[0], offset);
            w3[0] = 0;
            w2[3] = 0;
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 14:
            c3[2] = bytealign_be(w3[3], 0, offset);
            c3[1] = bytealign_be(w3[2], w3[3], offset);
            c3[0] = bytealign_be(w3[1], w3[2], offset);
            c2[3] = bytealign_be(w3[0], w3[1], offset);
            c2[2] = bytealign_be(w2[3], w3[0], offset);
            c2[1] = bytealign_be(w2[2], w2[3], offset);
            c2[0] = bytealign_be(w2[1], w2[2], offset);
            c1[3] = bytealign_be(w2[0], w2[1], offset);
            c1[2] = bytealign_be(w1[3], w2[0], offset);
            c1[1] = bytealign_be(w1[2], w1[3], offset);
            c1[0] = bytealign_be(w1[1], w1[2], offset);
            c0[3] = bytealign_be(w1[0], w1[1], offset);
            c0[2] = bytealign_be(w0[3], w1[0], offset);
            c0[1] = bytealign_be(w0[2], w0[3], offset);
            c0[0] = bytealign_be(w0[1], w0[2], offset);
            w3[3] = bytealign_be(w0[0], w0[1], offset);
            w3[2] = bytealign_be(0, w0[0], offset);
            w3[1] = 0;
            w3[0] = 0;
            w2[3] = 0;
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 15:
            c3[3] = bytealign_be(w3[3], 0, offset);
            c3[2] = bytealign_be(w3[2], w3[3], offset);
            c3[1] = bytealign_be(w3[1], w3[2], offset);
            c3[0] = bytealign_be(w3[0], w3[1], offset);
            c2[3] = bytealign_be(w2[3], w3[0], offset);
            c2[2] = bytealign_be(w2[2], w2[3], offset);
            c2[1] = bytealign_be(w2[1], w2[2], offset);
            c2[0] = bytealign_be(w2[0], w2[1], offset);
            c1[3] = bytealign_be(w1[3], w2[0], offset);
            c1[2] = bytealign_be(w1[2], w1[3], offset);
            c1[1] = bytealign_be(w1[1], w1[2], offset);
            c1[0] = bytealign_be(w1[0], w1[1], offset);
            c0[3] = bytealign_be(w0[3], w1[0], offset);
            c0[2] = bytealign_be(w0[2], w0[3], offset);
            c0[1] = bytealign_be(w0[1], w0[2], offset);
            c0[0] = bytealign_be(w0[0], w0[1], offset);
            w3[3] = bytealign_be(0, w0[0], offset);
            w3[2] = 0;
            w3[1] = 0;
            w3[0] = 0;
            w2[3] = 0;
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;
    }
}

void switch_buffer_by_offset_be(thread u32* w0, thread u32* w1, thread u32* w2, thread u32* w3, const u32 offset) {
    const int offset_switch = offset / 4;
    switch (offset_switch) {
        case 0:
            w3[3] = bytealign_be(w3[2], w3[3], offset);
            w3[2] = bytealign_be(w3[1], w3[2], offset);
            w3[1] = bytealign_be(w3[0], w3[1], offset);
            w3[0] = bytealign_be(w2[3], w3[0], offset);
            w2[3] = bytealign_be(w2[2], w2[3], offset);
            w2[2] = bytealign_be(w2[1], w2[2], offset);
            w2[1] = bytealign_be(w2[0], w2[1], offset);
            w2[0] = bytealign_be(w1[3], w2[0], offset);
            w1[3] = bytealign_be(w1[2], w1[3], offset);
            w1[2] = bytealign_be(w1[1], w1[2], offset);
            w1[1] = bytealign_be(w1[0], w1[1], offset);
            w1[0] = bytealign_be(w0[3], w1[0], offset);
            w0[3] = bytealign_be(w0[2], w0[3], offset);
            w0[2] = bytealign_be(w0[1], w0[2], offset);
            w0[1] = bytealign_be(w0[0], w0[1], offset);
            w0[0] = bytealign_be(0, w0[0], offset);

            break;

        case 1:
            w3[3] = bytealign_be(w3[1], w3[2], offset);
            w3[2] = bytealign_be(w3[0], w3[1], offset);
            w3[1] = bytealign_be(w2[3], w3[0], offset);
            w3[0] = bytealign_be(w2[2], w2[3], offset);
            w2[3] = bytealign_be(w2[1], w2[2], offset);
            w2[2] = bytealign_be(w2[0], w2[1], offset);
            w2[1] = bytealign_be(w1[3], w2[0], offset);
            w2[0] = bytealign_be(w1[2], w1[3], offset);
            w1[3] = bytealign_be(w1[1], w1[2], offset);
            w1[2] = bytealign_be(w1[0], w1[1], offset);
            w1[1] = bytealign_be(w0[3], w1[0], offset);
            w1[0] = bytealign_be(w0[2], w0[3], offset);
            w0[3] = bytealign_be(w0[1], w0[2], offset);
            w0[2] = bytealign_be(w0[0], w0[1], offset);
            w0[1] = bytealign_be(0, w0[0], offset);
            w0[0] = 0;

            break;

        case 2:
            w3[3] = bytealign_be(w3[0], w3[1], offset);
            w3[2] = bytealign_be(w2[3], w3[0], offset);
            w3[1] = bytealign_be(w2[2], w2[3], offset);
            w3[0] = bytealign_be(w2[1], w2[2], offset);
            w2[3] = bytealign_be(w2[0], w2[1], offset);
            w2[2] = bytealign_be(w1[3], w2[0], offset);
            w2[1] = bytealign_be(w1[2], w1[3], offset);
            w2[0] = bytealign_be(w1[1], w1[2], offset);
            w1[3] = bytealign_be(w1[0], w1[1], offset);
            w1[2] = bytealign_be(w0[3], w1[0], offset);
            w1[1] = bytealign_be(w0[2], w0[3], offset);
            w1[0] = bytealign_be(w0[1], w0[2], offset);
            w0[3] = bytealign_be(w0[0], w0[1], offset);
            w0[2] = bytealign_be(0, w0[0], offset);
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 3:
            w3[3] = bytealign_be(w2[3], w3[0], offset);
            w3[2] = bytealign_be(w2[2], w2[3], offset);
            w3[1] = bytealign_be(w2[1], w2[2], offset);
            w3[0] = bytealign_be(w2[0], w2[1], offset);
            w2[3] = bytealign_be(w1[3], w2[0], offset);
            w2[2] = bytealign_be(w1[2], w1[3], offset);
            w2[1] = bytealign_be(w1[1], w1[2], offset);
            w2[0] = bytealign_be(w1[0], w1[1], offset);
            w1[3] = bytealign_be(w0[3], w1[0], offset);
            w1[2] = bytealign_be(w0[2], w0[3], offset);
            w1[1] = bytealign_be(w0[1], w0[2], offset);
            w1[0] = bytealign_be(w0[0], w0[1], offset);
            w0[3] = bytealign_be(0, w0[0], offset);
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 4:
            w3[3] = bytealign_be(w2[2], w2[3], offset);
            w3[2] = bytealign_be(w2[1], w2[2], offset);
            w3[1] = bytealign_be(w2[0], w2[1], offset);
            w3[0] = bytealign_be(w1[3], w2[0], offset);
            w2[3] = bytealign_be(w1[2], w1[3], offset);
            w2[2] = bytealign_be(w1[1], w1[2], offset);
            w2[1] = bytealign_be(w1[0], w1[1], offset);
            w2[0] = bytealign_be(w0[3], w1[0], offset);
            w1[3] = bytealign_be(w0[2], w0[3], offset);
            w1[2] = bytealign_be(w0[1], w0[2], offset);
            w1[1] = bytealign_be(w0[0], w0[1], offset);
            w1[0] = bytealign_be(0, w0[0], offset);
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 5:
            w3[3] = bytealign_be(w2[1], w2[2], offset);
            w3[2] = bytealign_be(w2[0], w2[1], offset);
            w3[1] = bytealign_be(w1[3], w2[0], offset);
            w3[0] = bytealign_be(w1[2], w1[3], offset);
            w2[3] = bytealign_be(w1[1], w1[2], offset);
            w2[2] = bytealign_be(w1[0], w1[1], offset);
            w2[1] = bytealign_be(w0[3], w1[0], offset);
            w2[0] = bytealign_be(w0[2], w0[3], offset);
            w1[3] = bytealign_be(w0[1], w0[2], offset);
            w1[2] = bytealign_be(w0[0], w0[1], offset);
            w1[1] = bytealign_be(0, w0[0], offset);
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 6:
            w3[3] = bytealign_be(w2[0], w2[1], offset);
            w3[2] = bytealign_be(w1[3], w2[0], offset);
            w3[1] = bytealign_be(w1[2], w1[3], offset);
            w3[0] = bytealign_be(w1[1], w1[2], offset);
            w2[3] = bytealign_be(w1[0], w1[1], offset);
            w2[2] = bytealign_be(w0[3], w1[0], offset);
            w2[1] = bytealign_be(w0[2], w0[3], offset);
            w2[0] = bytealign_be(w0[1], w0[2], offset);
            w1[3] = bytealign_be(w0[0], w0[1], offset);
            w1[2] = bytealign_be(0, w0[0], offset);
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 7:
            w3[3] = bytealign_be(w1[3], w2[0], offset);
            w3[2] = bytealign_be(w1[2], w1[3], offset);
            w3[1] = bytealign_be(w1[1], w1[2], offset);
            w3[0] = bytealign_be(w1[0], w1[1], offset);
            w2[3] = bytealign_be(w0[3], w1[0], offset);
            w2[2] = bytealign_be(w0[2], w0[3], offset);
            w2[1] = bytealign_be(w0[1], w0[2], offset);
            w2[0] = bytealign_be(w0[0], w0[1], offset);
            w1[3] = bytealign_be(0, w0[0], offset);
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 8:
            w3[3] = bytealign_be(w1[2], w1[3], offset);
            w3[2] = bytealign_be(w1[1], w1[2], offset);
            w3[1] = bytealign_be(w1[0], w1[1], offset);
            w3[0] = bytealign_be(w0[3], w1[0], offset);
            w2[3] = bytealign_be(w0[2], w0[3], offset);
            w2[2] = bytealign_be(w0[1], w0[2], offset);
            w2[1] = bytealign_be(w0[0], w0[1], offset);
            w2[0] = bytealign_be(0, w0[0], offset);
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 9:
            w3[3] = bytealign_be(w1[1], w1[2], offset);
            w3[2] = bytealign_be(w1[0], w1[1], offset);
            w3[1] = bytealign_be(w0[3], w1[0], offset);
            w3[0] = bytealign_be(w0[2], w0[3], offset);
            w2[3] = bytealign_be(w0[1], w0[2], offset);
            w2[2] = bytealign_be(w0[0], w0[1], offset);
            w2[1] = bytealign_be(0, w0[0], offset);
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 10:
            w3[3] = bytealign_be(w1[0], w1[1], offset);
            w3[2] = bytealign_be(w0[3], w1[0], offset);
            w3[1] = bytealign_be(w0[2], w0[3], offset);
            w3[0] = bytealign_be(w0[1], w0[2], offset);
            w2[3] = bytealign_be(w0[0], w0[1], offset);
            w2[2] = bytealign_be(0, w0[0], offset);
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 11:
            w3[3] = bytealign_be(w0[3], w1[0], offset);
            w3[2] = bytealign_be(w0[2], w0[3], offset);
            w3[1] = bytealign_be(w0[1], w0[2], offset);
            w3[0] = bytealign_be(w0[0], w0[1], offset);
            w2[3] = bytealign_be(0, w0[0], offset);
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 12:
            w3[3] = bytealign_be(w0[2], w0[3], offset);
            w3[2] = bytealign_be(w0[1], w0[2], offset);
            w3[1] = bytealign_be(w0[0], w0[1], offset);
            w3[0] = bytealign_be(0, w0[0], offset);
            w2[3] = 0;
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 13:
            w3[3] = bytealign_be(w0[1], w0[2], offset);
            w3[2] = bytealign_be(w0[0], w0[1], offset);
            w3[1] = bytealign_be(0, w0[0], offset);
            w3[0] = 0;
            w2[3] = 0;
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 14:
            w3[3] = bytealign_be(w0[0], w0[1], offset);
            w3[2] = bytealign_be(0, w0[0], offset);
            w3[1] = 0;
            w3[0] = 0;
            w2[3] = 0;
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;

        case 15:
            w3[3] = bytealign_be(0, w0[0], offset);
            w3[2] = 0;
            w3[1] = 0;
            w3[0] = 0;
            w2[3] = 0;
            w2[2] = 0;
            w2[1] = 0;
            w2[0] = 0;
            w1[3] = 0;
            w1[2] = 0;
            w1[1] = 0;
            w1[0] = 0;
            w0[3] = 0;
            w0[2] = 0;
            w0[1] = 0;
            w0[0] = 0;

            break;
    }
}

#define SHA1_STEP(f, a, b, c, d, e, x) \
    {                                  \
        e += K;                        \
        e = add3(e, x, f(b, c, d));    \
        e += rotl32(a, 5);             \
        b = rotl32(b, 30);             \
    }

#define SHA1_STEP(f, a, b, c, d, e, x) \
    {                                  \
        e += K;                        \
        e = add3(e, x, f(b, c, d));    \
        e += rotl32(a, 5);             \
        b = rotl32(b, 30);             \
    }

// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf needs to be in algorithm native byte order (md5 = LE, sha1 = BE,
// etc) input buf needs to be 64 byte aligned when using sha1_update()

void sha1_transform(const thread u32* w0, const thread u32* w1, const thread u32* w2, const thread u32* w3, thread u32* digest) {
    u32 a = digest[0];
    u32 b = digest[1];
    u32 c = digest[2];
    u32 d = digest[3];
    u32 e = digest[4];

    u32 w00_t = w0[0];
    u32 w01_t = w0[1];
    u32 w02_t = w0[2];
    u32 w03_t = w0[3];
    u32 w04_t = w1[0];
    u32 w05_t = w1[1];
    u32 w06_t = w1[2];
    u32 w07_t = w1[3];
    u32 w08_t = w2[0];
    u32 w09_t = w2[1];
    u32 w0a_t = w2[2];
    u32 w0b_t = w2[3];
    u32 w0c_t = w3[0];
    u32 w0d_t = w3[1];
    u32 w0e_t = w3[2];
    u32 w0f_t = w3[3];
    u32 w10_t;
    u32 w11_t;
    u32 w12_t;
    u32 w13_t;
    u32 w14_t;
    u32 w15_t;
    u32 w16_t;
    u32 w17_t;
    u32 w18_t;
    u32 w19_t;
    u32 w1a_t;
    u32 w1b_t;
    u32 w1c_t;
    u32 w1d_t;
    u32 w1e_t;
    u32 w1f_t;
    u32 w20_t;
    u32 w21_t;
    u32 w22_t;
    u32 w23_t;
    u32 w24_t;
    u32 w25_t;
    u32 w26_t;
    u32 w27_t;
    u32 w28_t;
    u32 w29_t;
    u32 w2a_t;
    u32 w2b_t;
    u32 w2c_t;
    u32 w2d_t;
    u32 w2e_t;
    u32 w2f_t;
    u32 w30_t;
    u32 w31_t;
    u32 w32_t;
    u32 w33_t;
    u32 w34_t;
    u32 w35_t;
    u32 w36_t;
    u32 w37_t;
    u32 w38_t;
    u32 w39_t;
    u32 w3a_t;
    u32 w3b_t;
    u32 w3c_t;
    u32 w3d_t;
    u32 w3e_t;
    u32 w3f_t;
    u32 w40_t;
    u32 w41_t;
    u32 w42_t;
    u32 w43_t;
    u32 w44_t;
    u32 w45_t;
    u32 w46_t;
    u32 w47_t;
    u32 w48_t;
    u32 w49_t;
    u32 w4a_t;
    u32 w4b_t;
    u32 w4c_t;
    u32 w4d_t;
    u32 w4e_t;
    u32 w4f_t;

#define K SHA1C00

    SHA1_STEP(SHA1_F0o, a, b, c, d, e, w00_t);
    SHA1_STEP(SHA1_F0o, e, a, b, c, d, w01_t);
    SHA1_STEP(SHA1_F0o, d, e, a, b, c, w02_t);
    SHA1_STEP(SHA1_F0o, c, d, e, a, b, w03_t);
    SHA1_STEP(SHA1_F0o, b, c, d, e, a, w04_t);
    SHA1_STEP(SHA1_F0o, a, b, c, d, e, w05_t);
    SHA1_STEP(SHA1_F0o, e, a, b, c, d, w06_t);
    SHA1_STEP(SHA1_F0o, d, e, a, b, c, w07_t);
    SHA1_STEP(SHA1_F0o, c, d, e, a, b, w08_t);
    SHA1_STEP(SHA1_F0o, b, c, d, e, a, w09_t);
    SHA1_STEP(SHA1_F0o, a, b, c, d, e, w0a_t);
    SHA1_STEP(SHA1_F0o, e, a, b, c, d, w0b_t);
    SHA1_STEP(SHA1_F0o, d, e, a, b, c, w0c_t);
    SHA1_STEP(SHA1_F0o, c, d, e, a, b, w0d_t);
    SHA1_STEP(SHA1_F0o, b, c, d, e, a, w0e_t);
    SHA1_STEP(SHA1_F0o, a, b, c, d, e, w0f_t);
    w10_t = rotl32((w0d_t ^ w08_t ^ w02_t ^ w00_t), 1);
    SHA1_STEP(SHA1_F0o, e, a, b, c, d, w10_t);
    w11_t = rotl32((w0e_t ^ w09_t ^ w03_t ^ w01_t), 1);
    SHA1_STEP(SHA1_F0o, d, e, a, b, c, w11_t);
    w12_t = rotl32((w0f_t ^ w0a_t ^ w04_t ^ w02_t), 1);
    SHA1_STEP(SHA1_F0o, c, d, e, a, b, w12_t);
    w13_t = rotl32((w10_t ^ w0b_t ^ w05_t ^ w03_t), 1);
    SHA1_STEP(SHA1_F0o, b, c, d, e, a, w13_t);

#undef K
#define K SHA1C01

    w14_t = rotl32((w11_t ^ w0c_t ^ w06_t ^ w04_t), 1);
    SHA1_STEP(SHA1_F1, a, b, c, d, e, w14_t);
    w15_t = rotl32((w12_t ^ w0d_t ^ w07_t ^ w05_t), 1);
    SHA1_STEP(SHA1_F1, e, a, b, c, d, w15_t);
    w16_t = rotl32((w13_t ^ w0e_t ^ w08_t ^ w06_t), 1);
    SHA1_STEP(SHA1_F1, d, e, a, b, c, w16_t);
    w17_t = rotl32((w14_t ^ w0f_t ^ w09_t ^ w07_t), 1);
    SHA1_STEP(SHA1_F1, c, d, e, a, b, w17_t);
    w18_t = rotl32((w15_t ^ w10_t ^ w0a_t ^ w08_t), 1);
    SHA1_STEP(SHA1_F1, b, c, d, e, a, w18_t);
    w19_t = rotl32((w16_t ^ w11_t ^ w0b_t ^ w09_t), 1);
    SHA1_STEP(SHA1_F1, a, b, c, d, e, w19_t);
    w1a_t = rotl32((w17_t ^ w12_t ^ w0c_t ^ w0a_t), 1);
    SHA1_STEP(SHA1_F1, e, a, b, c, d, w1a_t);
    w1b_t = rotl32((w18_t ^ w13_t ^ w0d_t ^ w0b_t), 1);
    SHA1_STEP(SHA1_F1, d, e, a, b, c, w1b_t);
    w1c_t = rotl32((w19_t ^ w14_t ^ w0e_t ^ w0c_t), 1);
    SHA1_STEP(SHA1_F1, c, d, e, a, b, w1c_t);
    w1d_t = rotl32((w1a_t ^ w15_t ^ w0f_t ^ w0d_t), 1);
    SHA1_STEP(SHA1_F1, b, c, d, e, a, w1d_t);
    w1e_t = rotl32((w1b_t ^ w16_t ^ w10_t ^ w0e_t), 1);
    SHA1_STEP(SHA1_F1, a, b, c, d, e, w1e_t);
    w1f_t = rotl32((w1c_t ^ w17_t ^ w11_t ^ w0f_t), 1);
    SHA1_STEP(SHA1_F1, e, a, b, c, d, w1f_t);
    w20_t = rotl32((w1a_t ^ w10_t ^ w04_t ^ w00_t), 2);
    SHA1_STEP(SHA1_F1, d, e, a, b, c, w20_t);
    w21_t = rotl32((w1b_t ^ w11_t ^ w05_t ^ w01_t), 2);
    SHA1_STEP(SHA1_F1, c, d, e, a, b, w21_t);
    w22_t = rotl32((w1c_t ^ w12_t ^ w06_t ^ w02_t), 2);
    SHA1_STEP(SHA1_F1, b, c, d, e, a, w22_t);
    w23_t = rotl32((w1d_t ^ w13_t ^ w07_t ^ w03_t), 2);
    SHA1_STEP(SHA1_F1, a, b, c, d, e, w23_t);
    w24_t = rotl32((w1e_t ^ w14_t ^ w08_t ^ w04_t), 2);
    SHA1_STEP(SHA1_F1, e, a, b, c, d, w24_t);
    w25_t = rotl32((w1f_t ^ w15_t ^ w09_t ^ w05_t), 2);
    SHA1_STEP(SHA1_F1, d, e, a, b, c, w25_t);
    w26_t = rotl32((w20_t ^ w16_t ^ w0a_t ^ w06_t), 2);
    SHA1_STEP(SHA1_F1, c, d, e, a, b, w26_t);
    w27_t = rotl32((w21_t ^ w17_t ^ w0b_t ^ w07_t), 2);
    SHA1_STEP(SHA1_F1, b, c, d, e, a, w27_t);

#undef K
#define K SHA1C02

    w28_t = rotl32((w22_t ^ w18_t ^ w0c_t ^ w08_t), 2);
    SHA1_STEP(SHA1_F2o, a, b, c, d, e, w28_t);
    w29_t = rotl32((w23_t ^ w19_t ^ w0d_t ^ w09_t), 2);
    SHA1_STEP(SHA1_F2o, e, a, b, c, d, w29_t);
    w2a_t = rotl32((w24_t ^ w1a_t ^ w0e_t ^ w0a_t), 2);
    SHA1_STEP(SHA1_F2o, d, e, a, b, c, w2a_t);
    w2b_t = rotl32((w25_t ^ w1b_t ^ w0f_t ^ w0b_t), 2);
    SHA1_STEP(SHA1_F2o, c, d, e, a, b, w2b_t);
    w2c_t = rotl32((w26_t ^ w1c_t ^ w10_t ^ w0c_t), 2);
    SHA1_STEP(SHA1_F2o, b, c, d, e, a, w2c_t);
    w2d_t = rotl32((w27_t ^ w1d_t ^ w11_t ^ w0d_t), 2);
    SHA1_STEP(SHA1_F2o, a, b, c, d, e, w2d_t);
    w2e_t = rotl32((w28_t ^ w1e_t ^ w12_t ^ w0e_t), 2);
    SHA1_STEP(SHA1_F2o, e, a, b, c, d, w2e_t);
    w2f_t = rotl32((w29_t ^ w1f_t ^ w13_t ^ w0f_t), 2);
    SHA1_STEP(SHA1_F2o, d, e, a, b, c, w2f_t);
    w30_t = rotl32((w2a_t ^ w20_t ^ w14_t ^ w10_t), 2);
    SHA1_STEP(SHA1_F2o, c, d, e, a, b, w30_t);
    w31_t = rotl32((w2b_t ^ w21_t ^ w15_t ^ w11_t), 2);
    SHA1_STEP(SHA1_F2o, b, c, d, e, a, w31_t);
    w32_t = rotl32((w2c_t ^ w22_t ^ w16_t ^ w12_t), 2);
    SHA1_STEP(SHA1_F2o, a, b, c, d, e, w32_t);
    w33_t = rotl32((w2d_t ^ w23_t ^ w17_t ^ w13_t), 2);
    SHA1_STEP(SHA1_F2o, e, a, b, c, d, w33_t);
    w34_t = rotl32((w2e_t ^ w24_t ^ w18_t ^ w14_t), 2);
    SHA1_STEP(SHA1_F2o, d, e, a, b, c, w34_t);
    w35_t = rotl32((w2f_t ^ w25_t ^ w19_t ^ w15_t), 2);
    SHA1_STEP(SHA1_F2o, c, d, e, a, b, w35_t);
    w36_t = rotl32((w30_t ^ w26_t ^ w1a_t ^ w16_t), 2);
    SHA1_STEP(SHA1_F2o, b, c, d, e, a, w36_t);
    w37_t = rotl32((w31_t ^ w27_t ^ w1b_t ^ w17_t), 2);
    SHA1_STEP(SHA1_F2o, a, b, c, d, e, w37_t);
    w38_t = rotl32((w32_t ^ w28_t ^ w1c_t ^ w18_t), 2);
    SHA1_STEP(SHA1_F2o, e, a, b, c, d, w38_t);
    w39_t = rotl32((w33_t ^ w29_t ^ w1d_t ^ w19_t), 2);
    SHA1_STEP(SHA1_F2o, d, e, a, b, c, w39_t);
    w3a_t = rotl32((w34_t ^ w2a_t ^ w1e_t ^ w1a_t), 2);
    SHA1_STEP(SHA1_F2o, c, d, e, a, b, w3a_t);
    w3b_t = rotl32((w35_t ^ w2b_t ^ w1f_t ^ w1b_t), 2);
    SHA1_STEP(SHA1_F2o, b, c, d, e, a, w3b_t);

#undef K
#define K SHA1C03

    w3c_t = rotl32((w36_t ^ w2c_t ^ w20_t ^ w1c_t), 2);
    SHA1_STEP(SHA1_F1, a, b, c, d, e, w3c_t);
    w3d_t = rotl32((w37_t ^ w2d_t ^ w21_t ^ w1d_t), 2);
    SHA1_STEP(SHA1_F1, e, a, b, c, d, w3d_t);
    w3e_t = rotl32((w38_t ^ w2e_t ^ w22_t ^ w1e_t), 2);
    SHA1_STEP(SHA1_F1, d, e, a, b, c, w3e_t);
    w3f_t = rotl32((w39_t ^ w2f_t ^ w23_t ^ w1f_t), 2);
    SHA1_STEP(SHA1_F1, c, d, e, a, b, w3f_t);
    w40_t = rotl32((w34_t ^ w20_t ^ w08_t ^ w00_t), 4);
    SHA1_STEP(SHA1_F1, b, c, d, e, a, w40_t);
    w41_t = rotl32((w35_t ^ w21_t ^ w09_t ^ w01_t), 4);
    SHA1_STEP(SHA1_F1, a, b, c, d, e, w41_t);
    w42_t = rotl32((w36_t ^ w22_t ^ w0a_t ^ w02_t), 4);
    SHA1_STEP(SHA1_F1, e, a, b, c, d, w42_t);
    w43_t = rotl32((w37_t ^ w23_t ^ w0b_t ^ w03_t), 4);
    SHA1_STEP(SHA1_F1, d, e, a, b, c, w43_t);
    w44_t = rotl32((w38_t ^ w24_t ^ w0c_t ^ w04_t), 4);
    SHA1_STEP(SHA1_F1, c, d, e, a, b, w44_t);
    w45_t = rotl32((w39_t ^ w25_t ^ w0d_t ^ w05_t), 4);
    SHA1_STEP(SHA1_F1, b, c, d, e, a, w45_t);
    w46_t = rotl32((w3a_t ^ w26_t ^ w0e_t ^ w06_t), 4);
    SHA1_STEP(SHA1_F1, a, b, c, d, e, w46_t);
    w47_t = rotl32((w3b_t ^ w27_t ^ w0f_t ^ w07_t), 4);
    SHA1_STEP(SHA1_F1, e, a, b, c, d, w47_t);
    w48_t = rotl32((w3c_t ^ w28_t ^ w10_t ^ w08_t), 4);
    SHA1_STEP(SHA1_F1, d, e, a, b, c, w48_t);
    w49_t = rotl32((w3d_t ^ w29_t ^ w11_t ^ w09_t), 4);
    SHA1_STEP(SHA1_F1, c, d, e, a, b, w49_t);
    w4a_t = rotl32((w3e_t ^ w2a_t ^ w12_t ^ w0a_t), 4);
    SHA1_STEP(SHA1_F1, b, c, d, e, a, w4a_t);
    w4b_t = rotl32((w3f_t ^ w2b_t ^ w13_t ^ w0b_t), 4);
    SHA1_STEP(SHA1_F1, a, b, c, d, e, w4b_t);
    w4c_t = rotl32((w40_t ^ w2c_t ^ w14_t ^ w0c_t), 4);
    SHA1_STEP(SHA1_F1, e, a, b, c, d, w4c_t);
    w4d_t = rotl32((w41_t ^ w2d_t ^ w15_t ^ w0d_t), 4);
    SHA1_STEP(SHA1_F1, d, e, a, b, c, w4d_t);
    w4e_t = rotl32((w42_t ^ w2e_t ^ w16_t ^ w0e_t), 4);
    SHA1_STEP(SHA1_F1, c, d, e, a, b, w4e_t);
    w4f_t = rotl32((w43_t ^ w2f_t ^ w17_t ^ w0f_t), 4);
    SHA1_STEP(SHA1_F1, b, c, d, e, a, w4f_t);

#undef K

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
}

void sha1_init(thread sha1_ctx* ctx) {
    ctx->h[0] = SHA1M_A;
    ctx->h[1] = SHA1M_B;
    ctx->h[2] = SHA1M_C;
    ctx->h[3] = SHA1M_D;
    ctx->h[4] = SHA1M_E;

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;

    ctx->len = 0;
}

void sha1_update_64(thread sha1_ctx* ctx, thread u32* w0, thread u32* w1, thread u32* w2, thread u32* w3, const int len) {
    if (len == 0)
        return;

    const int pos = ctx->len & 63;

    ctx->len += len;

    if (pos == 0) {
        ctx->w0[0] = w0[0];
        ctx->w0[1] = w0[1];
        ctx->w0[2] = w0[2];
        ctx->w0[3] = w0[3];
        ctx->w1[0] = w1[0];
        ctx->w1[1] = w1[1];
        ctx->w1[2] = w1[2];
        ctx->w1[3] = w1[3];
        ctx->w2[0] = w2[0];
        ctx->w2[1] = w2[1];
        ctx->w2[2] = w2[2];
        ctx->w2[3] = w2[3];
        ctx->w3[0] = w3[0];
        ctx->w3[1] = w3[1];
        ctx->w3[2] = w3[2];
        ctx->w3[3] = w3[3];

        if (len == 64) {
            sha1_transform(ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

            ctx->w0[0] = 0;
            ctx->w0[1] = 0;
            ctx->w0[2] = 0;
            ctx->w0[3] = 0;
            ctx->w1[0] = 0;
            ctx->w1[1] = 0;
            ctx->w1[2] = 0;
            ctx->w1[3] = 0;
            ctx->w2[0] = 0;
            ctx->w2[1] = 0;
            ctx->w2[2] = 0;
            ctx->w2[3] = 0;
            ctx->w3[0] = 0;
            ctx->w3[1] = 0;
            ctx->w3[2] = 0;
            ctx->w3[3] = 0;
        }
    } else {
        if ((pos + len) < 64) {
            switch_buffer_by_offset_be(w0, w1, w2, w3, pos);

            ctx->w0[0] |= w0[0];
            ctx->w0[1] |= w0[1];
            ctx->w0[2] |= w0[2];
            ctx->w0[3] |= w0[3];
            ctx->w1[0] |= w1[0];
            ctx->w1[1] |= w1[1];
            ctx->w1[2] |= w1[2];
            ctx->w1[3] |= w1[3];
            ctx->w2[0] |= w2[0];
            ctx->w2[1] |= w2[1];
            ctx->w2[2] |= w2[2];
            ctx->w2[3] |= w2[3];
            ctx->w3[0] |= w3[0];
            ctx->w3[1] |= w3[1];
            ctx->w3[2] |= w3[2];
            ctx->w3[3] |= w3[3];
        } else {
            u32 c0[4] = {0};
            u32 c1[4] = {0};
            u32 c2[4] = {0};
            u32 c3[4] = {0};

            switch_buffer_by_offset_carry_be(w0, w1, w2, w3, c0, c1, c2, c3, pos);

            ctx->w0[0] |= w0[0];
            ctx->w0[1] |= w0[1];
            ctx->w0[2] |= w0[2];
            ctx->w0[3] |= w0[3];
            ctx->w1[0] |= w1[0];
            ctx->w1[1] |= w1[1];
            ctx->w1[2] |= w1[2];
            ctx->w1[3] |= w1[3];
            ctx->w2[0] |= w2[0];
            ctx->w2[1] |= w2[1];
            ctx->w2[2] |= w2[2];
            ctx->w2[3] |= w2[3];
            ctx->w3[0] |= w3[0];
            ctx->w3[1] |= w3[1];
            ctx->w3[2] |= w3[2];
            ctx->w3[3] |= w3[3];

            sha1_transform(ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

            ctx->w0[0] = c0[0];
            ctx->w0[1] = c0[1];
            ctx->w0[2] = c0[2];
            ctx->w0[3] = c0[3];
            ctx->w1[0] = c1[0];
            ctx->w1[1] = c1[1];
            ctx->w1[2] = c1[2];
            ctx->w1[3] = c1[3];
            ctx->w2[0] = c2[0];
            ctx->w2[1] = c2[1];
            ctx->w2[2] = c2[2];
            ctx->w2[3] = c2[3];
            ctx->w3[0] = c3[0];
            ctx->w3[1] = c3[1];
            ctx->w3[2] = c3[2];
            ctx->w3[3] = c3[3];
        }
    }
}

void sha1_update(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];
        w2[0] = w[pos4 + 8];
        w2[1] = w[pos4 + 9];
        w2[2] = w[pos4 + 10];
        w2[3] = w[pos4 + 11];
        w3[0] = w[pos4 + 12];
        w3[1] = w[pos4 + 13];
        w3[2] = w[pos4 + 14];
        w3[3] = w[pos4 + 15];

        sha1_update_64(ctx, w0, w1, w2, w3, 64);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];
    w2[0] = w[pos4 + 8];
    w2[1] = w[pos4 + 9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    sha1_update_64(ctx, w0, w1, w2, w3, len - pos1);
}

void sha1_update_swap(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];
        w2[0] = w[pos4 + 8];
        w2[1] = w[pos4 + 9];
        w2[2] = w[pos4 + 10];
        w2[3] = w[pos4 + 11];
        w3[0] = w[pos4 + 12];
        w3[1] = w[pos4 + 13];
        w3[2] = w[pos4 + 14];
        w3[3] = w[pos4 + 15];

        w0[0] = swap32(w0[0]);
        w0[1] = swap32(w0[1]);
        w0[2] = swap32(w0[2]);
        w0[3] = swap32(w0[3]);
        w1[0] = swap32(w1[0]);
        w1[1] = swap32(w1[1]);
        w1[2] = swap32(w1[2]);
        w1[3] = swap32(w1[3]);
        w2[0] = swap32(w2[0]);
        w2[1] = swap32(w2[1]);
        w2[2] = swap32(w2[2]);
        w2[3] = swap32(w2[3]);
        w3[0] = swap32(w3[0]);
        w3[1] = swap32(w3[1]);
        w3[2] = swap32(w3[2]);
        w3[3] = swap32(w3[3]);

        sha1_update_64(ctx, w0, w1, w2, w3, 64);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];
    w2[0] = w[pos4 + 8];
    w2[1] = w[pos4 + 9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    w0[0] = swap32(w0[0]);
    w0[1] = swap32(w0[1]);
    w0[2] = swap32(w0[2]);
    w0[3] = swap32(w0[3]);
    w1[0] = swap32(w1[0]);
    w1[1] = swap32(w1[1]);
    w1[2] = swap32(w1[2]);
    w1[3] = swap32(w1[3]);
    w2[0] = swap32(w2[0]);
    w2[1] = swap32(w2[1]);
    w2[2] = swap32(w2[2]);
    w2[3] = swap32(w2[3]);
    w3[0] = swap32(w3[0]);
    w3[1] = swap32(w3[1]);
    w3[2] = swap32(w3[2]);
    w3[3] = swap32(w3[3]);

    sha1_update_64(ctx, w0, w1, w2, w3, len - pos1);
}

void sha1_update_utf16le(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    if (enc_scan(w, len)) {
        encoder enc;

        enc_init(&enc);

        while (enc_has_next(&enc, len)) {
            u32 enc_buf[16] = {0};

            const int enc_len = enc_next(&enc, w, len, 256, enc_buf, sizeof(enc_buf));

            if (enc_len == -1) {
                ctx->len = -1;

                return;
            }

            sha1_update_64(ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
        }

        return;
    }

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16le(w1, w2, w3);
        make_utf16le(w0, w0, w1);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le(w1, w2, w3);
    make_utf16le(w0, w0, w1);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_update_utf16le_swap(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    if (enc_scan(w, len)) {
        encoder enc;

        enc_init(&enc);

        while (enc_has_next(&enc, len)) {
            u32 enc_buf[16] = {0};

            const int enc_len = enc_next(&enc, w, len, 256, enc_buf, sizeof(enc_buf));

            if (enc_len == -1) {
                ctx->len = -1;

                return;
            }

            enc_buf[0] = swap32(enc_buf[0]);
            enc_buf[1] = swap32(enc_buf[1]);
            enc_buf[2] = swap32(enc_buf[2]);
            enc_buf[3] = swap32(enc_buf[3]);
            enc_buf[4] = swap32(enc_buf[4]);
            enc_buf[5] = swap32(enc_buf[5]);
            enc_buf[6] = swap32(enc_buf[6]);
            enc_buf[7] = swap32(enc_buf[7]);
            enc_buf[8] = swap32(enc_buf[8]);
            enc_buf[9] = swap32(enc_buf[9]);
            enc_buf[10] = swap32(enc_buf[10]);
            enc_buf[11] = swap32(enc_buf[11]);
            enc_buf[12] = swap32(enc_buf[12]);
            enc_buf[13] = swap32(enc_buf[13]);
            enc_buf[14] = swap32(enc_buf[14]);
            enc_buf[15] = swap32(enc_buf[15]);

            sha1_update_64(ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
        }

        return;
    }

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16le(w1, w2, w3);
        make_utf16le(w0, w0, w1);

        w0[0] = swap32(w0[0]);
        w0[1] = swap32(w0[1]);
        w0[2] = swap32(w0[2]);
        w0[3] = swap32(w0[3]);
        w1[0] = swap32(w1[0]);
        w1[1] = swap32(w1[1]);
        w1[2] = swap32(w1[2]);
        w1[3] = swap32(w1[3]);
        w2[0] = swap32(w2[0]);
        w2[1] = swap32(w2[1]);
        w2[2] = swap32(w2[2]);
        w2[3] = swap32(w2[3]);
        w3[0] = swap32(w3[0]);
        w3[1] = swap32(w3[1]);
        w3[2] = swap32(w3[2]);
        w3[3] = swap32(w3[3]);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le(w1, w2, w3);
    make_utf16le(w0, w0, w1);

    w0[0] = swap32(w0[0]);
    w0[1] = swap32(w0[1]);
    w0[2] = swap32(w0[2]);
    w0[3] = swap32(w0[3]);
    w1[0] = swap32(w1[0]);
    w1[1] = swap32(w1[1]);
    w1[2] = swap32(w1[2]);
    w1[3] = swap32(w1[3]);
    w2[0] = swap32(w2[0]);
    w2[1] = swap32(w2[1]);
    w2[2] = swap32(w2[2]);
    w2[3] = swap32(w2[3]);
    w3[0] = swap32(w3[0]);
    w3[1] = swap32(w3[1]);
    w3[2] = swap32(w3[2]);
    w3[3] = swap32(w3[3]);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_update_utf16be(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16be(w1, w2, w3);
        make_utf16be(w0, w0, w1);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16be(w1, w2, w3);
    make_utf16be(w0, w0, w1);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_update_utf16beN(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16beN(w1, w2, w3);
        make_utf16beN(w0, w0, w1);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16beN(w1, w2, w3);
    make_utf16beN(w0, w0, w1);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_update_utf16be_swap(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16be(w1, w2, w3);
        make_utf16be(w0, w0, w1);

        w0[0] = swap32(w0[0]);
        w0[1] = swap32(w0[1]);
        w0[2] = swap32(w0[2]);
        w0[3] = swap32(w0[3]);
        w1[0] = swap32(w1[0]);
        w1[1] = swap32(w1[1]);
        w1[2] = swap32(w1[2]);
        w1[3] = swap32(w1[3]);
        w2[0] = swap32(w2[0]);
        w2[1] = swap32(w2[1]);
        w2[2] = swap32(w2[2]);
        w2[3] = swap32(w2[3]);
        w3[0] = swap32(w3[0]);
        w3[1] = swap32(w3[1]);
        w3[2] = swap32(w3[2]);
        w3[3] = swap32(w3[3]);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16be(w1, w2, w3);
    make_utf16be(w0, w0, w1);

    w0[0] = swap32(w0[0]);
    w0[1] = swap32(w0[1]);
    w0[2] = swap32(w0[2]);
    w0[3] = swap32(w0[3]);
    w1[0] = swap32(w1[0]);
    w1[1] = swap32(w1[1]);
    w1[2] = swap32(w1[2]);
    w1[3] = swap32(w1[3]);
    w2[0] = swap32(w2[0]);
    w2[1] = swap32(w2[1]);
    w2[2] = swap32(w2[2]);
    w2[3] = swap32(w2[3]);
    w3[0] = swap32(w3[0]);
    w3[1] = swap32(w3[1]);
    w3[2] = swap32(w3[2]);
    w3[3] = swap32(w3[3]);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_update_global(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];
        w2[0] = w[pos4 + 8];
        w2[1] = w[pos4 + 9];
        w2[2] = w[pos4 + 10];
        w2[3] = w[pos4 + 11];
        w3[0] = w[pos4 + 12];
        w3[1] = w[pos4 + 13];
        w3[2] = w[pos4 + 14];
        w3[3] = w[pos4 + 15];

        sha1_update_64(ctx, w0, w1, w2, w3, 64);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];
    w2[0] = w[pos4 + 8];
    w2[1] = w[pos4 + 9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    sha1_update_64(ctx, w0, w1, w2, w3, len - pos1);
}

void sha1_update_global_swap(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];
        w2[0] = w[pos4 + 8];
        w2[1] = w[pos4 + 9];
        w2[2] = w[pos4 + 10];
        w2[3] = w[pos4 + 11];
        w3[0] = w[pos4 + 12];
        w3[1] = w[pos4 + 13];
        w3[2] = w[pos4 + 14];
        w3[3] = w[pos4 + 15];

        w0[0] = swap32(w0[0]);
        w0[1] = swap32(w0[1]);
        w0[2] = swap32(w0[2]);
        w0[3] = swap32(w0[3]);
        w1[0] = swap32(w1[0]);
        w1[1] = swap32(w1[1]);
        w1[2] = swap32(w1[2]);
        w1[3] = swap32(w1[3]);
        w2[0] = swap32(w2[0]);
        w2[1] = swap32(w2[1]);
        w2[2] = swap32(w2[2]);
        w2[3] = swap32(w2[3]);
        w3[0] = swap32(w3[0]);
        w3[1] = swap32(w3[1]);
        w3[2] = swap32(w3[2]);
        w3[3] = swap32(w3[3]);

        sha1_update_64(ctx, w0, w1, w2, w3, 64);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];
    w2[0] = w[pos4 + 8];
    w2[1] = w[pos4 + 9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    w0[0] = swap32(w0[0]);
    w0[1] = swap32(w0[1]);
    w0[2] = swap32(w0[2]);
    w0[3] = swap32(w0[3]);
    w1[0] = swap32(w1[0]);
    w1[1] = swap32(w1[1]);
    w1[2] = swap32(w1[2]);
    w1[3] = swap32(w1[3]);
    w2[0] = swap32(w2[0]);
    w2[1] = swap32(w2[1]);
    w2[2] = swap32(w2[2]);
    w2[3] = swap32(w2[3]);
    w3[0] = swap32(w3[0]);
    w3[1] = swap32(w3[1]);
    w3[2] = swap32(w3[2]);
    w3[3] = swap32(w3[3]);

    sha1_update_64(ctx, w0, w1, w2, w3, len - pos1);
}

void sha1_update_global_utf16le(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    if (enc_scan_global(w, len)) {
        encoder enc;

        enc_init(&enc);

        while (enc_has_next(&enc, len)) {
            u32 enc_buf[16] = {0};

            const int enc_len = enc_next_global(&enc, w, len, 256, enc_buf, sizeof(enc_buf));

            if (enc_len == -1) {
                ctx->len = -1;

                return;
            }

            sha1_update_64(ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
        }

        return;
    }

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16le(w1, w2, w3);
        make_utf16le(w0, w0, w1);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le(w1, w2, w3);
    make_utf16le(w0, w0, w1);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_update_global_utf16le_swap(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    if (enc_scan_global(w, len)) {
        encoder enc;

        enc_init(&enc);

        while (enc_has_next(&enc, len)) {
            u32 enc_buf[16] = {0};

            const int enc_len = enc_next_global(&enc, w, len, 256, enc_buf, sizeof(enc_buf));

            if (enc_len == -1) {
                ctx->len = -1;

                return;
            }

            enc_buf[0] = swap32(enc_buf[0]);
            enc_buf[1] = swap32(enc_buf[1]);
            enc_buf[2] = swap32(enc_buf[2]);
            enc_buf[3] = swap32(enc_buf[3]);
            enc_buf[4] = swap32(enc_buf[4]);
            enc_buf[5] = swap32(enc_buf[5]);
            enc_buf[6] = swap32(enc_buf[6]);
            enc_buf[7] = swap32(enc_buf[7]);
            enc_buf[8] = swap32(enc_buf[8]);
            enc_buf[9] = swap32(enc_buf[9]);
            enc_buf[10] = swap32(enc_buf[10]);
            enc_buf[11] = swap32(enc_buf[11]);
            enc_buf[12] = swap32(enc_buf[12]);
            enc_buf[13] = swap32(enc_buf[13]);
            enc_buf[14] = swap32(enc_buf[14]);
            enc_buf[15] = swap32(enc_buf[15]);

            sha1_update_64(ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
        }

        return;
    }

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16le(w1, w2, w3);
        make_utf16le(w0, w0, w1);

        w0[0] = swap32(w0[0]);
        w0[1] = swap32(w0[1]);
        w0[2] = swap32(w0[2]);
        w0[3] = swap32(w0[3]);
        w1[0] = swap32(w1[0]);
        w1[1] = swap32(w1[1]);
        w1[2] = swap32(w1[2]);
        w1[3] = swap32(w1[3]);
        w2[0] = swap32(w2[0]);
        w2[1] = swap32(w2[1]);
        w2[2] = swap32(w2[2]);
        w2[3] = swap32(w2[3]);
        w3[0] = swap32(w3[0]);
        w3[1] = swap32(w3[1]);
        w3[2] = swap32(w3[2]);
        w3[3] = swap32(w3[3]);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le(w1, w2, w3);
    make_utf16le(w0, w0, w1);

    w0[0] = swap32(w0[0]);
    w0[1] = swap32(w0[1]);
    w0[2] = swap32(w0[2]);
    w0[3] = swap32(w0[3]);
    w1[0] = swap32(w1[0]);
    w1[1] = swap32(w1[1]);
    w1[2] = swap32(w1[2]);
    w1[3] = swap32(w1[3]);
    w2[0] = swap32(w2[0]);
    w2[1] = swap32(w2[1]);
    w2[2] = swap32(w2[2]);
    w2[3] = swap32(w2[3]);
    w3[0] = swap32(w3[0]);
    w3[1] = swap32(w3[1]);
    w3[2] = swap32(w3[2]);
    w3[3] = swap32(w3[3]);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_update_global_utf16be(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16be(w1, w2, w3);
        make_utf16be(w0, w0, w1);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16be(w1, w2, w3);
    make_utf16be(w0, w0, w1);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_update_global_utf16be_swap(thread sha1_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    int pos1;
    int pos4;

    for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8) {
        w0[0] = w[pos4 + 0];
        w0[1] = w[pos4 + 1];
        w0[2] = w[pos4 + 2];
        w0[3] = w[pos4 + 3];
        w1[0] = w[pos4 + 4];
        w1[1] = w[pos4 + 5];
        w1[2] = w[pos4 + 6];
        w1[3] = w[pos4 + 7];

        make_utf16be(w1, w2, w3);
        make_utf16be(w0, w0, w1);

        w0[0] = swap32(w0[0]);
        w0[1] = swap32(w0[1]);
        w0[2] = swap32(w0[2]);
        w0[3] = swap32(w0[3]);
        w1[0] = swap32(w1[0]);
        w1[1] = swap32(w1[1]);
        w1[2] = swap32(w1[2]);
        w1[3] = swap32(w1[3]);
        w2[0] = swap32(w2[0]);
        w2[1] = swap32(w2[1]);
        w2[2] = swap32(w2[2]);
        w2[3] = swap32(w2[3]);
        w3[0] = swap32(w3[0]);
        w3[1] = swap32(w3[1]);
        w3[2] = swap32(w3[2]);
        w3[3] = swap32(w3[3]);

        sha1_update_64(ctx, w0, w1, w2, w3, 32 * 2);
    }

    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16be(w1, w2, w3);
    make_utf16be(w0, w0, w1);

    w0[0] = swap32(w0[0]);
    w0[1] = swap32(w0[1]);
    w0[2] = swap32(w0[2]);
    w0[3] = swap32(w0[3]);
    w1[0] = swap32(w1[0]);
    w1[1] = swap32(w1[1]);
    w1[2] = swap32(w1[2]);
    w1[3] = swap32(w1[3]);
    w2[0] = swap32(w2[0]);
    w2[1] = swap32(w2[1]);
    w2[2] = swap32(w2[2]);
    w2[3] = swap32(w2[3]);
    w3[0] = swap32(w3[0]);
    w3[1] = swap32(w3[1]);
    w3[2] = swap32(w3[2]);
    w3[3] = swap32(w3[3]);

    sha1_update_64(ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

void sha1_final(thread sha1_ctx* ctx) {
    const int pos = ctx->len & 63;

    append_0x80_4x4(ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

    if (pos >= 56) {
        sha1_transform(ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

        ctx->w0[0] = 0;
        ctx->w0[1] = 0;
        ctx->w0[2] = 0;
        ctx->w0[3] = 0;
        ctx->w1[0] = 0;
        ctx->w1[1] = 0;
        ctx->w1[2] = 0;
        ctx->w1[3] = 0;
        ctx->w2[0] = 0;
        ctx->w2[1] = 0;
        ctx->w2[2] = 0;
        ctx->w2[3] = 0;
        ctx->w3[0] = 0;
        ctx->w3[1] = 0;
        ctx->w3[2] = 0;
        ctx->w3[3] = 0;
    }

    ctx->w3[2] = 0;
    ctx->w3[3] = ctx->len * 8;

    sha1_transform(ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

// sha1_hmac

void sha1_hmac_init_64(
    thread sha1_hmac_ctx* ctx,
    const thread u32* w0,
    const thread u32* w1,
    const thread u32* w2,
    const thread u32* w3) {
    u32 a0[4];
    u32 a1[4];
    u32 a2[4];
    u32 a3[4];

    // ipad

    a0[0] = w0[0] ^ 0x36363636;
    a0[1] = w0[1] ^ 0x36363636;
    a0[2] = w0[2] ^ 0x36363636;
    a0[3] = w0[3] ^ 0x36363636;
    a1[0] = w1[0] ^ 0x36363636;
    a1[1] = w1[1] ^ 0x36363636;
    a1[2] = w1[2] ^ 0x36363636;
    a1[3] = w1[3] ^ 0x36363636;
    a2[0] = w2[0] ^ 0x36363636;
    a2[1] = w2[1] ^ 0x36363636;
    a2[2] = w2[2] ^ 0x36363636;
    a2[3] = w2[3] ^ 0x36363636;
    a3[0] = w3[0] ^ 0x36363636;
    a3[1] = w3[1] ^ 0x36363636;
    a3[2] = w3[2] ^ 0x36363636;
    a3[3] = w3[3] ^ 0x36363636;

    sha1_init(&ctx->ipad);

    sha1_update_64(&ctx->ipad, a0, a1, a2, a3, 64);

    // opad

    u32 b0[4];
    u32 b1[4];
    u32 b2[4];
    u32 b3[4];

    b0[0] = w0[0] ^ 0x5c5c5c5c;
    b0[1] = w0[1] ^ 0x5c5c5c5c;
    b0[2] = w0[2] ^ 0x5c5c5c5c;
    b0[3] = w0[3] ^ 0x5c5c5c5c;
    b1[0] = w1[0] ^ 0x5c5c5c5c;
    b1[1] = w1[1] ^ 0x5c5c5c5c;
    b1[2] = w1[2] ^ 0x5c5c5c5c;
    b1[3] = w1[3] ^ 0x5c5c5c5c;
    b2[0] = w2[0] ^ 0x5c5c5c5c;
    b2[1] = w2[1] ^ 0x5c5c5c5c;
    b2[2] = w2[2] ^ 0x5c5c5c5c;
    b2[3] = w2[3] ^ 0x5c5c5c5c;
    b3[0] = w3[0] ^ 0x5c5c5c5c;
    b3[1] = w3[1] ^ 0x5c5c5c5c;
    b3[2] = w3[2] ^ 0x5c5c5c5c;
    b3[3] = w3[3] ^ 0x5c5c5c5c;

    sha1_init(&ctx->opad);

    sha1_update_64(&ctx->opad, b0, b1, b2, b3, 64);
}

void sha1_hmac_init(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    if (len > 64) {
        sha1_ctx tmp;

        sha1_init(&tmp);

        sha1_update(&tmp, w, len);

        sha1_final(&tmp);

        w0[0] = tmp.h[0];
        w0[1] = tmp.h[1];
        w0[2] = tmp.h[2];
        w0[3] = tmp.h[3];
        w1[0] = tmp.h[4];
        w1[1] = 0;
        w1[2] = 0;
        w1[3] = 0;
        w2[0] = 0;
        w2[1] = 0;
        w2[2] = 0;
        w2[3] = 0;
        w3[0] = 0;
        w3[1] = 0;
        w3[2] = 0;
        w3[3] = 0;
    } else {
        w0[0] = w[0];
        w0[1] = w[1];
        w0[2] = w[2];
        w0[3] = w[3];
        w1[0] = w[4];
        w1[1] = w[5];
        w1[2] = w[6];
        w1[3] = w[7];
        w2[0] = w[8];
        w2[1] = w[9];
        w2[2] = w[10];
        w2[3] = w[11];
        w3[0] = w[12];
        w3[1] = w[13];
        w3[2] = w[14];
        w3[3] = w[15];
    }

    sha1_hmac_init_64(ctx, w0, w1, w2, w3);
}

void sha1_hmac_init_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    if (len > 64) {
        sha1_ctx tmp;

        sha1_init(&tmp);

        sha1_update_swap(&tmp, w, len);

        sha1_final(&tmp);

        w0[0] = tmp.h[0];
        w0[1] = tmp.h[1];
        w0[2] = tmp.h[2];
        w0[3] = tmp.h[3];
        w1[0] = tmp.h[4];
        w1[1] = 0;
        w1[2] = 0;
        w1[3] = 0;
        w2[0] = 0;
        w2[1] = 0;
        w2[2] = 0;
        w2[3] = 0;
        w3[0] = 0;
        w3[1] = 0;
        w3[2] = 0;
        w3[3] = 0;
    } else {
        w0[0] = swap32(w[0]);
        w0[1] = swap32(w[1]);
        w0[2] = swap32(w[2]);
        w0[3] = swap32(w[3]);
        w1[0] = swap32(w[4]);
        w1[1] = swap32(w[5]);
        w1[2] = swap32(w[6]);
        w1[3] = swap32(w[7]);
        w2[0] = swap32(w[8]);
        w2[1] = swap32(w[9]);
        w2[2] = swap32(w[10]);
        w2[3] = swap32(w[11]);
        w3[0] = swap32(w[12]);
        w3[1] = swap32(w[13]);
        w3[2] = swap32(w[14]);
        w3[3] = swap32(w[15]);
    }

    sha1_hmac_init_64(ctx, w0, w1, w2, w3);
}

void sha1_hmac_init_global(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    if (len > 64) {
        sha1_ctx tmp;

        sha1_init(&tmp);

        sha1_update_global(&tmp, w, len);

        sha1_final(&tmp);

        w0[0] = tmp.h[0];
        w0[1] = tmp.h[1];
        w0[2] = tmp.h[2];
        w0[3] = tmp.h[3];
        w1[0] = tmp.h[4];
        w1[1] = 0;
        w1[2] = 0;
        w1[3] = 0;
        w2[0] = 0;
        w2[1] = 0;
        w2[2] = 0;
        w2[3] = 0;
        w3[0] = 0;
        w3[1] = 0;
        w3[2] = 0;
        w3[3] = 0;
    } else {
        w0[0] = w[0];
        w0[1] = w[1];
        w0[2] = w[2];
        w0[3] = w[3];
        w1[0] = w[4];
        w1[1] = w[5];
        w1[2] = w[6];
        w1[3] = w[7];
        w2[0] = w[8];
        w2[1] = w[9];
        w2[2] = w[10];
        w2[3] = w[11];
        w3[0] = w[12];
        w3[1] = w[13];
        w3[2] = w[14];
        w3[3] = w[15];
    }

    sha1_hmac_init_64(ctx, w0, w1, w2, w3);
}

void sha1_hmac_init_global_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    if (len > 64) {
        sha1_ctx tmp;

        sha1_init(&tmp);

        sha1_update_global_swap(&tmp, w, len);

        sha1_final(&tmp);

        w0[0] = tmp.h[0];
        w0[1] = tmp.h[1];
        w0[2] = tmp.h[2];
        w0[3] = tmp.h[3];
        w1[0] = tmp.h[4];
        w1[1] = 0;
        w1[2] = 0;
        w1[3] = 0;
        w2[0] = 0;
        w2[1] = 0;
        w2[2] = 0;
        w2[3] = 0;
        w3[0] = 0;
        w3[1] = 0;
        w3[2] = 0;
        w3[3] = 0;
    } else {
        w0[0] = swap32(w[0]);
        w0[1] = swap32(w[1]);
        w0[2] = swap32(w[2]);
        w0[3] = swap32(w[3]);
        w1[0] = swap32(w[4]);
        w1[1] = swap32(w[5]);
        w1[2] = swap32(w[6]);
        w1[3] = swap32(w[7]);
        w2[0] = swap32(w[8]);
        w2[1] = swap32(w[9]);
        w2[2] = swap32(w[10]);
        w2[3] = swap32(w[11]);
        w3[0] = swap32(w[12]);
        w3[1] = swap32(w[13]);
        w3[2] = swap32(w[14]);
        w3[3] = swap32(w[15]);
    }

    sha1_hmac_init_64(ctx, w0, w1, w2, w3);
}

void sha1_hmac_init_global_utf16le_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    if (enc_scan_global(w, len)) {
        encoder enc;

        enc_init(&enc);

        while (enc_has_next(&enc, len)) {
            // forced full decode in one round

            u32 enc_buf[256];

            const int enc_len = enc_next_global(&enc, w, len, 256, enc_buf, sizeof(enc_buf));

            if (enc_len == -1) {
                // hmac doesn't have password length
                // ctx->len = -1;

                return;
            }

            if (enc_len > 64) {
                sha1_ctx tmp;

                sha1_init(&tmp);

                sha1_update_utf16le_swap(&tmp, enc_buf, enc_len);

                sha1_final(&tmp);

                enc_buf[0] = tmp.h[0];
                enc_buf[1] = tmp.h[1];
                enc_buf[2] = tmp.h[2];
                enc_buf[3] = tmp.h[3];
                enc_buf[4] = tmp.h[4];
                enc_buf[5] = 0;
                enc_buf[6] = 0;
                enc_buf[7] = 0;
                enc_buf[8] = 0;
                enc_buf[9] = 0;
                enc_buf[10] = 0;
                enc_buf[11] = 0;
                enc_buf[12] = 0;
                enc_buf[13] = 0;
                enc_buf[14] = 0;
                enc_buf[15] = 0;
            } else {
                enc_buf[0] = swap32(enc_buf[0]);
                enc_buf[1] = swap32(enc_buf[1]);
                enc_buf[2] = swap32(enc_buf[2]);
                enc_buf[3] = swap32(enc_buf[3]);
                enc_buf[4] = swap32(enc_buf[4]);
                enc_buf[5] = swap32(enc_buf[5]);
                enc_buf[6] = swap32(enc_buf[6]);
                enc_buf[7] = swap32(enc_buf[7]);
                enc_buf[8] = swap32(enc_buf[8]);
                enc_buf[9] = swap32(enc_buf[9]);
                enc_buf[10] = swap32(enc_buf[10]);
                enc_buf[11] = swap32(enc_buf[11]);
                enc_buf[12] = swap32(enc_buf[12]);
                enc_buf[13] = swap32(enc_buf[13]);
                enc_buf[14] = swap32(enc_buf[14]);
                enc_buf[15] = swap32(enc_buf[15]);
            }

            sha1_hmac_init_64(ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12);
        }

        return;
    }

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    const int len_new = len * 2;

    if (len_new > 64) {
        sha1_ctx tmp;

        sha1_init(&tmp);

        sha1_update_global_utf16le_swap(&tmp, w, len);

        sha1_final(&tmp);

        w0[0] = tmp.h[0];
        w0[1] = tmp.h[1];
        w0[2] = tmp.h[2];
        w0[3] = tmp.h[3];
        w1[0] = tmp.h[4];
        w1[1] = 0;
        w1[2] = 0;
        w1[3] = 0;
        w2[0] = 0;
        w2[1] = 0;
        w2[2] = 0;
        w2[3] = 0;
        w3[0] = 0;
        w3[1] = 0;
        w3[2] = 0;
        w3[3] = 0;
    } else {
        w0[0] = w[0];
        w0[1] = w[1];
        w0[2] = w[2];
        w0[3] = w[3];
        w1[0] = w[4];
        w1[1] = w[5];
        w1[2] = w[6];
        w1[3] = w[7];

        make_utf16le(w1, w2, w3);
        make_utf16le(w0, w0, w1);

        w0[0] = swap32(w0[0]);
        w0[1] = swap32(w0[1]);
        w0[2] = swap32(w0[2]);
        w0[3] = swap32(w0[3]);
        w1[0] = swap32(w1[0]);
        w1[1] = swap32(w1[1]);
        w1[2] = swap32(w1[2]);
        w1[3] = swap32(w1[3]);
        w2[0] = swap32(w2[0]);
        w2[1] = swap32(w2[1]);
        w2[2] = swap32(w2[2]);
        w2[3] = swap32(w2[3]);
        w3[0] = swap32(w3[0]);
        w3[1] = swap32(w3[1]);
        w3[2] = swap32(w3[2]);
        w3[3] = swap32(w3[3]);
    }

    sha1_hmac_init_64(ctx, w0, w1, w2, w3);
}

void sha1_hmac_update_64(thread sha1_hmac_ctx* ctx, thread u32* w0, thread u32* w1, thread u32* w2, thread u32* w3, const int len) {
    sha1_update_64(&ctx->ipad, w0, w1, w2, w3, len);
}

void sha1_hmac_update(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    sha1_update(&ctx->ipad, w, len);
}

void sha1_hmac_update_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    sha1_update_swap(&ctx->ipad, w, len);
}

void sha1_hmac_update_utf16le(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    sha1_update_utf16le(&ctx->ipad, w, len);
}

void sha1_hmac_update_utf16le_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    sha1_update_utf16le_swap(&ctx->ipad, w, len);
}

void sha1_hmac_update_global(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    sha1_update_global(&ctx->ipad, w, len);
}

void sha1_hmac_update_global_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    sha1_update_global_swap(&ctx->ipad, w, len);
}

void sha1_hmac_update_global_utf16le(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    sha1_update_global_utf16le(&ctx->ipad, w, len);
}

void sha1_hmac_update_global_utf16le_swap(thread sha1_hmac_ctx* ctx, const thread u32* w, const int len) {
    sha1_update_global_utf16le_swap(&ctx->ipad, w, len);
}

void sha1_hmac_final(thread sha1_hmac_ctx* ctx) {
    sha1_final(&ctx->ipad);

    ctx->opad.w0[0] = ctx->ipad.h[0];
    ctx->opad.w0[1] = ctx->ipad.h[1];
    ctx->opad.w0[2] = ctx->ipad.h[2];
    ctx->opad.w0[3] = ctx->ipad.h[3];
    ctx->opad.w1[0] = ctx->ipad.h[4];
    ctx->opad.w1[1] = 0;
    ctx->opad.w1[2] = 0;
    ctx->opad.w1[3] = 0;
    ctx->opad.w2[0] = 0;
    ctx->opad.w2[1] = 0;
    ctx->opad.w2[2] = 0;
    ctx->opad.w2[3] = 0;
    ctx->opad.w3[0] = 0;
    ctx->opad.w3[1] = 0;
    ctx->opad.w3[2] = 0;
    ctx->opad.w3[3] = 0;

    ctx->opad.len += 20;

    sha1_final(&ctx->opad);
}

kernel void test_sha1_hmac(device u32 hash[5]) {
    constant char *data = "whatwhat";
    u64 data_len = 8;

    constant char *key = "secr";
    u64 key_len = 4;

    u32 data_padded[16] = {0};
    data_padded[0] = swap32(reinterpret_cast<constant u32*>(data)[0]);
    data_padded[1] = swap32(reinterpret_cast<constant u32*>(data)[1]);

    u32 key_padded[16] = {0};
    key_padded[0] = swap32(reinterpret_cast<constant u32*>(key)[0]);

    sha1_hmac_ctx hmac_ctx;
    sha1_hmac_init(&hmac_ctx, key_padded, key_len);
    sha1_hmac_update(&hmac_ctx, data_padded, data_len);
    sha1_hmac_final(&hmac_ctx);

    #pragma unroll
    for (u64 idx = 0; idx < 5; idx++)
        hash[idx] = swap32(hmac_ctx.opad.h[idx]);
}

/* ---------------------- SHA1 AND HMAC END ------------------------ */

struct GlobalContext {
    u8 mac_ap[6];
    u8 mac_sta[6];
    u32 target_hash[5];

    u8 pattern[64];
    u64 pattern_len;

    u64 hashes_to_check;

    u8 passphrase[64];
    bool found_passphrase;
    // device atomic<ulong> *total_hash_count;
};

// = "PMK Name" + mac_ap + mac_sta
void pmkid_msg_init(u8 msg[20], device const u8 mac_ap[6], device const u8 mac_sta[6]) {
    msg[0] = 'P';
    msg[1] = 'M';
    msg[2] = 'K';
    msg[3] = ' ';
    msg[4] = 'N';
    msg[5] = 'a';
    msg[6] = 'm';
    msg[7] = 'e';

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 8] = mac_ap[idx];

    for (u64 idx = 0; idx < 6; idx++)
        msg[idx + 14] = mac_sta[idx];
}

constant u64 STAT_REPORT_INTERVAL = 10000;

bool pmkid(
        device GlobalContext *ctx,
        thread sha1_hmac_ctx *hmac_ctx,
        thread u32 hash[5],
        thread u64 &hash_count,
        thread u8 msg[20],
        thread const u8 current[64]) {

    sha1_hmac_init(hmac_ctx, (thread const u32*)current, 64);
    sha1_hmac_update(hmac_ctx, (thread u32*)msg, 20);
    sha1_hmac_final(hmac_ctx);

    #pragma unroll
    for (u64 idx = 0; idx < 5; idx++)
        hash[idx] = swap32(hmac_ctx->opad.h[idx]);

    hash_count++;

    if (hash_count == STAT_REPORT_INTERVAL) {
        // u64 total_hash_count = atomic_load_explicit(ctx->total_hash_count, memory_order_relaxed);
        // atomic_store_explicit(ctx->total_hash_count, total_hash_count + hash_count, memory_order_relaxed);
        // atomic_fence();

        ctx->found_passphrase = true;
        hash_count = 0;
    }

    #pragma unroll
    for (u64 idx = 0; idx < 5; idx++)
        if (hash[idx] != ctx->target_hash[idx])
            // Keep looking for matching hashes.
            return true;

    // Notify CPU of the passphrase we found.
    #pragma unroll
    for (u64 idx = 0; idx < 64; idx++)
        ctx->passphrase[idx] = current[idx];
    ctx->found_passphrase = true;

    return false;
}

constant u8 DIGITS[] =
    "\0"
    " "
    "0123456789";
constant u8 LOWERCASE[] =
    "\0"
    " "
    "abcdefghijklmnopqrstuvwxyz";
constant u8 UPPERCASE[] =
    "\0"
    " "
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constant u8 ALPHA[] =
    "\0"
    " "
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constant u8 ALPHA_NUM[] =
    "\0"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constant u8 ANY[] =
    "\0"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

// Function to initialize indices based on a given index.
inline void initialize_indices(u64 current_idx, u32 indices[], const u32 set_sizes[], u64 len) {
    for (u64 idx = 0; idx < len; idx++) {
        u32 set_size = set_sizes[idx];
        indices[idx] = current_idx % set_size;
        current_idx /= set_size;
    }
}

#define LEN 64

kernel void hash_and_generate_permutations(
        device GlobalContext* ctx,
        uint id [[thread_position_in_grid]],
        uint tcount [[threads_per_grid]]) {
    u8 current[LEN] = {0};
    u64 len = ctx->pattern_len;

    // Precompute character sets for each position in the pattern.
    constant u8* char_sets[LEN];
    u32 set_sizes[LEN];

    for (u64 idx = 0; idx < len; idx++) {
        switch (ctx->pattern[idx]) {
            case 'd':
                char_sets[idx] = DIGITS;
                set_sizes[idx] = sizeof(DIGITS);
                break;
            case 'l':
                char_sets[idx] = LOWERCASE;
                set_sizes[idx] = sizeof(LOWERCASE);
                break;
            case 'u':
                char_sets[idx] = UPPERCASE;
                set_sizes[idx] = sizeof(UPPERCASE);
                break;
            case 'a':
                char_sets[idx] = ALPHA;
                set_sizes[idx] = sizeof(ALPHA);
                break;
            case 'n':
                char_sets[idx] = ALPHA_NUM;
                set_sizes[idx] = sizeof(ALPHA_NUM);
                break;
            case '?':
                char_sets[idx] = ANY;
                set_sizes[idx] = sizeof(ANY);
                break;
            default:
                return; // this is an error
        }
    }

    // Calculate the total number of permutations.
    u64 perms = 1;
    for (u64 idx = 0; idx < len; ++idx)
        perms *= set_sizes[idx];

    // Calculate the range of permutations this chunk will handle.
    u64 stride = 1024 * 64;
    u64 start_idx = id * stride;
    u64 end_idx = perms;

    // Initialize indices to start at start_index.
    u32 indices[LEN];
    initialize_indices(start_idx, indices, set_sizes, len);

    u32 hash[5];
    u64 hash_count = 0;

    u8 pmk_msg[20];
    pmkid_msg_init(pmk_msg, ctx->mac_ap, ctx->mac_sta);

    sha1_hmac_ctx hmac_ctx;

    while (start_idx < end_idx) {
        // Construct the current permutation based on indices.
        for (u64 idx = 0; idx < len; idx++)
            current[idx] = char_sets[idx][indices[idx]];

        if (!pmkid(ctx, &hmac_ctx, hash, hash_count, pmk_msg, current))
            return;

        // Increment indices from left to right.
        u64 pos = 0;
        while (pos < len) {
            if (indices[pos] < set_sizes[pos] - 1) {
                indices[pos]++;
                break;
            } else {
                indices[pos] = 0;
                pos++;
            }
        }

        // All permutations generated
        if (pos == len)
            break;

        start_idx++;

        // If we've completed a stride, move to the next chunk's corresponding stride.
        if (start_idx % stride == 0) {
            start_idx += (tcount - 1) * stride;
            initialize_indices(start_idx, indices, set_sizes, len);
        }
    }
}

