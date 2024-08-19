#include "sha1.h"
#include "util.h"

#ifndef ROTLEFT
#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))
#endif

void sha1_transform(struct sha_ctx* ctx, uint8_t* data) {
    uint32_t m[80];
    int i=0;
    int j=0;
    for(; i<16;){
        m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j+3]);
        i++;
        j+=4;
    }
    for(; i<80; i++){
        m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
        m[i] = (m[i] << 1) | (m[i] >> 31);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t t;

	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

void sha1_init(struct sha_ctx* ctx){
	memset(ctx, 0, sizeof(struct sha_ctx));
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
}

void sha1_update(struct sha_ctx* ctx, uint8_t* data, int len){
    for(int i=0; i<len; i++){
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if(ctx->datalen == 64){
            sha1_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha1_final(struct sha_ctx* ctx, uint8_t* _hash){
    uint32_t i;

	i = ctx->datalen;

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha1_transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		_hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		_hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		_hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		_hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		_hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}

void sha1_hash(uint8_t* str, int len, uint8_t* _hash){
    struct sha_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, str, len);
    sha1_final(&ctx, _hash);
}

void sha1_entry(struct string* str) {
    uint8_t hsh[20];
    pad(str, 3);
    uint8_t* buf = malloc(str->len * 2);
    int len = 0;
    for(int i=0; i<str->len; i+=3){
        sha1_hash(&(str->buf[i]), 3, hsh);
        for(int j=0; j<6; j++){
            buf[len++] = hsh[j];
        }
    }
    free(str->buf);
    str->buf = buf;
    str->len = len;
}