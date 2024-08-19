
#include "tea.h"
#include "util.h"

#ifndef BLOCK_SIZE
#define BLOCK_SIZE 8
#endif

void encrypt_tea(uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;
    uint32_t delta=0x9E3779B9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i<32; i++) {
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }
    v[0]=v0; v[1]=v1;
}




void tea_entry(struct string* str){
    pad(str, BLOCK_SIZE);
    uint32_t* buf = (uint32_t*)str->buf;
    uint32_t* key = (uint32_t[]){PLACEHOLDER};
    for(int i=0; i<str->len / sizeof(uint32_t); i += 2){
        encrypt_tea(&(buf[i]), key);
    }
}