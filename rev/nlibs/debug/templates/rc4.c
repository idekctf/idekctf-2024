#include "rc4.h"
#include "util.h"

void swap_rc4(uint8_t* a, uint8_t* b){
	uint8_t tmp = *a;
	*a = *b;
	*b = tmp;
	return;
}

struct rc4_t* init_rc4(uint8_t* key, int len){
	struct rc4_t* rc4 = (struct rc4_t*)malloc(sizeof(struct rc4_t));
	for(int i=0; i<256; i++){
		rc4->S[i]=i;
	}
	rc4->i = 0;
	rc4->j = 0;
	int j = 0;
	for(int i=0; i<256; i++){
		j = (j + rc4->S[i] + key[i % len]) % 256;
		swap_rc4(rc4->S+i, rc4->S+j);
	}
	return rc4;
}

uint8_t genByte(struct rc4_t* rc4){
	rc4->i = (rc4->i + 1) % 256;
	rc4->j = (rc4->j + rc4->S[rc4->i]) % 256;
	swap_rc4(rc4->S+rc4->i, rc4->S+rc4->j);
	int t = (rc4->S[rc4->i]+rc4->S[rc4->j]) % 256;
	return rc4->S[t];
}

void encrypt_rc4(struct rc4_t* rc4, uint8_t* enc, int len){
	for(int i=0; i<len; i++){
		enc[i] ^= genByte(rc4);
	}
	return;
}

void rc4_entry(struct string* str){
	struct rc4_t* rc4 = init_rc4((uint8_t*)"PLACEHOLDER", 1337);
	encrypt_rc4(rc4, (uint8_t*)str->buf, str->len);
	free(rc4);
}