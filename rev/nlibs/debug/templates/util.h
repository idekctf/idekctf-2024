#pragma once

#define uint8_t unsigned char
#define int8_t char
#define uint16_t unsigned short
#define int16_t short
#define uint32_t unsigned int
#define int32_t int
#define uint64_t unsigned long long
#define int64_t long long

struct string{
	uint8_t* buf;
	int len;
};

void pad(struct string* str, int block_size){
    int leftover = (block_size - (str->len % block_size)) % block_size;
    str->buf = realloc(str->buf, leftover + str->len);
    memset(&(str->buf[str->len]), 0, leftover);
    str->len += leftover;
}

void print(struct string* str){
	for(int i=0; i<str->len; i++){
		printf("%02X ", str->buf[i]);
	}
	printf("\n");
}