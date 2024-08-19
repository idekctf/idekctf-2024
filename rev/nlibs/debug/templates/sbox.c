#include "sbox.h"
#include "util.h"

void sbox_entry(struct string* str){
	uint8_t* sbox = (uint8_t[]){PLACEHOLDER};
	for(int i=0; i<str->len; i++){
		str->buf[i] = sbox[str->buf[i]];
	}
}
