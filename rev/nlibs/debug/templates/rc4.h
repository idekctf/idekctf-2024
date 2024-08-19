#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct rc4_t{
	uint8_t S[256];
	int i;
	int j;
};

void rc4_entry(struct string* str);