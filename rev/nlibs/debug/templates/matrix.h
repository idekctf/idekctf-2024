#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "util.h"

#define MOD 41389

struct Matrix_t {
    int N;
    uint32_t** mat;
};

void matrix_entry(struct string* str);