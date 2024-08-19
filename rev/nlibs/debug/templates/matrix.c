#include "matrix.h"
#include "util.h"

struct Matrix_t* init_matrix(int n){
    struct Matrix_t* mat = (struct Matrix_t*)malloc(sizeof(struct Matrix_t));
    mat->mat = malloc(sizeof(void*) * n);
    for(int i=0; i<n; i++){
        mat->mat[i] = calloc(n, sizeof(uint32_t));
    }
    mat->N = n;
    return mat;
}

void free_mat(struct Matrix_t* mat){
    for(int i=0; i<mat->N; i++){
        free(mat->mat[i]);
        mat->mat[i] = NULL;
    }
    free(mat->mat);
    mat->mat = NULL;
    free(mat);
}

struct Matrix_t* init_identity(int n){
    struct Matrix_t* mat = init_matrix(n);
    for(int i=0; i<mat->N; i++){
        mat->mat[i][i] = 1;
    }
    return mat;
}

void rref_add(struct Matrix_t* mat, int r1, int r2){
    if(r1 == r2){
        return;
    }
    for(int i=0; i<mat->N; i++){
        mat->mat[r1][i] = (mat->mat[r1][i] + mat->mat[r2][i]) % MOD;
    }
}

void rref_mul(struct Matrix_t* mat, int r1, int a){
    if(a == 0){
        return;
    }
    for(int i=0; i<mat->N; i++){
        mat->mat[r1][i] = (a * mat->mat[r1][i]) % MOD;
    }
}

struct Matrix_t* genRandomInvertibleMatrix(int n){
    struct Matrix_t* mat = init_identity(n);
    srand(1337);
    for(int i=0; i<n*n; i++){
        if(rand()%2){
            int a = rand()%n;
            int b = rand()%n;
            rref_add(mat, a, b);
        }else{
            int a = rand()%n;
            int b = rand()%MOD;
            rref_mul(mat, a, b);
        }
    }
    return mat;
}

void matrix_entry(struct string* str){
    struct Matrix_t* mat = genRandomInvertibleMatrix(str->len);
    uint8_t* newbuf = malloc(str->len*2);
    uint8_t* ptr = newbuf;
    for(int i=0; i<mat->N; i++){
        int tot = 0;
        for(int j=0; j<mat->N; j++){
            tot += mat->mat[i][j] * str->buf[j];
            tot %= MOD;
        }
        memcpy(ptr, &tot, 2);
        ptr += 2;
    }
    free(str->buf);
    str->buf = newbuf;
    str->len *= 2;
    free_mat(mat);
}