#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

#define MAX_SZ 0x10000
#define MAX_NOTES 0x500
#define BUF_SZ 0x21000
#define CHALLENGE_SZ 0x10

void* notes[MAX_NOTES] = {0};

typedef struct {
    uint32_t* ptr;
    uint32_t val;
} Challenge;

Challenge challenges[CHALLENGE_SZ] = {0};


int get_int(){
    int a;
    scanf("%d%*c",&a);
    return a;
}

int rng_fd = -1;

uint32_t get_rng(){
    if(rng_fd == -1){
        rng_fd = open("/dev/urandom", O_RDONLY);
        if(rng_fd < 0){
            puts("Error: Could not open /dev/urandom");
            exit(1);
        }
    }
    uint32_t rng;
    read(rng_fd, &rng, 4);
    return rng;
}

void* get_rand_map(){
    void* chunk_address = (void*)(0x10000ULL + (((int64_t)get_rng()) << 12));
    void* ret = mmap(chunk_address, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(ret == NULL){
        puts("Error: Failed to allocate memory");
        exit(1);
    }
    return ret;
}


void new(){
    printf("Index? ");
    int idx = get_int();
    if(idx < 0 || idx >= MAX_NOTES){
        puts("Nope");
        exit(1);
    }
    printf("Size? ");
    int sz = get_int();
    if(sz < 0 || sz >= MAX_SZ) {
        puts("Nope");
        exit(1);
    }
    if(notes[idx] != NULL){
        puts("Nope");
        exit(1);
    }
    notes[idx] = malloc(sz);
    if(notes[idx] == NULL){
        puts("Nope");
        exit(1);
    }
    puts("Done");
}

void delete(){
    printf("Index? ");
    int idx = get_int();
    if(idx < 0 || idx >= MAX_NOTES){
        puts("Nope");
        exit(1);
    }
    if(notes[idx] == NULL){
        puts("Nope");
        exit(1);
    }
    free(notes[idx]);
    notes[idx] = NULL;
}

typedef struct { // https://stackoverflow.com/questions/4958384/what-is-the-format-of-the-x86-64-va-list-structure#4958507
   unsigned int gp_offset;
   unsigned int fp_offset;
   void *overflow_arg_area;
   void *reg_save_area;
} _va_list[1];

void fmt(char* buf){
    void* start = malloc(1);
    _va_list vl;

    vl->overflow_arg_area = start;
    vl->gp_offset = 0x30;
    vl->fp_offset = 0x130;
    vl->reg_save_area = 0;
    vfprintf(stdout, buf, (void*)vl);
}

void generate_challenge(){
    for(int i=0; i<CHALLENGE_SZ; i++){
        challenges[i].ptr = get_rand_map();
        challenges[i].val = get_rng();
        printf("Challenge %d: Write %p to address %p\n", i, challenges[i].val, challenges[i].ptr);
    }
}

int main(){
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    while(1){
        puts(
            "1 malloc\n"
            "2 free\n"
            "3 Challenge time");
        printf("Choice? ");
        int choice = get_int();
        if(choice == 1){
            new();
        }else if(choice == 2){
            delete();
        }else if(choice == 3){
            break;
        }
    }
    generate_challenge();
    char buf[BUF_SZ];
    memset(buf, 0, BUF_SZ);
    printf("Format string? ");
    fgets(buf, BUF_SZ, stdin);
    for(int i=0; i<BUF_SZ; i++){
        if(buf[i] == '*'){
            puts("No! >:(");
            puts("Context: https://eth007.me/blog/ctf/stiller-printf/");
            exit(1);
        }
    }
    fmt(buf);
    for(int i=0; i<CHALLENGE_SZ; i++){
        if(challenges[i].ptr[0] != challenges[i].val){
            puts("Nope :(");
            exit(1);
        }
    }
    puts("Yay! You Win!");
    system("cat /flag.txt");
}