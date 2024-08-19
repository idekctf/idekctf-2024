#include <stdlib.h>
#include <stdio.h>
#include <sys/random.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()*+,-./;<=>?@[]^_`{|}~";
char entropy[20];
bool zapped = false;

#define CHUNKS (128)
char *chunks[CHUNKS];
bool usable[CHUNKS] = {false};
uint32_t cursor = 0;

char *gibberish() {
    uint32_t len = 3 + (uint32_t)rand() % 14;
    entropy[len] = 0;
    for (int i = 0; i < len; i++) {
        entropy[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    return entropy;
}

uint32_t n() {
    int i;
    printf("%s: ", gibberish());
    if (1 == scanf("%d", &i)) {
        return i;
    }
    return -1;
}

void zap() {
    if (zapped) return;
    zapped = true;

    uint32_t idx = n();
    if (idx >= CHUNKS) return;

    chunks[idx][0] = 0;
}

void add() {
    uint32_t size = n();
    if (size >= 0x1000) return;

    char *chunk = malloc(size);
    if (chunk == NULL) return;

    if (cursor >= CHUNKS) return;

    uint32_t idx = cursor++;
    printf("%s: ", gibberish());
    read(0, chunk, size);
    chunks[idx] = chunk;
    usable[idx] = true;
    printf("%s: %d\n", gibberish(), idx);
}

void del() {
    uint32_t idx = n();
    if (idx >= CHUNKS) return;

    if (!usable[idx]) return;

    free(chunks[idx]);
    usable[idx] = false;
}

int main() {
    srand((int)((intptr_t)&main>>12));
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    while (true) {
        uint32_t choice = n();
        switch (choice) {
            case 0:
                add();
                break;
            case 1:
                del();
                break;
            case 2:
                zap();
                break;
        }
    }
}