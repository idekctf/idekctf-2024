#include <stdio.h>
#include <stdlib.h>

int main() {
    setuid(0);
    FILE *file;
    char ch;
    file = fopen("/flag.txt", "r");
    if (file == NULL) {
        perror("flag.txt missing");
        return 1;
    }
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
    return 0;
}
