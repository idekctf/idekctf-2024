#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <sys/msg.h>
#include <sys/socket.h>

#define DO_CREATE    0xc028ca00 
#define DO_DELETE    0xc028ca01
#define DO_BORROW    0xc028ca02
#define DO_READ      0xc028ca03
#define DO_NOTE      0xc028ca04
#define DO_RETURN    0xc028ca05

// GLOBAL VARIABLES
int fd;

// MODULE STUFF
struct req {
    uint64_t idx;
    uint64_t name_addr;
    uint64_t note_size;
    uint64_t note_addr;
    uint64_t info_addr;
};

int create_book(char * name, uint64_t size, char * note, char * info) {
    struct req req; 
    req.idx = 0;
    req.name_addr = (uint64_t) name;
    req.note_size = size;
    req.note_addr = (uint64_t) note;
    req.info_addr = (uint64_t) info;
    
    if (ioctl(fd, DO_CREATE, &req) < 0) {
        perror("[!] Create failed");
        return -1;
    }
    printf("[+] Created new book\n");
    return 0;
}

int delete_book(uint64_t index) {
    struct req req; 
    req.idx = index;
    req.name_addr = 0;
    req.note_size = 0;
    req.note_addr = 0;
    req.info_addr = 0;
    
    if (ioctl(fd, DO_DELETE, &req) < 0) {
        perror("[!] Delete failed");
        return -1;
    }
    printf("[+] Deleted book %d\n", index);
    return 0;
}

int borrow_book(uint64_t index) {
    struct req req; 
    req.idx = index;
    req.name_addr = 0;
    req.note_size = 0;
    req.note_addr = 0;
    req.info_addr = 0;
    
    if (ioctl(fd, DO_BORROW, &req) < 0) {
        perror("[!] Borrow failed");
        return -1;
    }
    printf("[+] Borrowed book %d\n", index);
    return 0;
}

int read_book(uint64_t index, char * name, char * note, char * info) {
    struct req req; 
    req.idx = index;
    req.name_addr = (uint64_t) name;
    req.note_size = 0;
    req.note_addr = (uint64_t) note;
    req.info_addr = (uint64_t) info;
    
    ioctl(fd, DO_READ, &req);

    printf("[+] Performed read\n");
    return 0;
}

int note_book(uint64_t index, uint64_t size, char * note) {
    struct req req; 
    req.idx = index;
    req.name_addr = 0;
    req.note_size = size;
    req.note_addr = (uint64_t) note;
    req.info_addr = 0;
    
    if (ioctl(fd, DO_NOTE, &req) < 0) {
        perror("[!] Change note failed");
        return -1;
    }
    printf("[+] Changed note of book %d\n", index);
    return 0;
}

int return_book(uint64_t index) {
    struct req req; 
    req.idx = index;
    req.name_addr = 0;
    req.note_size = 0;
    req.note_addr = 0;
    req.info_addr = 0;
    
    if (ioctl(fd, DO_RETURN, &req) < 0) {
        perror("[!] Return failed");
        return -1;
    }
    printf("[+] Returned book %d\n", index);
    return 0;
}

int main(void) {
    char name[0x100]; 
    char note[0x100]; 
    char info[0x100]; 
    
    // Open librarymodule device
    if ((fd = open("/dev/librarymodule", O_RDONLY)) < 0) {
        perror("[!] Failed to open miscdevice");
        exit(-1);
    }
    
    // Read 0
    memset(name, 0, sizeof(name)); 
    memset(note, 0, sizeof(note)); 
    memset(info, 0, sizeof(info));
    
    read_book(0, name, note, info); 
    
    return 0;
    
}
