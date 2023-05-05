#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h> 
#include "threads/synch.h"
void syscall_init (void);
struct lock filesys_lock;
// void syscall_handler (struct intr_frame *f UNUSED);
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file , unsigned initial_size);
bool remove (const char *file);
int open(const char *file);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
#endif /* userprog/syscall.h */
