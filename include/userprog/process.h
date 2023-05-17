#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#include "threads/thread.h"

bool lazy_load_segment(struct page *page, void *aux);
tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);
void argument_stack(char **parse, int count, void **rsp);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
struct thread *get_child_process(int pid);
struct lazy_load_arg
{
    struct file *file;
    off_t ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
};
#endif /* userprog/process.h */
