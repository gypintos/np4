#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"

#define MAP_FAILED ((mapid_t) -1)
/** NEW ADDED HERE **/
#define READDIR_MAX_LEN 14

typedef int mapid_t;
// struct lock filesys_lock;

void syscall_init (void);
void halt (void);
void exit (int status);
tid_t exec (const char *file_name);
int wait (tid_t);
bool create (const char *file_name, unsigned initial_size);
bool remove (const char *file_name);
int open (const char *file_name);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t id_addr);
void munmap_helper (struct id_addr *m, struct thread *t);
struct file * get_file_by_id (int fd);
void insert_fd (struct thread *t, struct file_desc* opened_file);
void get_args (int *ptr, int argnum, void **syscall_args_ptr);
void validate_addr (void *addr, void *esp, bool writable);
void validate_buf (char* buff_ptr, int size, void *esp, bool writeable);
void release_buf (const char* buff_ptr, int size);
void release_args (int *ptr, int argnum, void **syscall_args_ptr);

#endif
