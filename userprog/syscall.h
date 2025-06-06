#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "lib/user/syscall.h"
#include "filesys/off_t.h"

struct file
{
    struct inode* inode;        /* File's inode. */
    off_t pos;                        /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
};

struct lock file_lock;

void syscall_init (void);

void halt(void) NO_RETURN;
void exit(int status) NO_RETURN;
pid_t exec(const char* file);
int wait(pid_t);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned length);
int write(int fd, const void* buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

#ifdef VM

struct mmap_entry {
    mapid_t mapid;
    struct page** page_addrs;
    int pg_cnt;
    struct file* file;
    struct list_elem elem;
};

mapid_t mmap(int fd, void* addr);
void munmap(mapid_t);

#endif

#endif /* userprog/syscall.h */
