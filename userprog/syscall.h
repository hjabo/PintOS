#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include "filesys/off_t.h"
#include <stddef.h>
#include <list.h>
struct file
{
    struct inode* inode;        /* File's inode. */
    off_t pos;                        /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
};

#ifdef VM
struct mmap_entry{
  int mapid;
  struct file *file;
  void *start_addr;
  size_t length;
  struct list_elem elem;
};
#endif
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

int mmap(int fd, void *vaddr);
void munmap(int mapid);
#endif /* userprog/syscall.h */
