#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void sys_exit(int status);
static int sys_write(int fd, const void* buffer, unsigned size);

#endif /* userprog/syscall.h */
