#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "devices/block.h"

struct file
{
    struct inode* inode;        /* File's inode. */
    off_t pos;                        /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
};

struct lock file_lock;

void syscall_handler(struct intr_frame* f);
struct file* getfile(int fd);
void check_user_vaddr(const void* vaddr);

void
syscall_init (void) 
{
    lock_init(&file_lock);
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
syscall_handler (struct intr_frame *f) 
{
    void* sp = f->esp;
    uint32_t syscall_num = *(uint32_t*)(sp);

    switch (syscall_num) 
    {
        case SYS_HALT:
            halt();
            break;

        case SYS_EXIT:
            check_user_vaddr(sp + 4);
            exit(*(int*)(sp + 4));
            break;

        case SYS_EXEC:
            check_user_vaddr(sp + 4);
            f->eax = exec((const char*)*(uint32_t*)(sp + 4));
            break;

        case SYS_WAIT:
            check_user_vaddr(sp + 4);
            f->eax = wait((pid_t)*(uint32_t*)(sp + 4));
            break;

        case SYS_CREATE:
            check_user_vaddr(sp + 4);
            f->eax = create((const char*)*(uint32_t*)(sp + 4), (unsigned)*(uint32_t*)(sp + 8));
            break;

        case SYS_REMOVE:
            check_user_vaddr(sp + 4);
            f->eax = remove((const char*)*(uint32_t*)(sp + 4));
            break;

        case SYS_OPEN:
            check_user_vaddr(sp + 4);
            f->eax = open((const char*)*(uint32_t*)(sp + 4));
            break;

        case SYS_FILESIZE:
            check_user_vaddr(sp + 4);
            f->eax = filesize((int)*(uint32_t*)(sp + 4));
            break;

        case SYS_READ:
            check_user_vaddr(sp + 4);
            f->eax = read((int)*(uint32_t*)(sp + 4), (void*)*(uint32_t*)(sp + 8), (unsigned)*((uint32_t*)(sp + 12)));
            break;

        case SYS_WRITE:
            check_user_vaddr(sp + 4);
            f->eax = write((int)*(uint32_t*)(sp + 4), (void*)*(uint32_t*)(sp + 8), (unsigned)*((uint32_t*)(sp + 12)));
            break;

        case SYS_SEEK:
            check_user_vaddr(sp + 4);
            seek((int)*(uint32_t*)(sp + 4), (unsigned)*((uint32_t*)(sp + 8)));
            break;

        case SYS_TELL:
            check_user_vaddr(sp + 4);
            f->eax = tell((int)*(uint32_t*)(sp + 4));
            break;

        case SYS_CLOSE:
            check_user_vaddr(sp + 4);
            close((int)*(uint32_t*)(sp + 4));
            break;

        default:
            exit(-1);
            break;
    }
}

void 
halt(void) 
{
    shutdown_power_off();
}

void 
exit(int status)
{
	struct thread* cur = thread_current();
    cur->exit_status = status;
    int i;
    for (i = 3; i < 128; i++) {
        if (cur->fd[i] != NULL)
            close(i);
    }

	printf("%s: exit(%d)\n", cur->name, status); // Process Termination Message
	thread_exit();
}

pid_t 
exec(const char* file)
{
    char *fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        exit(-1);
    strlcpy(fn_copy, file, PGSIZE);
    pid_t tid = process_execute(fn_copy);
    palloc_free_page(fn_copy);
    return tid;
}

int
wait(pid_t pid)
{
    return process_wait(pid);
}

bool
create(const char* file, unsigned initial_size)
{
    if (file == NULL)
        exit(-1);
    return filesys_create(file, initial_size);
}

bool
remove(const char* file)
{
    if (file == NULL)
        exit(-1);
    return filesys_remove(file);
}

int
open(const char* file)
{
    if (file == NULL)
        exit(-1);
    
    lock_acquire(&file_lock);
    struct file* return_file = filesys_open(file);
    if (return_file == NULL) {
        lock_release(&file_lock);
        return -1;
    }

    int i;
    for (i = 3; i < 128; i++)
    {
        if (getfile(i) == NULL)
        {
            if (strcmp(thread_current()->name, file) == false)
                file_deny_write(return_file);
            thread_current()->fd[i] = return_file;
            lock_release(&file_lock);
            return i;
        }
    }
    lock_release(&file_lock);
    return -1;
}

int
filesize(int fd)
{
    struct file* f = getfile(fd);
    if (f == NULL)
        exit(-1);
    else
        return file_length(f);
}

int
read(int fd, void* buffer, unsigned size)
{
    check_user_vaddr(buffer);
    lock_acquire(&file_lock);
    if (fd == 0)
    {
        int i;
        for (i = 0; i < size; i++)
        {
            if (((char*)buffer)[i] == '\0')
                break;
        }
        lock_release(&file_lock);
        return i;
    }
    else
    {
        struct file* f = getfile(fd);
        if (f == NULL)
        {
            lock_release(&file_lock);
            exit(-1);
        }
        lock_release(&file_lock);
        return file_read(f, buffer, size);
    }
}

int
write(int fd, const void* buffer, unsigned size)
{
    check_user_vaddr(buffer);
    lock_acquire(&file_lock);
    if (fd == 1)
    {
        putbuf(buffer, size);
        lock_release(&file_lock);
        return size;
    }
    else
    {
        struct file* f = getfile(fd);
        if (f == NULL)
        {
            lock_release(&file_lock);
            exit(-1);
        }
        if (f->deny_write)
            file_deny_write(f);
        lock_release(&file_lock);
        return file_write(f, buffer, size);
    }
}

void
seek(int fd, unsigned position)
{
    struct file* f = getfile(fd);
    if (f == NULL)
        exit(-1);
    else
        return file_seek(f, position);
}

unsigned
tell(int fd)
{
    struct file* f = getfile(fd);
    if (f == NULL)
        exit(-1);
    else
        return file_tell(f);
}

void
close(int fd)
{
    lock_acquire(&file_lock);
    struct file* f = getfile(fd);
    if (f == NULL) {
        lock_release(&file_lock);
        exit(-1);
    }
    file_close(f);
    thread_current()->fd[fd] = NULL;
    lock_release(&file_lock);
}

struct file* 
getfile(int fd)
{
    return (thread_current()->fd[fd]);
}

void
check_user_vaddr(const void* vaddr)
{
    if (!is_user_vaddr(vaddr))
        exit(-1);
}
