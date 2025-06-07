#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/block.h"

#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/mmap.h"
#endif

struct file
{
    struct inode* inode;        /* File's inode. */
    off_t pos;                        /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
};

void syscall_handler(struct intr_frame* f);
struct file* getfile(int fd);
void check_user_vaddr(const void* vaddr);

void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
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

    #ifdef VM
        case SYS_MMAP:
            check_user_vaddr(sp + 4);
            f->eax = mmap((int)*(uint32_t*)(sp + 4), (void*)*(uint32_t*)(sp + 8));
            break;

        case SYS_MUNMAP:
            check_user_vaddr(sp + 4);
            munmap((int)*(uint32_t*)(sp + 4));
            break;
    #endif

        default:
            thread_exit();
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
	thread_exit();
}

pid_t 
exec(const char* file)
{
    char *fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        thread_exit();
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
        thread_exit();
    return filesys_create(file, initial_size);
}

bool
remove(const char* file)
{
    if (file == NULL)
        thread_exit();
    return filesys_remove(file);
}

int
open(const char* file)
{
    if (file == NULL)
    {
        thread_exit();
    }
    
    lock_acquire(&filesys_lock);
    struct file* return_file = filesys_open(file);
    if (return_file == NULL) {
        lock_release(&filesys_lock);
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
            lock_release(&filesys_lock);
            return i;
        }
    }
    lock_release(&filesys_lock);
    return -1;
}

int
filesize(int fd)
{
    struct file* f = getfile(fd);
    if (f == NULL)
        thread_exit();
    else
        return file_length(f);
}

int
read(int fd, void* buffer, unsigned size)
{
    check_user_vaddr(buffer);
    lock_acquire(&filesys_lock);
    if (fd == 0)
        return 0;
    else
    {
        struct file* f = getfile(fd);
        if (f == NULL)
        {
            lock_release(&filesys_lock);
            thread_exit();
        }
        int ret = file_read(f, buffer, size);
        lock_release(&filesys_lock);
        return ret;
    }
}

int
write(int fd, const void* buffer, unsigned size)
{
    check_user_vaddr(buffer);
    lock_acquire(&filesys_lock);
    if (fd == 1)
    {
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }
    else
    {
        struct file* f = getfile(fd);
        if (f == NULL)
        {
            lock_release(&filesys_lock);
            thread_exit();
        }
        int ret = file_write(f, buffer, size);
        lock_release(&filesys_lock);
        return ret;
    }
}

void
seek(int fd, unsigned position)
{
    struct file* f = getfile(fd);
    if (f == NULL)
        thread_exit();
    else
        return file_seek(f, position);
}

unsigned
tell(int fd)
{
    struct file* f = getfile(fd);
    if (f == NULL)
        thread_exit();
    else
        return file_tell(f);
}

void
close(int fd)
{
    struct file* f = getfile(fd);
    if (f == NULL)
        thread_exit();
    file_close(f);
    thread_current()->fd[fd] = NULL;
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
        thread_exit();
}

#ifdef VM

mapid_t 
mmap(int fd, void* addr)
{
    if (addr == NULL || pg_ofs(addr) != 0 || !is_user_vaddr(addr))
        return -1;
    mapid_t mapid = do_mmap(fd, addr);
    return mapid;
}

void
munmap(mapid_t mapid) 
{
    if (mapid < 0)
        return -1;
    do_munmap(mapid);
}

#endif
