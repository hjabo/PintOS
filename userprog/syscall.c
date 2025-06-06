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
#include "vm/page.h"
#endif

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
        return 0;
    else
    {
        struct file* f = getfile(fd);
        if (f == NULL)
        {
            lock_release(&file_lock);
            exit(-1);
        }
        int ret = file_read(f, buffer, size);
        lock_release(&file_lock);
        return ret;
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
        int ret = file_write(f, buffer, size);
        lock_release(&file_lock);
        return ret;
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
    struct file* f = getfile(fd);
    if (f == NULL)
        exit(-1);
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
        exit(-1);
}

#ifdef VM

mapid_t 
mmap(int fd, void* addr)
{
    if (addr == NULL || pg_ofs(addr) != 0 || !is_user_vaddr(addr))
        return -1;

    struct file* origin = getfile(fd);
    if (origin == NULL)
        return -1;

    struct file* f = file_reopen(origin);
    if (f == NULL)
        return -1;

    off_t ofs = f->pos;
    off_t length = file_length(f);
    if (length == 0)
        return -1;

    struct thread* t = thread_current();

    size_t read_bytes = length;
    size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

    int pg_cnt = length <= PGSIZE ? 1 : length % PGSIZE ? length / PGSIZE + 1 : length / PGSIZE;

    int i;
    for (i = 0; i < pg_cnt; i++) {
        void* check_addr = addr + i * PGSIZE;
        if (page_find(&t->spt, check_addr) != NULL)
            return -1;
    }

    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(ofs % PGSIZE == 0);

    struct mmap_entry* me = (struct mmap_entry*)malloc(sizeof(struct mmap_entry));
    if (me == NULL)
        return -1;
    mapid_t mapid = (mapid_t)(t->mapid_allocator++);
    me->mapid = mapid;
    me->pg_cnt = pg_cnt;
    me->file = f;
    me->page_addrs = (struct page**)malloc(sizeof(struct page*) * pg_cnt);
    list_push_back(&t->mmap_list, &me->elem);

    int j;
    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct page* p = (struct page*)malloc(sizeof(struct page));
        if (p == NULL) 
        {
            list_remove(&me->elem);
            int k;
            for (k = 0; k < i; k++)
                free(me->page_addrs[k]);
            free(me->page_addrs);
            free(me);
            return -1;
        }
        p->vaddr = addr;
        p->frame = NULL;
        p->status = IN_DISK;
        p->file = f;
        p->offset = ofs;
        p->read_bytes = page_read_bytes;
        p->writable = true;
        p->pagedir = thread_current()->pagedir;
        p->block_sector = -1;

        hash_insert(&t->spt, &p->hash_elem);
        me->page_addrs[j++] = p;

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        ofs += page_read_bytes;
        addr += PGSIZE;
    }

    return mapid;
}

void
munmap(mapid_t mapid) 
{
    return;
}

#endif
