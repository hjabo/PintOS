#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "devices/block.h"

struct file
{
    struct inode* inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
};

static void syscall_handler(struct intr_frame* f);
struct file* getfile(int fd);
void check_user_vaddr(const void* vaddr);

void
syscall_init (void) 
{
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
            //f->eax = write(*(int*)(sp + 4), (void*)*(int*)(sp + 8), *(unsigned*)(sp + 12));
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

	printf("%s: exit(%d)\n", cur->name, status); // Process Termination Message
	thread_exit();
}

pid_t 
exec(const char* file)
{
    return process_execute(file);
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
    //printf(" SYSCALL: open \n");
    if (file == NULL)
        exit(-1);
    check_user_vaddr(file);
    // lock_acquire (&file_lock);
    struct file* return_file = filesys_open(file);
    if (return_file == NULL)
        return -1;
    else
    {
        int i;
        for (i = 3; i < 128; i++)
        {
            if (getfile(i) == NULL)
            {
                if (strcmp(thread_current()->name, file) == false)
                    file_deny_write(return_file);

                thread_current()->fd[i] = return_file;
                //printf("  >> filesys_open(file) success, return %d, idx of fd", i);
                        // lock_release (&file_lock);
                return i;
            }
        }
        //printf("  >> filesys_open(file) failed ; thread's fd is full, return -1\n");
    }
    // lock_release (&file_lock);
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
    // lock_acquire (&file_lock);
    if (fd == 0)
    {
        /* input_getc() 를 이용해 키보드 입력을 버퍼에 넣는다. 그리고 입력된 사이즈(bytes)를 리턴한다. */
        int i;
        for (i = 0; i < size; i++)
        {
            if (((char*)buffer)[i] == '\0')
                break;
        }
        // lock_release (&file_lock);
        return i;
    }
    else
    {
        struct file* f = getfile(fd);
        if (f == NULL)
            exit(-1);
        else
        {
            // lock_release (&file_lock);
            return file_read(f, buffer, size);
        }
    }
}

int
write(int fd, const void* buffer, unsigned size) // 이거 내용 부정확하니까 docs 보고 다시 짜기!!
{
    check_user_vaddr(buffer);
    // lock_acquire (&file_lock);
    if (fd == 1)
    {
        /* putbuf() 함수를 이용하여 버퍼의 내용을 콘솔에 입력한다. 이 때에는 필요한 사이즈만큼 반복문을 돌아야 한다. */
        putbuf(buffer, size);
        return size;
    }
    else
    {
        struct file* f = getfile(fd);
        if (f == NULL)
        {
            // lock_release (&file_lock);
            exit(-1);
        }
        if (f->deny_write)
        {
            file_deny_write(f);
        }
        // lock_release (&file_lock);
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
    struct file* f = getfile(fd);
    if (f == NULL)
        exit(-1);
    else
    {
        file_close(f);
        thread_current()->fd[fd] = NULL;
    }
}

struct file
    * getfile(int fd)
{
    return (thread_current()->fd[fd]);
}

void
check_user_vaddr(const void* vaddr)
{
    // ASSERT(is_user_vaddr(vaddr)); 
    // 이거 ASSERT로 하면 프로세스가 -1로 종료되지 않아서 테스트케이스 통과 안함
    if (!is_user_vaddr(vaddr))
        exit(-1);
}
