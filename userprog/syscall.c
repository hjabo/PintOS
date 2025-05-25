#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

void syscall_handler(struct intr_frame* f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
syscall_handler (struct intr_frame *f) 
{
    uint32_t syscall_num = *(uint32_t*)(f->esp);

    switch (syscall_num) 
    {
        case SYS_HALT:
            shutdown_power_off();
            break;

        case SYS_EXIT:
            sys_exit(*(int*)(f->esp + 4));
            break;

        case SYS_WRITE:
            {
                int fd = *(int*)(f->esp + 4);
                void* buffer = (void*)*(int*)(f->esp + 8);
                unsigned size = *(unsigned*)(f->esp + 12);

                f->eax = sys_write(fd, buffer, size);
            }
            break;

        default:
            sys_exit(-1);
            break;
    }
}

void 
sys_exit(int status)
{
	struct thread* cur = thread_current();

	printf("%s: exit(%d)\n", cur->name, status); // Process Termination Message
	thread_exit();
}

static int
sys_write(int fd, const void* buffer, unsigned size)
{
    if (fd != 1 && fd != 2)
        return -1;

    if (!is_user_vaddr(buffer) || !is_user_vaddr(buffer + size - 1))
        sys_exit(-1);

    putbuf(buffer, size);

    return size;
}
