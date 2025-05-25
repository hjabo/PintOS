#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"

void syscall_handler(struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void sys_halt(void);
void sys_exit(int status);
int sys_exec(const char *file);
int sys_wait(int pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
static int sys_write(int fd, const void *buffer, unsigned size);


void syscall_handler(struct intr_frame *f){
  uint32_t syscall_number = *((uint32_t *)f->esp);
  switch(syscall_number){
    case SYS_HALT:
      sys_halt();
    case SYS_EXIT:
      sys_exit(*(int*)(f->esp+4));
      break;
    case SYS_WRITE:
      {
        int fd = *(int*)(f->esp+4);
        void* buffer = (void *)*(int*)(f->esp+8);
        unsigned size = *(unsigned*)(f->esp+12);
        f->eax = sys_write(fd,buffer,size);
      }
      break;
    case SYS_EXEC:
      f->eax = sys_exec(*(int *)(f->esp+4));
      break;
    case SYS_WAIT:
      f->eax = sys_wait(*(int *)(f->esp+4));
      break;
    case SYS_CREATE:
      f->eax = sys_create((const char*)*(int *)(f->esp+4), (unsigned)*(int *)(f->esp+8));
      break;
    case SYS_REMOVE:
      f->eax = sys_remove((const char*)*(int *)(f->esp+4));
      break;
    default:
      sys_exit(-1);
  }
}



void sys_halt(void){
  shutdown_power_off();
}
void sys_exit(int status){
  struct thread* cur = thread_current();	

  printf("%s: exit(%d)\n",cur->name,status);
  cur->exit_status = status;
  thread_exit();
}
int sys_exec(const char *file){
  return process_execute(file);
}
int sys_wait(int pid){
  return process_wait(pid);
}
bool sys_create(const char *file, unsigned initial_size){
  return filesys_create(file,initial_size);
}
bool sys_remove(const char *file){
  return filesys_remove(file);
}

static int sys_write(int fd, const void *buffer, unsigned size){
  if(fd!=1&&fd!=2)
    return -1;
  if(!is_user_vaddr(buffer) || !is_user_vaddr(buffer+size-1))
    sys_exit(-1);
  putbuf(buffer,size);
  return size;
}

