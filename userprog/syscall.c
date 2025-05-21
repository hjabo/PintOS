#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"

void syscall_handler(struct intr_frame *f UNUSED){
  printf("syscall_handler called!\n");
  int status = *((int *)f->esp + 1);
  switch(*(int *)f->esp){
    case SYS_HALT:
    case SYS_EXIT:
      exit(status);
      break;
    case SYS_EXEC:
    case SYS_WAIT:
    default:
      exit(-1);
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void halt(void){
  shutdown();
}
void exit(int status){
  printf("exit called with %d\n",status);
  struct thread *cur = thread_current();
  char name[32];
  strlcpy(name, cur->name,sizeof name);
  char *save_ptr;
  char *program_name = strtok_r(name," ",&save_ptr);
  printf("%s: exit(%d)\n",thread_name(),status);
  thread_exit();
}
int exec(const char *file){
  return process_execute(file);
}
int wait(int pid){
  return process_wait(pid);
}
bool create(const char *file, unsigned initial_size){
  return filesys_create(file,initial_size);
}
bool remove(const char *file){
  return filesys_remove(file);
}


