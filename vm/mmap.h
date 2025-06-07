#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <list.h>

struct lock mmap_lock;

struct mmap_entry {
    int mapid;
    struct page** page_addrs;
    int pg_cnt;
    struct file* file;
    struct list_elem elem;
};

int do_mmap(int fd, void* addr);
void do_munmap(int);

#endif /* vm/mmap.h */