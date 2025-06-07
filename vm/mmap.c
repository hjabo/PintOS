#include "vm/mmap.h"
#include <stdio.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/page.h"

struct file
{
    struct inode* inode;        /* File's inode. */
    off_t pos;                        /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
};

struct file* getfile(int fd);

int
do_mmap(int fd, void* addr)
{
    struct file* origin = getfile(fd);
    if (origin == NULL)
    {
        return -1;
    }

    struct file* f = file_reopen(origin);
    if (f == NULL)
    {
        return -1;
    }

    off_t ofs = f->pos;
    off_t length = file_length(f);
    if (length == 0)
    {
        return -1;
    }

    struct thread* t = thread_current();

    size_t read_bytes = length;
    size_t zero_bytes = (PGSIZE - read_bytes % PGSIZE) % PGSIZE;

    int pg_cnt = length <= PGSIZE ? 1 : length % PGSIZE ? length / PGSIZE + 1 : length / PGSIZE;

    int i;
    for (i = 0; i < pg_cnt; i++) {
        void* check_addr = addr + i * PGSIZE;
        if (page_find(&t->spt, check_addr) != NULL)
            return -1;
    }

    struct mmap_entry* me = (struct mmap_entry*)malloc(sizeof(struct mmap_entry));
    int mapid = t->mapid_allocator++;
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
do_munmap(int mapid)
{
    struct thread* t = thread_current();

    struct list_elem* e;
    for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list);)
    {
        struct mmap_entry* me = list_entry(e, struct mmap_entry, elem);
        e = list_next(e);

        if (mapid != -1 && me->mapid != mapid)
            continue;

        int i;
        for (i = 0; i < me->pg_cnt; i++)
        {
            struct page* p = me->page_addrs[i];
            if (p->frame != NULL)
            {
                if (pagedir_is_dirty(p->pagedir, p->vaddr))
                {
                    if (file_write_at(p->file, p->frame->paddr, p->read_bytes, p->offset) != (int)p->read_bytes)
                        thread_exit();
                }
                if (mapid != -1)
                    free_frame(p->frame);
            }
            if (mapid != -1)
            {
                hash_delete(&t->spt, &p->hash_elem);
                free(p);
            }
        }
        list_remove(&me->elem);
        free(me->page_addrs);
        free(me);
    }
}