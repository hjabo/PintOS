#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <hash.h>
#include "threads/palloc.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/swap.h"

enum page_status
{
    IN_FRAME, 
    IN_SWAP,
    IN_DISK
};

struct page
{
    void* vaddr;                                /* Virtual address. */
    struct frame_entry* frame;          /* Occupying frame. */
    struct hash_elem hash_elem;     /* Hash table element. */
    
    /* Meta data. */
    enum page_status status;
    struct file* file;                     /* ELF excutable file to load page from */
    off_t offset;                          /* File offset */
    size_t read_bytes;              /* Number of bytes to read from file */
    bool writable;
    uint32_t* pagedir;

    /* Swap meta data. */
    int block_sector;
};

unsigned page_hash(const struct hash_elem*, void*);
bool page_less(const struct hash_elem*, const struct hash_elem*, void*);
void page_destructor(struct hash_elem*, void*);
struct page* page_find(struct hash* spt, void* va);
#endif /* vm/page.h */
