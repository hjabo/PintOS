#include "vm/swap.h"
#include <stdio.h>
#include <stdint.h>
#include <bitmap.h>
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"

static struct bitmap* free_blocks;
struct block* swap_table;

static struct lock block_lock;

void
swap_init(void)
{
    free_blocks = bitmap_create(1024);
    swap_table = block_get_role(BLOCK_SWAP);
    lock_init(&block_lock);
}

/* Insert the contents of a page into the swap table */
void
swap_insert(struct page* p)
{
    lock_acquire(&block_lock);
    char* c = (char*) p->frame->paddr;
    size_t sector_num = bitmap_scan_and_flip(free_blocks, 0, 1, false);
    if (sector_num == BITMAP_ERROR)
        PANIC("Swap space is full.");
    p->block_sector = sector_num;
    int i;
    for (i = 0; i < 8; i++) {
        block_write(swap_table, sector_num * 8 + i, c);
        c += 512;
    }
    lock_release(&block_lock);
}

/* Read from swap into the page */
void
swap_get(struct page* p)
{
    lock_acquire(&block_lock);
    char* c = (char*) p->frame->paddr;
    size_t read_sector = p->block_sector;
    int i;
    for (i = 0; i < 8; i++) {
        block_read(swap_table, read_sector * 8 + i, c);
        c += 512;
    }
    bitmap_reset(free_blocks, read_sector);
    lock_release(&block_lock);
}

void
swap_free(struct page* p)
{
    lock_acquire(&block_lock);
    bitmap_reset(free_blocks, p->block_sector);
    lock_release(&block_lock);
}