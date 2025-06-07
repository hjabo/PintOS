#include "vm/frame.h"
#include <stdio.h>
#include <bitmap.h>
#include <round.h>
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"

static struct bitmap* free_frames;
static struct frame_entry* frame_table;
static unsigned clock, clock_max;

static struct lock frame_lock;

void
frame_init(size_t user_pages)
{
    size_t bm_pages = DIV_ROUND_UP(bitmap_buf_size(user_pages), PGSIZE);
    if (bm_pages > user_pages)
        bm_pages = user_pages;
    user_pages -= bm_pages;

    frame_table = (struct frame_entry*)malloc(sizeof(struct frame_entry) * user_pages);
    free_frames = bitmap_create(user_pages);
    size_t i;
    for (i = 0; i < user_pages; i++) {
        frame_table[i].num = i;
        frame_table[i].page_addr = NULL;
    }

    clock = 0;
    clock_max = (unsigned) user_pages;

    lock_init(&frame_lock);
}

struct frame_entry*
frame_get_multiple(size_t page_cnt)
{
    lock_acquire(&frame_lock);
    size_t fnum = bitmap_scan_and_flip(free_frames, 0, page_cnt, false);
    if (fnum != BITMAP_ERROR) {
        frame_table[fnum].paddr = palloc_get_page(PAL_USER | PAL_ASSERT | PAL_ZERO);
        lock_release(&frame_lock);
        return &frame_table[fnum];
    }
    else {
        /* Frame eviction. */
        while (pagedir_is_accessed(frame_table[clock].page_addr->pagedir, frame_table[clock].page_addr->vaddr))      // Check accecss.
        {
            pagedir_set_accessed(frame_table[clock].page_addr->pagedir, frame_table[clock].page_addr->vaddr, false);
            clock = (clock + 1) % clock_max;
        }

        /* Swap frame. */
        struct page* victim_page = frame_table[clock].page_addr;

        swap_insert(victim_page);
        victim_page->frame = NULL;
        victim_page->status = IN_SWAP;
        pagedir_clear_page(victim_page->pagedir, victim_page->vaddr);

        unsigned clock_prev = clock;
        clock = (clock + 1) % clock_max;
        lock_release(&frame_lock);
        return &frame_table[clock_prev];
    }
}

struct frame_entry*
get_frame()
{
    return frame_get_multiple(1);
}

void
free_frame(struct frame_entry* f){
    lock_acquire(&frame_lock);
    if(f== NULL){
      lock_release(&frame_lock);
      return;
    }
    pagedir_clear_page(f->page_addr->pagedir, f->page_addr->vaddr);
    bitmap_reset(free_frames,f->num);
    palloc_free_page(frame_table[f->num].paddr);
    f->page_addr = NULL;
    lock_release(&frame_lock);
}
