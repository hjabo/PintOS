#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdint.h>
#include "vm/page.h"
#include "vm/swap.h"

struct frame_entry {
    uint32_t num;             // Frame number
    void* paddr;              // Frame physical address
    struct page* page_addr;      // Pointer to page that occupies the frame
};

void frame_init(size_t);
struct frame_entry* get_frame(void);
struct frame_entry* frame_get_multiple(size_t);
void free_frame(struct frame_entry*);
#endif /* vm/frame.h */
