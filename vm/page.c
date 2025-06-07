#include "vm/page.h"
#include <stdio.h>
#include <stdint.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

/* hash function, address comparator */
/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem* p_, void* aux UNUSED)
{
    const struct page* p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->vaddr, sizeof p->vaddr);
}

/* Returns true if page a precedes page b. */
bool
page_less(const struct hash_elem* a_, const struct hash_elem* b_,
    void* aux UNUSED)
{
    const struct page* a = hash_entry(a_, struct page, hash_elem);
    const struct page* b = hash_entry(b_, struct page, hash_elem);

    return pg_no(a->vaddr) < pg_no(b->vaddr);
}

void
page_destructor(struct hash_elem* e, void* aux UNUSED)
{
    struct page* p = hash_entry(e, struct page, hash_elem);
    if (p->frame != NULL) {
        struct frame_entry* f = p->frame;
        free_frame(f);
        p->frame = NULL;
    }
    if (p->block_sector != -1)
        swap_free(p);
    free(p);
}

/* Function to search the hash table. */
/* Returns the page containing the given virtual address, */
/* or a null pointer if no such page exists. */
struct page*
page_find(struct hash* spt, void* va)
{
    struct page page;
    struct hash_elem* e;

    page.vaddr = pg_round_down(va);

    e = hash_find(spt, &page.hash_elem);

    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}