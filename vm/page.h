#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <hash.h>
#include "filesys/file.h"

enum page_type {
	PAGE_FILE,
	PAGE_SWAP,
	PAGE_ZERO
};

struct page {
	void *upage;
	void *kpage;
	struct hash_elem hash_elem;

	struct file *file;
	off_t file_offset;
	size_t read_bytes;
	size_t zero_bytes;
	bool writable;

	enum page_type type;
	bool loaded;
};

void page_table_init(struct hash *page_table);
bool page_insert(struct hash *page_table,struct page *p);
struct page *page_lookup(struct hash *page_table, void *addr);
void page_table_destroy(struct hash *page_table);
void page_destroy_func(struct hash_elem *e, void *aux);

unsigned page_hash_func(const struct hash_elem *e, void *aux);
bool page_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux);

bool vm_load_page(struct page *p, uint32_t *pagedir);

#endif
