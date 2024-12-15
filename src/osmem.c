// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include "osmem.h"
// ---------
//#pragma once
#include "printf.h"
// ----------

#define MMAP_THRESHOLD 131072
#define ALIGNMENT 8
#define ALIGN_SIZE(size) ((size + ALIGNMENT - 1) & ~(ALIGNMENT - 1))
#define HEAP_PREALLOC_SIZE 131072
#define PAGE_SIZE 4096
#define STATUS_FREE 0
#define STATUS_ALLOC 1
#define STATUS_MAPPED 2

struct block_meta {
	size_t size;
	int status;
	short mall;
	struct block_meta *prev;
	struct block_meta *next;
};

struct block_meta *mem_list;
static void *preallocated;
static size_t offset;

void add_block_after(struct block_meta *block, struct block_meta *new)
{
	new->prev = block;
	new->next = block->next;
	block->next = new;
	if (new->next)
		new->next->prev = new;
}

void add_block(struct block_meta *block)
{
	block->next = NULL;
	if (mem_list == NULL) {
		mem_list = block;
		block->prev = NULL;
	} else {
		struct block_meta *last = mem_list;

		while (last->next)
			last = last->next;
		last->next = block;
		block->prev = last;
	}
}

int all_blocks_mapped(struct block_meta *mem_list)
{
	struct block_meta *current = mem_list;

	while (current != NULL) {
		if (current->status != STATUS_MAPPED)
			return 0;
		current = current->next;
	}
	return 1;
}

void merge_blocks(struct block_meta *block1, struct block_meta *block2)
{
	if ((char *)block1 + ALIGN_SIZE(sizeof(struct block_meta) + block1->size) == (char *)block2)
		block1->size += ALIGN_SIZE(block2->size + sizeof(struct block_meta));
	block1->next = block2->next;
	if (block2->next)
		block2->next->prev = block1;
}

void coalesce_blocks(void)
{
	struct block_meta *aux = mem_list;

	while (aux && aux->next) {
		if (aux->status == 0 && aux->next->status == 0)
			merge_blocks(aux, aux->next);
		else
			aux = aux->next;
	}
}

struct block_meta *find_block(size_t size)
{
	if (mem_list == NULL)
		return NULL;
	coalesce_blocks();
	struct block_meta *aux = mem_list;
	struct block_meta *best_block = NULL;

	while (aux) {
		if (aux->status == 0 && ALIGN_SIZE(aux->size) >= ALIGN_SIZE(size))
			if (best_block == NULL || aux->size < best_block->size)
				best_block = aux;
		aux = aux->next;
	}
	return best_block;
}

struct block_meta *last_block(void)
{
	if (mem_list == NULL)
		return NULL;
	struct block_meta *aux = mem_list;

	while (aux->next)
		aux = aux->next;
	if (aux->status == 0)
		return aux;
	return NULL;
}

struct block_meta *last_real_block(void)
{
	if (mem_list == NULL)
		return NULL;

	struct block_meta *aux = mem_list;

	while (aux->next)
		aux = aux->next;
	return aux;
}

void split_block(struct block_meta *block, size_t size)
{
	size_t total_size = ALIGN_SIZE(size + sizeof(struct block_meta));
	size_t old_size = ALIGN_SIZE(block->size + sizeof(struct block_meta));
	size_t remaining_size = old_size - total_size;

	if (remaining_size >= ALIGN_SIZE(1 + sizeof(struct block_meta))) {
		struct block_meta *new = (struct block_meta *)((char *)block + total_size);

		new->size = remaining_size - sizeof(struct block_meta);
		new->status = 0;
		block->size = ALIGN_SIZE(size);

		add_block_after(block, new);
	}
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	size_t total_size = ALIGN_SIZE(size + sizeof(struct block_meta));

	coalesce_blocks();
	struct block_meta *block;
	struct block_meta *new = find_block(size);

	if (new)
		new->status = 1;
	struct block_meta *last = last_block();

	if (total_size < MMAP_THRESHOLD) {
		if (mem_list == NULL) {
			preallocated = sbrk(HEAP_PREALLOC_SIZE);
			if (preallocated == (void *)-1) {
				errno = ENOMEM;
				return NULL;
			}
			offset = 0;
		}
		if (new == NULL) {
			if (offset + total_size <= HEAP_PREALLOC_SIZE) {
				block = preallocated + offset;
				offset += total_size;
			} else {
				if (last) {
					size_t old_size = ALIGN_SIZE(last->size + sizeof(struct block_meta));

					if (old_size < total_size) {
						size_t dif = total_size - old_size;

						sbrk(dif);
						block = last;
						block->size = size;
					}
				} else {
					block = sbrk(total_size);
					if ((void *)block == (void *)-1) {
						errno = ENOMEM;
						return NULL;
					}
				}
			}
		} else {
			split_block(new, size);
			block = new;
		}
	} else {
		block = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if ((void *)block == MAP_FAILED) {
			errno = ENOMEM;
			return NULL;
		}
		block->status = STATUS_MAPPED;
	}
	if (block->status == 0)
		block->status = 1;
	block->mall = 1;
	if (new == NULL && last == NULL) {
		block->size = size;
		add_block(block);
	}

	return (void *)(block + 1);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *block = (struct block_meta *)((char *)ptr - sizeof(struct block_meta));
	size_t total_size = ALIGN_SIZE(block->size + sizeof(struct block_meta));

	block->status = 0;
	if (block->mall == 1) {
		if (total_size >= MMAP_THRESHOLD) {
			if (block->prev)
				block->prev->next = block->next;
			if (block->next)
				block->next->prev = block->prev;
			munmap(block, total_size);
		}
	} else if (block->mall == 2) {
		if (total_size >= PAGE_SIZE) {
			if (mem_list == block)
				mem_list = NULL;
			munmap(block, total_size);
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t good_size = nmemb * size;

	if (good_size == 0)
		return NULL;

	size_t total_size = ALIGN_SIZE(good_size + sizeof(struct block_meta));

	coalesce_blocks();
	struct block_meta *block;
	struct block_meta *new = find_block(good_size);

	if (new)
		new->status = 1;
	struct block_meta *last = last_block();

	if (total_size < PAGE_SIZE) {
		if (mem_list == NULL) {
			preallocated = sbrk(HEAP_PREALLOC_SIZE);
			if (preallocated == (void *)-1) {
				errno = ENOMEM;
				return NULL;
			}
			offset = 0;
		}
		if (new == NULL) {
			if (offset + total_size <= HEAP_PREALLOC_SIZE) {
				block = preallocated + offset;
				offset += total_size;
			} else {
				if (last) {
					size_t old_size = ALIGN_SIZE(last->size + sizeof(struct block_meta));

					if (old_size < total_size) {
						size_t dif = total_size - old_size;

						sbrk(dif);
						block = last;
						block->size = good_size;
					}
				} else {
					block = sbrk(total_size);
					if ((void *)block == (void *)-1) {
						errno = ENOMEM;
						return NULL;
					}
				}
			}
		} else {
			if (total_size < new->size)
				split_block(new, good_size);
			block = new;
		}
	} else {
		block = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if ((void *)block == MAP_FAILED) {
			errno = ENOMEM;
			return NULL;
		}
	}
	block->status = 1;
	block->mall = 2;
	if (new == NULL && last == NULL) {
		block->size = good_size;
		add_block(block);
	}
	memset((block + 1), 0, good_size);

	return (void *)(block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	if (ptr == NULL)
		return os_malloc(size);
	int ok = 0;
	struct block_meta *block = (struct block_meta *)((char *)ptr - sizeof(struct block_meta));

	if (block->status == 0)
		return NULL;

	size_t total_size = ALIGN_SIZE(size + sizeof(struct block_meta));
	size_t total_old_size = ALIGN_SIZE(block->size + sizeof(struct block_meta));
	struct block_meta *block2;
	struct block_meta *last = last_real_block();
	struct block_meta *new = find_block(size);

	if (total_size < MMAP_THRESHOLD) {
		if (total_size <= total_old_size) {
			if (mem_list == NULL || all_blocks_mapped(mem_list) || block->status == STATUS_MAPPED) {
				if (preallocated == NULL) {
					preallocated = sbrk(HEAP_PREALLOC_SIZE);
					if (preallocated == (void *)-1) {
						errno = ENOMEM;
						return NULL;
					}
					offset = 0;
				}
				if (offset + total_size <= HEAP_PREALLOC_SIZE) {
					block2 = preallocated + offset;
					offset += total_size;
				} else {
					block2 = sbrk(total_size);
					if ((void *)block2 == (void *)-1) {
						errno = ENOMEM;
						return NULL;
					}
				}
				block2->size = size;
				block2->status = 1;
				block2->mall = 1;
				add_block(block2);
				memcpy((void *)(block2 + 1), ptr, block2->size);
				os_free(ptr);
				ok = 1;
				return (void *)(block2 + 1);
			}
			if (ok == 0) {
				split_block(block, size);
				return ptr;
			}
		} else {
			struct block_meta *next_block = block->next;

			while (next_block && next_block->status == 0) {
				merge_blocks(block, next_block);
				if (ALIGN_SIZE(block->size + sizeof(struct block_meta)) >= total_size) {
					split_block(block, size);
					return ptr;
				}
				next_block = next_block->next;
			}
			if (last == block) {
				size_t dif = total_size - total_old_size;

				sbrk(dif);
				block->size = size;
				return (void *)(block + 1);
			}
			if (new) {
				split_block(new, size);
				block2 = new;
				block2->size = size;
				block2->status = 1;
				block2->mall = 1;
				memcpy((void *)(block2 + 1), ptr, block->size);
				os_free(ptr);
				coalesce_blocks();
				ok = 1;
				return (void *)(block2 + 1);
			}
			if (ok == 0) {
				if (preallocated == NULL) {
					preallocated = sbrk(HEAP_PREALLOC_SIZE);
					if (preallocated == (void *)-1) {
						errno = ENOMEM;
						return NULL;
					}
					offset = 0;
				}
				if (offset + total_size <= HEAP_PREALLOC_SIZE) {
					block2 = preallocated + offset;
					offset += total_size;
				} else {
					block2 = sbrk(total_size);
					if ((void *)block2 == (void *)-1) {
						errno = ENOMEM;
						return NULL;
					}
				}
				block2->size = size;
				block2->status = 1;
				block2->mall = 1;
				add_block(block2);
				memcpy((void *)(block2 + 1), ptr, block2->size);
				os_free(ptr);
				return (void *)(block2 + 1);
			}
		}
	} else {
		if (total_size <= total_old_size) {
			if (block->status == STATUS_MAPPED) {
				block2 = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
				if ((void *)block == MAP_FAILED) {
					errno = ENOMEM;
					return NULL;
				}
				block2->size = size;
				block2->status = STATUS_MAPPED;
				block2->mall = 1;
				add_block(block2);
				memcpy((void *)(block2 + 1), ptr, block2->size);
				os_free(ptr);
				ok = 1;
				return (void *)(block2 + 1);
			}
			if (ok == 0) {
				split_block(block, size);
				block->next->status = STATUS_MAPPED;
				return ptr;
			}
		} else {
			block2 = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
			if ((void *)block == MAP_FAILED) {
				errno = ENOMEM;
				return NULL;
			}
			block2->size = size;
			block2->status = STATUS_MAPPED;
			block2->mall = 1;
			add_block(block2);
			memcpy((void *)(block2 + 1), ptr, block->size);
			os_free(ptr);
			return (void *)(block2 + 1);
		}
	}
	return NULL;
}
