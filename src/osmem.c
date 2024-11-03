// SPDX-License-Identifier: BSD-3-Clause
#include <unistd.h>
#include <sys/mman.h>
#include <stddef.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD 131072
#define ALIGNMENT 8
#define ALIGN_SIZE(size) ((size + ALIGNMENT - 1) & ~(ALIGNMENT - 1))
#define HEAP_PREALLOC_SIZE 131072

struct block_meta *free_list = NULL;
static void *preallocated = NULL;
static size_t pr_size = 0;

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	size_t total_size = ALIGN_SIZE(size + sizeof(struct block_meta));
	struct block_meta *block;
	if (total_size < MMAP_THRESHOLD)
	{
		if (preallocated == NULL)
		{
			preallocated = sbrk(HEAP_PREALLOC_SIZE);
			if (preallocated == (void *)-1)
			{
				errno = ENOMEM;
				return NULL;
			}
			pr_size = HEAP_PREALLOC_SIZE;
		}
		block = (struct block_meta *)preallocated;
		preallocated = (char *)preallocated + total_size;
		pr_size = pr_size - total_size;
	}
	else
	{
		block = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if ((void *)block == MAP_FAILED)
		{
			errno = ENOMEM;
			return NULL;
		}
	}
	block->size = size;
	block->status = 1;
	block->next = NULL;
	block->prev = NULL;

	return (void *)(block + 1);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *block = (struct block_meta *)((char *)ptr - sizeof(struct block_meta));
	block->status = 0;
	size_t total_size = block->size + sizeof(struct block_meta);
	if (total_size >= MMAP_THRESHOLD)
		munmap(block, total_size);
	else
	{
		if (free_list == NULL)
		{
			free_list = block;
			block->prev = NULL;
			block->next = NULL;
		}
		else
		{
			struct block_meta *aux = free_list;
			while (aux)
				aux = aux->next;
			aux->next = block;
			block->prev = aux;
			block->next = NULL;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
