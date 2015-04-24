#ifndef VM_SWAP_H_
#define VM_SWAP_H_

#include "devices/block.h"
#include <bitmap.h>

struct block *sw;
struct bitmap *sw_table;
struct lock sw_lock;

void swap_init (void);
block_sector_t swap_set (void * addr);
void swap_get (block_sector_t sector, void * addr);
void release_sector (block_sector_t sector);
#endif
