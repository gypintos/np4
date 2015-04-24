#include "vm/swap.h"

#include <debug.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

int SEC_NUM = PGSIZE / BLOCK_SECTOR_SIZE;

void swap_init(void)
{
  sw = block_get_role(BLOCK_SWAP);
  /** NEW ADDED HERE **/
  if(sw == NULL){
    return;
  }
  sw_table = bitmap_create(block_size(sw)/SEC_NUM);
  lock_init(&sw_lock);
}

void swap_get(block_sector_t sec, void * addr)
{
  int i = 0; 
  while (i < SEC_NUM){
    block_read(sw, i + SEC_NUM * sec, addr + i* BLOCK_SECTOR_SIZE);
    i++;
  }
  lock_acquire(&sw_lock);
  bitmap_set (sw_table, sec, false);
  lock_release(&sw_lock);
}

block_sector_t swap_set(void * addr)
{
  lock_acquire(&sw_lock);
  block_sector_t sec = bitmap_scan (sw_table, 0, 1, false);
  if(sec == BITMAP_ERROR){
    PANIC("Swap table full error.");
  }
  int i = 0;
  while (i < SEC_NUM){
    block_write(sw, i + SEC_NUM * sec, addr + i * BLOCK_SECTOR_SIZE);
    i++;
  }
  bitmap_set (sw_table, sec, true);
  lock_release(&sw_lock);
  return sec;
}


void
release_sector (block_sector_t sec)
{
  lock_acquire(&sw_lock);
  bitmap_set (sw_table, sec, false);
  lock_release(&sw_lock);
}
