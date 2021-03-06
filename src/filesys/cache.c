#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include <bitmap.h>
#include <string.h>

#define BUF_SIZE_BLOCK 64
#define BUF_SIZE_PAGE (BLOCK_SECTOR_SIZE * BUF_SIZE_BLOCK) / PGSIZE
#define PRE_READ_POOL 30
#define SLEEP_AFTER 15
#define SLEEP_BEFORE 50

struct bitmap *c_map;
struct lock c_map_lock;
void *c_base;
struct hash_iterator c_it;

struct hash evic_buf_ht;
void *buf_clock_curr;
void *buf_clock_min;
void *buf_clock_max;

struct hash buf_ht;
struct lock c_lock;
struct condition cond_pin;
struct condition pre_read_cond;
struct lock pre_read_lock;

bool
cache_elem_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux);
unsigned
cache_hash_fun (const struct hash_elem *e, void *aux);
bool
evic_cache_elem_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux);
unsigned
evic_cache_hash_fun (const struct hash_elem *e, void *aux UNUSED);
struct cache_elem *load_sec_to_cache (block_sector_t sector, bool isPreRead);
struct cache_elem *find_evic_cache_elem (void* ch_addr);
struct cache_elem *load_sec_to_cache_after_evic (block_sector_t sector, bool isPreRead);
struct cache_elem *find_cache_elem (block_sector_t sec);
void buf_to_sec (void *ch_addr, const void *buffer, size_t write_bytes);
struct cache_elem *pick_ce (void);
void read_sec_to_buf (const void *ch_addr, void *buffer, size_t read_bytes);
void pre_read_cache (void *aux);
void cache_to_disk (struct cache_elem *ce);


void cache_buf_init (void) {
	c_base = palloc_get_multiple(PAL_ZERO|PAL_ASSERT, BUF_SIZE_PAGE);
	c_map = bitmap_create(BUF_SIZE_BLOCK);
	lock_init(&c_map_lock);
	lock_init(&c_lock);
	lock_init(&pre_read_lock);
	cond_init(&cond_pin);
	cond_init(&pre_read_cond);
	hash_init(&buf_ht, cache_hash_fun, cache_elem_cmp, NULL);
	hash_init(&evic_buf_ht, evic_cache_hash_fun, evic_cache_elem_cmp, NULL);
	list_init(&pre_read_que);
	buf_clock_min = c_base;
	buf_clock_curr = buf_clock_min;
	buf_clock_max = c_base + (BUF_SIZE_BLOCK -1) * BLOCK_SECTOR_SIZE;
	ch_teminate = false;
	ch_begin = true;
	pre_read_lock_ptr = &pre_read_lock;
	pre_read_cond_ptr = &pre_read_cond;
	
	int i = PRE_READ_POOL;
	while(i != 0){
		thread_create("pre_read_" + i, PRI_DEFAULT, pre_read_cache, NULL);
		i--;
	}

}	



void pre_read_cache (void *aux UNUSED) {
	 while (!ch_teminate) {
		 struct list_elem *e = NULL;
		 lock_acquire(&pre_read_lock);
		 while (!e){
		 	if (list_empty(&pre_read_que)){
		 		cond_wait(&pre_read_cond, &pre_read_lock);	
		 	} else {
		 		e = list_pop_front(&pre_read_que);
		 	}
		 }
		 lock_release(&pre_read_lock);
		 
		 struct pre_read_elem *pre = list_entry(e, struct pre_read_elem, elem);
		 block_sector_t sec_id = pre->sec_id;
		 free(pre);

		 lock_acquire(&c_lock);
		 struct cache_elem *ce = find_cache_elem(sec_id);
		 if (ce) {
		 	lock_release(&c_lock);
		 	continue;
		 }
		 lock_release(&c_lock);
		 ce = load_sec_to_cache (sec_id, true);
	 }
}

void
get_sec_from_cache (block_sector_t sec_id, void *buffer,
				  int sector_ofs, int chunk_size) {
	 lock_acquire(&c_lock);
	 struct cache_elem *ce = find_cache_elem (sec_id);
	 if (ce) ce->pin_cnt++;
	 lock_release(&c_lock);
	 if (!ce) 
		 ce = load_sec_to_cache (sec_id, false);
	 read_sec_to_buf (ce->ch_addr + sector_ofs, buffer, chunk_size);
	 lock_acquire(&c_lock);
	 ce->isUsed = true;
	 ce->pin_cnt--;
	 if (ce->pin_cnt == 0)
		cond_signal(&cond_pin, &c_lock);
	 lock_release(&c_lock);
}

void buf_to_sec (void *ch_addr, const void *buffer, size_t write_bytes)
{
	memcpy(ch_addr, buffer, write_bytes);
}

void
buf_to_cache (block_sector_t sec_id, const void *buffer,
			  int sector_ofs, int chunk_size) {
	lock_acquire(&c_lock);
	struct cache_elem *ce = find_cache_elem(sec_id);
	if (ce) ce->pin_cnt++;
	lock_release(&c_lock);
	if (!ce)
		ce = load_sec_to_cache(sec_id, false);
	buf_to_sec (ce->ch_addr + sector_ofs, buffer, chunk_size);
	lock_acquire(&c_lock);
	ce->isDirty = true;
	ce->isUsed = true;
	ce->pin_cnt--;
	if (ce->pin_cnt == 0)
		cond_signal(&cond_pin, &c_lock);
	lock_release(&c_lock);
}

struct cache_elem *load_sec_to_cache_after_evic (block_sector_t sector, bool isPreRead)
{
	lock_acquire(&c_lock);
	struct cache_elem *ce_evict = pick_ce();
	lock_release(&c_lock);
	struct cache_elem *ce = malloc(sizeof (struct cache_elem));
	ce->secId = sector;
	ce->pin_cnt = 0;
	ce->ch_addr = ce_evict->ch_addr;
	block_read(fs_device, sector, ce->ch_addr);
	lock_acquire(&c_lock);
	struct cache_elem *ce_ = find_cache_elem(sector);
	if (ce_){
		if(!isPreRead) ce_->pin_cnt++;
		ce_->isUsed = true;
		lock_acquire(&c_map_lock);
		bitmap_set(c_map, (ce->ch_addr - c_base) / BLOCK_SECTOR_SIZE, false);
		lock_release(&c_map_lock);
		free(ce);
	} else {
		if(!isPreRead) ce->pin_cnt++;
		ce->isUsed = true;
		hash_insert(&buf_ht, &ce->buf_hash_elem);
		hash_insert(&evic_buf_ht, &ce->evic_buf_hash_elem);
	}

	lock_release(&c_lock);
	free(ce_evict);

	if (ce_) return ce_;
	else return ce;
}

void thread_cache_to_disk (void) {
  while(true) {
	if (!ch_begin){
		thread_sleep(SLEEP_BEFORE);
	}
	else {
		lock_acquire(&c_lock);
		if (ch_teminate){
			lock_release(&c_lock);
			break;
		} else {
			lock_release(&c_lock);
			all_cache_to_disk(false);
			thread_sleep(SLEEP_AFTER);
		}
	}
  }
}

struct cache_elem *load_sec_to_cache (block_sector_t sector, bool isPreRead)
{
  lock_acquire(&c_map_lock);
  size_t index = bitmap_scan (c_map, 0, 1, false);
  if (index != BITMAP_ERROR){
	bitmap_set (c_map, index, true);
  	lock_release(&c_map_lock);
  } else {
  	lock_release(&c_map_lock);
	return load_sec_to_cache_after_evic(sector, isPreRead);
  }

  void *ch_addr  = c_base + BLOCK_SECTOR_SIZE * index;

  block_read(fs_device, sector, ch_addr);

  struct cache_elem *ce = malloc(sizeof (struct cache_elem));
  ce->secId = sector;
  ce->pin_cnt = 0;
  ce->ch_addr = ch_addr; 
 
  lock_acquire(&c_lock);
  struct cache_elem *ce_ = find_cache_elem(sector);
  if (ce_){
  	if (!isPreRead) ce_->pin_cnt++;
	ce_->isUsed = true;
	lock_acquire(&c_map_lock);
	bitmap_set (c_map, index, false);
	lock_release(&c_map_lock);
	free(ce);
  } else {
  	if (!isPreRead) ce->pin_cnt++;
	ce->isUsed = true;
	hash_insert(&buf_ht, &ce->buf_hash_elem);
	hash_insert(&evic_buf_ht, &ce->evic_buf_hash_elem);
  }

  lock_release(&c_lock);
  if (ce_) return ce_;
  else return ce;
}

void cache_to_disk (struct cache_elem *ce) {
	block_write(fs_device, ce->secId, ce->ch_addr);
}

void read_sec_to_buf (const void *ch_addr, void *buffer, size_t read_bytes)
{
	memcpy(buffer, ch_addr, read_bytes);
}


void all_cache_to_disk (bool exiting) {
	lock_acquire(&c_lock);
	hash_first(&c_it, &buf_ht);
	ch_teminate = exiting;
	while(hash_next (&c_it)){
		struct cache_elem *ce = hash_entry (hash_cur(&c_it), struct cache_elem, buf_hash_elem);
		if (ce->isDirty && (exiting || ce->pin_cnt == 0)) {
			ce->isDirty = false;
			cache_to_disk(ce);
		}
	}
	lock_release(&c_lock);
}

struct cache_elem *pick_ce (void) {
	
	struct cache_elem *ce;
	struct cache_elem *cef = NULL;
	struct cache_elem *cef_dirty = NULL;
	
	while (cef == NULL && cef_dirty == NULL) {
		void *start = buf_clock_curr == buf_clock_min ? buf_clock_max : buf_clock_curr - BLOCK_SECTOR_SIZE;
		while (buf_clock_curr != start) {
			buf_clock_curr = buf_clock_curr >= buf_clock_max ? buf_clock_min : buf_clock_curr;
			ce = find_evic_cache_elem(buf_clock_curr);

			if (ce) {
				if (ce->isUsed) {
					if (ce->pin_cnt == 0) {
						if (ce->isDirty && !cef_dirty) {
							cef_dirty = ce;
						} else if (!ce->isDirty && !cef) {
							cef = ce;
						}
					}
					buf_clock_curr += BLOCK_SECTOR_SIZE;
					ce->isUsed = false;
					continue;
				} else {
					if (ce->pin_cnt == 0) {
						if (ce->isDirty) {
							cache_to_disk(ce);
							ce->isDirty = false;
						}
						hash_delete (&buf_ht, &ce->buf_hash_elem);
						hash_delete (&evic_buf_ht, &ce->evic_buf_hash_elem);
						return ce;
					} else {
						buf_clock_curr += BLOCK_SECTOR_SIZE;
						continue;
					}
				}

			} else {
				buf_clock_curr += BLOCK_SECTOR_SIZE;
				continue;
			}
		}
		if (cef || cef_dirty ) continue;
		cond_wait(&cond_pin, &c_lock);
	}
	struct cache_elem *ce_chosen = cef != NULL ? cef : cef_dirty;
	if (ce_chosen == cef_dirty) {
		cache_to_disk(ce_chosen);
		ce_chosen->isDirty = false;
	}
	hash_delete (&buf_ht, &ce_chosen->buf_hash_elem);
	hash_delete (&evic_buf_ht, &ce_chosen->evic_buf_hash_elem);
	return ce_chosen;
}


bool cache_elem_cmp (const struct hash_elem *a, const struct hash_elem *b,
           			void *aux UNUSED){
  const struct cache_elem* a1 = hash_entry(a, struct cache_elem, buf_hash_elem);
  const struct cache_elem* b1 = hash_entry(b, struct cache_elem, buf_hash_elem);
  return a1->secId < b1->secId;
}

unsigned cache_hash_fun (const struct hash_elem *e, void *aux UNUSED){
  const struct cache_elem* ce = hash_entry(e, struct cache_elem, buf_hash_elem);
  return ce->secId;
}

unsigned evic_cache_hash_fun (const struct hash_elem *e, void *aux UNUSED){
  const struct cache_elem* ce = hash_entry(e, struct cache_elem, evic_buf_hash_elem);
  return (unsigned)ce->ch_addr;
}

bool evic_cache_elem_cmp (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED){
  const struct cache_elem *a1 = hash_entry (a, struct cache_elem, evic_buf_hash_elem);
  const struct cache_elem *b1 = hash_entry (b, struct cache_elem, evic_buf_hash_elem);
  return (unsigned)a1->ch_addr < (unsigned)b1->ch_addr;
}

struct cache_elem *find_evic_cache_elem (void* ch_addr){
  struct cache_elem ce;
  ce.ch_addr = ch_addr;
  struct hash_elem* e = hash_find(&evic_buf_ht, &ce.evic_buf_hash_elem);
  if (e!=NULL){
  	return hash_entry(e,struct cache_elem,evic_buf_hash_elem);
  } else {
  	return NULL;
  }
}

void *get_meta_inode (block_sector_t sec_id) {
	 lock_acquire(&c_lock);
	 struct cache_elem* ce = find_cache_elem (sec_id);
	 if (ce) ce->pin_cnt++;
	 lock_release(&c_lock);
	 if (!ce) 
		 ce = load_sec_to_cache (sec_id,false);
	 
	 return ce->ch_addr;
}

struct cache_elem *find_cache_elem (block_sector_t sec){
  struct cache_elem ce;
  ce.secId = sec;
  struct hash_elem* e = hash_find(&buf_ht, &ce.buf_hash_elem);
  if (e!=NULL){
  	return hash_entry(e,struct cache_elem,buf_hash_elem);
  } else {
  	return NULL;
  }

}

void cache_exit (void) {
	lock_acquire(&c_lock);
	ch_teminate = true;
	lock_release(&c_lock);
}

void free_meta_inode (block_sector_t sec_id, bool dirty) {
	 lock_acquire(&c_lock);
	 struct cache_elem *ce = find_cache_elem (sec_id);
	 if (!ce->isDirty) ce->isDirty = dirty;
	 ce->isUsed = true;
	 ce->pin_cnt--;
	 if (ce->pin_cnt == 0)
		cond_signal(&cond_pin, &c_lock);
	 lock_release(&c_lock);
}


