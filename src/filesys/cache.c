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

unsigned
cache_hash_fun (const struct hash_elem *p_, void *aux);
bool
cache_elem_cmp (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
void
cache_destructor (struct hash_elem *ce_, void *aux UNUSED);

unsigned
evic_cache_hash_fun (const struct hash_elem *p_, void *aux UNUSED);
bool
evic_cache_elem_cmp (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);

struct cache_elem *find_cache_elem (block_sector_t sector);
struct cache_elem *find_evic_cache_elem (void* ch_addr);
struct cache_elem *load_sec_to_cache (block_sector_t sector, bool isPreRead);
struct cache_elem *load_sec_to_cache_after_evic (block_sector_t sector, bool isPreRead);
void read_sec_to_buf (const void *ch_addr, void *buffer, size_t read_bytes);
void buf_to_sec (void *ch_addr, const void *buffer, size_t write_bytes);
struct cache_elem *pick_ce (void);

void cache_to_disk (struct cache_elem *ce);
void pre_read_cache (void *aux);

void cache_buf_init (void) {
	/* Allocate full cache */
	// c_base = palloc_get_multiple(PAL_ZERO|PAL_ASSERT, BUF_SIZE_PAGE);
	// /* Init bitmap to track cache usage */
 //    c_map = bitmap_create(BUF_SIZE_BLOCK);
	// /* Lock to operate on cache */
	// lock_init(&c_map_lock);
	// lock_init(&c_lock);
	// cond_init(&cond_pin);
	// /* Init hash table of cache contents */
	// hash_init(&buf_ht, cache_hash_fun, cache_elem_cmp, NULL);
	// /* Init hash table of for eviction algo */
	// hash_init(&evic_buf_ht, evic_cache_hash_fun, evic_cache_elem_cmp, NULL);
	// buf_clock_curr = buf_clock_min = c_base;
	// buf_clock_max = c_base + (BUF_SIZE_BLOCK - 1) * BLOCK_SECTOR_SIZE;


	// /* Thread that periodically writes back to disk */
	// ch_teminate = false;
	// ch_begin = true;

	// lock_init(&pre_read_lock);
	// pre_read_lock_ptr = &pre_read_lock;
	// cond_init(&pre_read_cond);
	// pre_read_cond_ptr = &pre_read_cond;
	// list_init(&pre_read_que);

	// /* Create read-ahead thread pool */
	// int i = PRE_READ_POOL;
	// while (i != 0) {
	// 	thread_create("pre_read_" + i, PRI_DEFAULT, pre_read_cache, NULL);
	// 	i--;
	// }

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



/* Looks up cache entry for the given sec_id, if
   such entry no found in cache, adds it */
void
read_from_cache (block_sector_t sec_id, void *buffer,
				  int sector_ofs, int chunk_size) {
     /* Lookup and pin cache entry - c_lock */
	 lock_acquire(&c_lock);
	 struct cache_elem *ce = find_cache_elem (sec_id);
	 if (ce) ce->pin_cnt++;
	 lock_release(&c_lock);

	 /* Entry not found, create new */
	 if (!ce) 
		 ce = load_sec_to_cache (sec_id, false);

	 /* Read data to process buffer */
	 read_sec_to_buf (ce->ch_addr + sector_ofs, buffer, chunk_size);
 
	 /* Unpin cache entry - c_lock */
	 lock_acquire(&c_lock);
	 ce->isUsed = true;
	 /* Signal to choosing for evict threads */
	 ce->pin_cnt--;
	 if (ce->pin_cnt == 0)
		cond_signal(&cond_pin, &c_lock);
	 lock_release(&c_lock);
}

void pre_read_cache (void *aux UNUSED) {
	 while (!ch_teminate) {
		 struct list_elem *e = NULL;
		 lock_acquire(&pre_read_lock);
		 // do {
			//  if (!list_empty(&pre_read_que)) {
			// 	e = list_pop_front(&pre_read_que);
			//  }
			//  else {
			// 	cond_wait(&pre_read_cond, &pre_read_lock);
			//  }
		 // } while (e == NULL);
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
		 // if (ce != NULL) {

			//  lock_release(&c_lock);
			//  /* Late read-ahead.. Stop */
			//  continue;
		 // }
		 lock_release(&c_lock);

		 /* Not in cache */
		 ce = load_sec_to_cache (sec_id, true);
	 }
}

void
buf_to_cache (block_sector_t sec_id, const void *buffer,
			  int sector_ofs, int chunk_size) {
 /* Lookup and pin cache entry - c_lock */
	lock_acquire(&c_lock);
	struct cache_elem *ce = find_cache_elem(sec_id);
	// if (ce != NULL) {
	// 	ce->pin_cnt++;
	// }
	if (ce) ce->pin_cnt++;
	lock_release(&c_lock);

	/* Entry not found - add a new one */
	// if (ce == NULL) {
	// 	ce = load_sec_to_cache(sec_id, /* is readahead */ false);
	// }
	if (!ce)
		ce = load_sec_to_cache(sec_id, false);

    /* Write to cache entry data*/
	buf_to_sec (ce->ch_addr + sector_ofs, buffer, chunk_size);

	/* Update cache entry */
	lock_acquire(&c_lock);
	ce->isDirty = true;
	ce->isUsed = true;

	/* Signal to choosing for evict threads */
	ce->pin_cnt--;
	if (ce->pin_cnt == 0)
		cond_signal(&cond_pin, &c_lock);
	lock_release(&c_lock);
}

/* Write given buffer to sector at given address from cache */
void buf_to_sec (void *ch_addr, const void *buffer, size_t write_bytes)
{
	memcpy(ch_addr, buffer, write_bytes);
}

/* load_sec_to_cache given sector into cache */
struct cache_elem *load_sec_to_cache (block_sector_t sector, bool isPreRead)
{
  /* Find and mark place in cache map - c_map_lock*/
  lock_acquire(&c_map_lock);
  size_t index = bitmap_scan (c_map, 0, 1, false);
  // if (index == BITMAP_ERROR) {
	 //  /* No free space - evict and load_sec_to_cache */
	 //  lock_release(&c_map_lock);
	 //  return load_sec_to_cache_after_evic(sector, isPreRead);
  // }
  // bitmap_set (c_map, index, true);
  // lock_release(&c_map_lock);
  if (index != BITMAP_ERROR){
	bitmap_set (c_map, index, true);
  	lock_release(&c_map_lock);
  } else {
  	lock_release(&c_map_lock);
	return load_sec_to_cache_after_evic(sector, isPreRead);
  }

  void *ch_addr  = c_base + BLOCK_SECTOR_SIZE * index;

  /* Write sector to cache */
  block_read(fs_device, sector, ch_addr);

  /* Initialize cache entry */
  struct cache_elem *ce = malloc(sizeof (struct cache_elem));
  ce->secId = sector;
  ce->pin_cnt = 0;
  ce->ch_addr = ch_addr;
  
  /* Add into cache contents - c_lock*/
  lock_acquire(&c_lock);
  struct cache_elem *ce_ = find_cache_elem(sector);
 //  if (ce_ == NULL) {
	// ce->pin_cnt += isPreRead ? 0 : 1;
	// ce->isUsed = true;
	// hash_insert(&buf_ht, &ce->buf_hash_elem);
	// hash_insert(&evic_buf_ht, &ce->evic_buf_hash_elem);
 //  }
 //  else {
	// ce_->pin_cnt += isPreRead ? 0 : 1;
	// ce_->isUsed = true;
	// lock_acquire(&c_map_lock);
	// bitmap_set (c_map, index, false);
	// lock_release(&c_map_lock);
	// free(ce);
 //  }
  if (ce_){
  	// ce_->pin_cnt += isPreRead ? 0 : 1;
  	if (!isPreRead) ce_->pin_cnt++;
	ce_->isUsed = true;
	lock_acquire(&c_map_lock);
	bitmap_set (c_map, index, false);
	lock_release(&c_map_lock);
	free(ce);
  } else {
  	// ce->pin_cnt += isPreRead ? 0 : 1;
  	if (!isPreRead) ce->pin_cnt++;
	ce->isUsed = true;
	hash_insert(&buf_ht, &ce->buf_hash_elem);
	hash_insert(&evic_buf_ht, &ce->evic_buf_hash_elem);
  }

  lock_release(&c_lock);
  // return ce_ == NULL ? ce : ce_;
  if (ce_) return ce_;
  else return ce;
}

/* load_sec_to_cache given sector into cache, after evicting other cache entry */
struct cache_elem *load_sec_to_cache_after_evic (block_sector_t sector, bool isPreRead)
{
	/* Choose entry to evict by deleting from cache - c_lock */
	lock_acquire(&c_lock);
	struct cache_elem *ce_evict = pick_ce();
	lock_release(&c_lock);

	/* Initialize cache entry */
	struct cache_elem *ce = malloc(sizeof (struct cache_elem));
	ce->secId = sector;
	ce->pin_cnt = 0;
	ce->ch_addr = ce_evict->ch_addr;

	/* Write sector to cache */
	block_read(fs_device, sector, ce->ch_addr);

	/* Add entry to cache */
	lock_acquire(&c_lock);
	struct cache_elem *ce_ = find_cache_elem(sector);
	// if (ce_ == NULL) {
	// 	ce->pin_cnt += isPreRead ? 0 : 1;
	// 	ce->isUsed = true;
	// 	hash_insert(&buf_ht, &ce->buf_hash_elem);
	// 	hash_insert(&evic_buf_ht, &ce->evic_buf_hash_elem);
	// }
	// else {
	// 	ce_->pin_cnt += isPreRead ? 0 : 1;
	// 	ce_->isUsed = true;
	// 	lock_acquire(&c_map_lock);
	// 	bitmap_set(c_map, (ce->ch_addr -c_base)/BLOCK_SECTOR_SIZE, false);
	// 	lock_release(&c_map_lock);
	// 	free(ce);
	// }
	if (ce_){
		// ce_->pin_cnt += isPreRead ? 0 : 1;
		if(!isPreRead) ce_->pin_cnt++;
		ce_->isUsed = true;
		lock_acquire(&c_map_lock);
		bitmap_set(c_map, (ce->ch_addr - c_base) / BLOCK_SECTOR_SIZE, false);
		lock_release(&c_map_lock);
		free(ce);
	} else {
		// ce->pin_cnt += isPreRead ? 0 : 1;
		if(!isPreRead) ce->pin_cnt++;
		ce->isUsed = true;
		hash_insert(&buf_ht, &ce->buf_hash_elem);
		hash_insert(&evic_buf_ht, &ce->evic_buf_hash_elem);
	}

	lock_release(&c_lock);
	free(ce_evict);

	// return ce_ == NULL ? ce : ce_;
	if (ce_) return ce_;
	else return ce;
}

/* Read sector at given address from cache into given buffer*/
void read_sec_to_buf (const void *ch_addr, void *buffer, size_t read_bytes)
{
	memcpy(buffer, ch_addr, read_bytes);
}

void cache_to_disk (struct cache_elem *ce) {
	block_write(fs_device, ce->secId, ce->ch_addr);
}

void thread_cache_to_disk (void) {
  while(true) {
	// if (ch_begin) {
	// 	lock_acquire(&c_lock);
	// 	if (ch_teminate) {
	// 		lock_release(&c_lock);
	// 		break;
	// 	}

	// 	lock_release(&c_lock);
	// 	all_cache_to_disk(/* Exiting */ false);
	// 	thread_sleep(SLEEP_AFTER);
	// }
	// else {
	// 	thread_sleep(SLEEP_BEFORE);
	// }
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

/* Choose entry to evict */
struct cache_elem *pick_ce (void) {
	
	struct cache_elem *ce;
	struct cache_elem *ce_fst_clrd = NULL;
	struct cache_elem *ce_fst_clrd_dirty = NULL;
	
	while (ce_fst_clrd == NULL && ce_fst_clrd_dirty == NULL) {
		void *start = buf_clock_curr == buf_clock_min ? buf_clock_max : buf_clock_curr - BLOCK_SECTOR_SIZE;
		while (buf_clock_curr != start) {
			// if (buf_clock_curr >= buf_clock_max) {
			// 	buf_clock_curr = buf_clock_min;
			// }
			buf_clock_curr = buf_clock_curr >= buf_clock_max ? buf_clock_min : buf_clock_curr;
			ce = find_evic_cache_elem(buf_clock_curr);
			// if (ce == NULL) {
			// 	buf_clock_curr += BLOCK_SECTOR_SIZE;
			// 	continue;
			// }
			// if (ce->isUsed) {
			// 	ce->isUsed = false;
			// 	if (ce->pin_cnt == 0) {
			// 		if (!ce->isDirty && ce_fst_clrd == NULL) {
			// 			ce_fst_clrd = ce;
			// 		}
			// 		else if (ce->isDirty && ce_fst_clrd_dirty == NULL) {
			// 			ce_fst_clrd_dirty = ce;
			// 		}

			// 	}
			// 	buf_clock_curr += BLOCK_SECTOR_SIZE;
			// 	continue;
			// }
			// else {
			// 	if (ce->pin_cnt != 0) {
			// 		buf_clock_curr += BLOCK_SECTOR_SIZE;
			// 		continue;
			// 	}
			// 	if (ce->isDirty) {
			// 		/* Write from cache to filesystem */
			// 		cache_to_disk(ce);
			// 		ce->isDirty = false;
			// 	}
			// 	hash_delete (&buf_ht, &ce->buf_hash_elem);
			// 	hash_delete (&evic_buf_ht, &ce->evic_buf_hash_elem);
			// 	return ce;
			// }

			if (ce) {
				if (ce->isUsed) {
					if (ce->pin_cnt == 0) {
						// if (!ce->isDirty && ce_fst_clrd == NULL) {
						// 	ce_fst_clrd = ce;
						// }
						// else if (ce->isDirty && ce_fst_clrd_dirty == NULL) {
						// 	ce_fst_clrd_dirty = ce;
						// }
						if (ce->isDirty && !ce_fst_clrd_dirty) {
							ce_fst_clrd_dirty = ce;
						} else if (!ce->isDirty && !ce_fst_clrd) {
							ce_fst_clrd = ce;
						}
					}
					buf_clock_curr += BLOCK_SECTOR_SIZE;
					ce->isUsed = false;
					continue;
				} else {
					// if (ce->pin_cnt != 0) {
					// 	buf_clock_curr += BLOCK_SECTOR_SIZE;
					// 	continue;
					// }
					// if (ce->isDirty) {
					// 	/* Write from cache to filesystem */
					// 	cache_to_disk(ce);
					// 	ce->isDirty = false;
					// }
					// hash_delete (&buf_ht, &ce->buf_hash_elem);
					// hash_delete (&evic_buf_ht, &ce->evic_buf_hash_elem);
					// return ce;
					if (ce->pin_cnt == 0) {
						if (ce->isDirty) {
							/* Write from cache to filesystem */
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
		// if (ce_fst_clrd != NULL || ce_fst_clrd_dirty != NULL) continue;
		if (ce_fst_clrd || ce_fst_clrd_dirty ) continue;
		cond_wait(&cond_pin, &c_lock);
	}
	struct cache_elem *ce_chosen = ce_fst_clrd != NULL ? ce_fst_clrd : ce_fst_clrd_dirty;
	if (ce_chosen == ce_fst_clrd_dirty) {
		/* Write from cache to filesystem */
		cache_to_disk(ce_chosen);
		ce_chosen->isDirty = false;
	}
	hash_delete (&buf_ht, &ce_chosen->buf_hash_elem);
	hash_delete (&evic_buf_ht, &ce_chosen->evic_buf_hash_elem);
	return ce_chosen;
}

/* Returns a hash value for sector p. */
unsigned
cache_hash_fun (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct cache_elem *p = hash_entry (p_, struct cache_elem, buf_hash_elem);
  return p->secId;
}

/* Returns true if sector a precedes sector b. */
bool
cache_elem_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct cache_elem *a = hash_entry (a_, struct cache_elem, buf_hash_elem);
  const struct cache_elem *b = hash_entry (b_, struct cache_elem, buf_hash_elem);
  return a->secId < b->secId;
}

/* Returns a hash value cache entry ce indexed by cache address. */
unsigned
evic_cache_hash_fun (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct cache_elem *ce = hash_entry (p_, struct cache_elem, evic_buf_hash_elem);
  return (unsigned)ce->ch_addr;
}

/* Returns true if sector a precedes sector b. */
bool
evic_cache_elem_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct cache_elem *a = hash_entry (a_, struct cache_elem, evic_buf_hash_elem);
  const struct cache_elem *b = hash_entry (b_, struct cache_elem, evic_buf_hash_elem);
  return (unsigned)a->ch_addr < (unsigned)b->ch_addr;
}

/* Returns cache enry for the given sector, or NULL if sector
   is not in cache */
struct cache_elem *find_cache_elem (block_sector_t sector)
{
  struct cache_elem ce;
  struct hash_elem *e;

  ce.secId = sector;
  e = hash_find (&buf_ht, &ce.buf_hash_elem);
  return e != NULL ? hash_entry (e, struct cache_elem, buf_hash_elem) : NULL;
}

/* Returns cache enry for the given sector, or NULL if sector
   is not in cache */
struct cache_elem *find_evic_cache_elem (void* ch_addr)
{
  struct cache_elem ce;
  struct hash_elem *e;

  ce.ch_addr = ch_addr;
  e = hash_find (&evic_buf_ht, &ce.evic_buf_hash_elem);
  return e != NULL ? hash_entry (e, struct cache_elem, evic_buf_hash_elem) : NULL;
}

/* Returns a hash value for sector p. */
void
cache_destructor (struct hash_elem *ce_, void *aux UNUSED)
{
  struct cache_elem *ce = hash_entry (ce_, struct cache_elem, buf_hash_elem);
  free(ce);
}

/* Loads inode cache entry and keeps it pinned*/
void *get_meta_inode (block_sector_t sec_id) {
	/* Lookup and pin cache entry - c_lock */
	 lock_acquire(&c_lock);
	 struct cache_elem *ce = find_cache_elem (sec_id);
	 if (ce != NULL) {
		 ce->pin_cnt++;
	 }
	 lock_release(&c_lock);

	 /* Entry not found, create new */
	 if (ce == NULL) {
		 ce = load_sec_to_cache (sec_id, /* is readahead */ false);
	 }
	 

	 return ce->ch_addr;
}


/* Unpins inode cache entry */
void free_meta_inode (block_sector_t sec_id, bool dirty) {
	 lock_acquire(&c_lock);
	 struct cache_elem *ce = find_cache_elem (sec_id);
	 /* As it was pinned, should be always retrievable */
	 ASSERT(ce != NULL);
	 ce->isUsed = true;
	 ce->isDirty = ce->isDirty ? true : dirty;
	 /* Signal to choosing for evict threads */
	 if (--ce->pin_cnt == 0)
		cond_signal(&cond_pin, &c_lock);
	 lock_release(&c_lock);
}

void cache_exit (void) {
	lock_acquire(&c_lock);
	ch_teminate = true;
	lock_release(&c_lock);
}