#include "hash.h"
#include "devices/block.h"

bool ch_teminate;
bool ch_begin;

struct cache_elem {
	block_sector_t secId;
	void *ch_addr;	
	bool isDirty;					
	bool isUsed;				
	unsigned pin_cnt;			
	struct hash_elem buf_hash_elem;	
	struct hash_elem evic_buf_hash_elem;	
};

struct list pre_read_que;
 
struct pre_read_elem {
	block_sector_t sec_id;		
	struct list_elem elem;
};	

struct condition *pre_read_cond_ptr;

struct lock *pre_read_lock_ptr;

void cache_buf_init(void);
void all_cache_to_disk(bool exiting);
void read_from_cache (block_sector_t sector_idx, void *buffer,
				  int sector_ofs, int chunk_size);
void
buf_to_cache (block_sector_t sector_idx, const void *buffer, int sector_ofs,
				 int chunk_size);
void thread_cache_to_disk (void);

void *get_meta_inode (block_sector_t sector_idx);
void free_meta_inode (block_sector_t sector_idx, bool dirty);
void cache_exit (void);