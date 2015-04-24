#include "hash.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "page.h"


struct frame {
  struct hash_elem elem;
  void* k_addr;         
  bool isPinned;          
  bool locked;          
  struct hash ht_thread_uaddr; 
  struct hash_iterator iter_htu;   
  struct hash_iterator iter_bit_htu; 
};

struct thread_uaddr {
  struct hash_elem elem;
  struct thread *t; 
  void *uaddr;
};

void *clock_point_init;     
void *clock_point_max;      
void *clock_point;      

struct hash frames_table;       
struct lock frame_table_lock;     
struct condition frame_table_cond; 
  
void fmt_init (void);
struct frame *select_fm(void);
void *fm_allocate (enum palloc_flags flags, bool lock);
void release_fm (struct page *p, bool freepdir);
void release_unused_fm (void *addr);
struct frame *find_fm (void *address);
bool if_fm_accessed (struct frame *f);
bool if_fm_dirty (struct frame *f);
void thread_fm_mapping (void *kaddr, void *uaddr);

unsigned get_frame_hash (const struct hash_elem *e, void *aux UNUSED);
bool cmp_frame_hash (const struct hash_elem *a,const struct hash_elem *b,
                     void *aux UNUSED);
void set_page_unaccessed (struct hash_elem *e, void *aux UNUSED);
unsigned get_thread_uaddr_hash (const struct hash_elem *e, void *aux UNUSED);
void remove_thread_uaddr (struct hash_elem *e, void *aux UNUSED);
bool cmp_thread_uaddr_hash (const struct hash_elem *a, const struct hash_elem *b,
                            void *aux UNUSED);
struct thread_uaddr *find_thread_uaddr (struct frame *f, struct thread *t);
typedef bool bool_fun (uint32_t *pd, const void *upage);
bool apply_or_to_fmt (struct frame *fm, bool_fun pdir_func);

