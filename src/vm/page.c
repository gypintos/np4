#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "filesys/inode.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
 
bool get_page_from_file (uint8_t *kaddr, struct file *file, 
            off_t off, uint32_t pr_bytes, uint32_t pz_bytes);
bool install_shared_page (struct page *p, bool lock);
unsigned hash_fun_exec_name(const struct hash_elem *elem, void *aux UNUSED);
bool cmp_exec_name(const struct hash_elem *a, const struct hash_elem *b,
                   void *aux UNUSED);

struct page* find_page (const void *addr, struct thread *t)
{
  struct hash_elem *elem;
  struct page p;
  p.vaddr = pg_round_down (addr);
  elem = hash_find (&t->page_table, &p.elem);
  if (elem != NULL){
    return hash_entry(elem, struct page, elem);
  } else {
    return NULL;
  }
}

void insert_stack_page (void * vaddr, bool writable, void * kaddr)
{
  struct page *p = (struct page*) malloc (sizeof(struct page));
  p->writable = writable;
  p->isLoaded = true;
  p->isSwapped = false;
  p->type = STACK;
  p->vaddr = vaddr;
  p->kaddr = kaddr;
  p->fd = -1;
  hash_insert(&thread_current()->page_table, &p->elem);
}

void insert_segment_page (void * vaddr, bool writable, off_t ofs,
                          uint32_t read_bytes, uint32_t zero_bytes)
{
  struct page *p = (struct page*) malloc (sizeof(struct page));
  p->writable = writable;
  p->isLoaded = false;
  p->isSwapped = false;
  p->vaddr = vaddr;
  p->type = SEGMENT;
  p->offset = ofs;
  p->read_bytes = read_bytes;
  p->zero_bytes = zero_bytes;
  hash_insert(&thread_current()->page_table,&p->elem);
}

void
insert_mmap_page (void * vaddr, off_t ofs, struct file *file,
                  uint32_t read_bytes, uint32_t zero_bytes) {
  struct page *p = (struct page*) malloc (sizeof(struct page));
  p->writable = true;
  p->isLoaded = false;
  p->vaddr = vaddr;
  p->type = MMAP;
  p->offset = ofs;
  p->file = file;
  p->zero_bytes = zero_bytes;
  p->read_bytes =read_bytes;
  hash_insert(&thread_current()->page_table, &p->elem);
}

bool load_page_to_frame(struct page *p, bool lock)
{
  if (!p->writable){
    if (install_shared_page(p,lock))
      return true;
  }

  void *kaddr = fm_allocate(PAL_ZERO, lock);
  if (kaddr == NULL) 
    return false;

  switch (p->type){
    case STACK:
    {
      return inc_stack(p->vaddr, false, kaddr);
    }
    case SEGMENT:
    {
      if (p->isSwapped){
        page_from_swap(p, kaddr);
      } else {
        bool load_from_file_result = get_page_from_file(kaddr, 
        thread_current()->exe, p->offset, p->read_bytes, p->zero_bytes);
        if (load_from_file_result == false) return false;
      }
      break;
    }
    case MMAP:
    {
      if (get_page_from_file(kaddr, p->file, p->offset, 
          p->read_bytes, p->zero_bytes) == false){
        return false;
      }
      break; 
    }
  }
  if (install_page(p->vaddr, kaddr, p->writable) == false){
    release_unused_fm(kaddr);
    return false;
  } else {
    p->isLoaded = true;
    p->kaddr = kaddr;
    return true;
  }
}

bool inc_stack(void * vaddr, bool lock, void *kaddr)
{
  
  if (!kaddr){
    kaddr = fm_allocate(PAL_ZERO, lock);
    if (kaddr == NULL) return false;
  } 
  void* paddr = pg_round_down(vaddr);
  struct page* p  = find_page(paddr, thread_current());
  if (!p || !p->isSwapped){
    insert_stack_page(paddr, true, kaddr);
    p = find_page(paddr, thread_current() );
  } else {
    page_from_swap(p, kaddr);
  }

  if(install_page(p->vaddr, kaddr, p->writable)){
    p->isLoaded = true;
    return true;
  } else {
    release_unused_fm(kaddr);
    hash_delete(&thread_current()->page_table, &p->elem);
    free(p);
    return false;
  }
}

bool get_page_from_file (uint8_t *kaddr, struct file *file, 
        off_t off, uint32_t pr_bytes, uint32_t pz_bytes)
{
  ASSERT((pz_bytes + pr_bytes) % PGSIZE == 0);
  // lock_acquire(&filesys_lock);
  file_seek(file, off);
  int fr_bytes = file_read(file, kaddr, pr_bytes);
  // lock_release(&filesys_lock);

  if (fr_bytes == pr_bytes){
    memset(kaddr + pr_bytes, 0, pz_bytes);
    return true;
  } else {
    release_unused_fm(kaddr);
    return false;
  }

}

void free_mmap_page_to_file (struct page *p) {
  if (p->isLoaded){
    struct frame *fm = find_fm(p->kaddr);
    ASSERT(fm);
    if (if_fm_dirty(fm)){
      lock_acquire(&frame_table_lock);
      fm->isPinned = true;
      lock_release(&frame_table_lock);

      // lock_acquire(&filesys_lock);
      uint32_t fw_bytes = file_write_at(p->file, p->kaddr, p->read_bytes, p->offset);
      ASSERT(fw_bytes == p->read_bytes);
      // lock_release(&filesys_lock);

      lock_acquire(&frame_table_lock);
      fm->isPinned = false;
      release_fm(p, true);
      lock_release(&frame_table_lock);
    } else {
      lock_acquire(&frame_table_lock);
      release_fm(p,true);
      lock_release(&frame_table_lock);
    }
  }
}

void write_mmap_page_to_file (struct page *p) {
  struct frame* fm = find_fm(p->kaddr);
  ASSERT(fm);
  if (if_fm_dirty(fm)){
    // lock_acquire(&filesys_lock);
    uint32_t fw_bytes = file_write_at(p->file, p->kaddr, p->read_bytes, p->offset);
    // lock_release(&filesys_lock);
  } 
}


void remove_page (struct hash_elem *h_elem, void *aux UNUSED)
{
  lock_acquire(&frame_table_lock);
  struct page* p = hash_entry(h_elem, struct page, elem);
  if (p->type == SEGMENT || p->type == STACK){
    if (p->isSwapped){
      release_sector(p->sec_addr);
    } else {
      release_fm(p, false);
    }
  } 
  free(p); 
  lock_release(&frame_table_lock);

}

void page_to_swap(struct page *p){
  p->sec_addr = swap_set(p->kaddr);
  p->isLoaded = false;
  p->isSwapped = true;
}

void page_from_swap(struct page *p, void *k_addr){
  swap_get(p->sec_addr, k_addr);
  p->kaddr = k_addr;
  p->isSwapped = false;
}

unsigned
hash_func_page (const struct hash_elem *e, void *aux UNUSED)
{
  const struct page *p = hash_entry (e, struct page, elem);
  return (unsigned)p->vaddr;
}

bool
cmp_page_hash (const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED)
{
  const struct page *a = hash_entry(a_, struct page, elem);
  const struct page *b = hash_entry(b_, struct page, elem);
  return a->vaddr < b->vaddr;
}

unsigned hash_fun_exec_name(const struct hash_elem *elem, void *aux UNUSED){
  struct exe_to_threads *e = hash_entry(elem, struct exe_to_threads, hash_elem);
  // return hash_string(e->exe_key); 
  /** NEW ADDED HERE **/
  return (unsigned) e->inumber; 
}

bool cmp_exec_name(const struct hash_elem *a, const struct hash_elem *b,
                  void *aux UNUSED){
  struct exe_to_threads *l = hash_entry(a, struct exe_to_threads, hash_elem);
  struct exe_to_threads *r = hash_entry(b, struct exe_to_threads, hash_elem);
  // return hash_string(l->exe_key) < hash_string(r->exe_key);
  /** NEW ADDED HERE **/
  return l->inumber <  r->inumber;

}

/* DELETE
struct exe_to_threads* find_exe_to_threads_entry (char *exe_key)
{
  struct exe_to_threads* etp = malloc(sizeof(struct exe_to_threads));
  strlcpy(etp->exe_key, exe_key, sizeof(etp->exe_key));
  struct hash_elem* elem = hash_find(&ht_exec_to_threads, &etp->hash_elem);
  if (elem != NULL){
    return hash_entry(elem, struct exe_to_threads, hash_elem);
  } else {
    return NULL;
  }

} */

/** NEW ADDED HERE **/
struct exe_to_threads* find_exe_to_threads_entry (block_sector_t inumber)
{
  struct exe_to_threads* etp = malloc(sizeof(struct exe_to_threads));
  etp->inumber = inumber;
  struct hash_elem* elem = hash_find(&ht_exec_to_threads, &etp->hash_elem);
  if (elem != NULL){
    return hash_entry(elem, struct exe_to_threads, hash_elem);
  } else {
    return NULL;
  }

}

/** NEW ADDED HERE **/
void
insert_exe_to_threads_entry(struct thread *t, struct file *file)
{
  block_sector_t inumber = inode_get_inumber (file_get_inode (file));
  struct exe_to_threads* etp = find_exe_to_threads_entry(inumber);
  if(!etp){
    struct exe_to_threads* new_etp = malloc(sizeof(struct exe_to_threads));
    new_etp->inumber = inumber;
    list_init(&new_etp->threads);
    // strlcpy(new_etp->exe_key, t->name, sizeof(new_etp->exe_key));
    list_push_back(&new_etp->threads, &t->exec_elem);
    hash_insert(&ht_exec_to_threads, &new_etp->hash_elem);
  } else {
    list_push_back(&etp->threads, &t->exec_elem);
  }
}

void delete_exe_to_threads_entry (struct thread *t)
{  

  /** NEW ADDED HERE **/
  struct list_elem *e;
  ASSERT (t->exe != NULL);
  block_sector_t inumber = inode_get_inumber (file_get_inode (t->exe));
  /** NEW ADDED HERE **/
  struct exe_to_threads* etp = find_exe_to_threads_entry(inumber);

  if (etp != NULL){
    struct list_elem* e = list_begin(&etp->threads);
    while(e != list_end(&etp->threads)){
      struct thread* t_ = list_entry(e, struct thread, exec_elem);
      if (t == t_){
        list_remove(&t_->exec_elem);
        break;
      }
      e = list_next(e);
    }
    if (list_size(&etp->threads) == 0){
      hash_delete(&ht_exec_to_threads, &etp->hash_elem);
      free(etp);
    }
  }
}

bool install_shared_page (struct page *p, bool lock) {
  lock_acquire(&ht_exec_to_threads_lock);

  /** NEW ADDED HERE **/
  struct thread *t = thread_current();
  ASSERT (t->exe != NULL);
  block_sector_t inumber = inode_get_inumber (file_get_inode (t->exe));

  struct exe_to_threads *etp = find_exe_to_threads_entry(inumber);
  if (etp != NULL){
    struct list_elem *e;
    for (e = list_begin(&etp->threads); e != list_end(&etp->threads); e = list_next(e)){
      struct thread* t = list_entry(e, struct thread, exec_elem);
      if (thread_current() == t) continue;
      lock_acquire(&frame_table_lock);
      struct page* p_other = find_page(p->vaddr, t);
      if(p_other->isLoaded){
        struct frame* fm = find_fm(p_other->kaddr);
        p->kaddr = fm->k_addr;
        fm->isPinned = true;
        lock_release(&frame_table_lock);
        lock_release(&ht_exec_to_threads_lock);
        if (!install_page(p->vaddr, fm->k_addr, p->writable)){
          release_unused_fm(fm->k_addr);
          return false;
        } else {
          fm->locked = lock;
          p->isLoaded = true;
          return true;
        }
      }
      lock_release(&frame_table_lock);
    }
  }
  lock_release(&ht_exec_to_threads_lock);
  return false;
}

