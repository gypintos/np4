#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "frame.h"


struct hash_iterator fmt_iter;  

void fmt_init (void) {
  hash_init(&frames_table, get_frame_hash, cmp_frame_hash, NULL);
  lock_init(&frame_table_lock);
  cond_init(&frame_table_cond);
  lock_init(&ht_exec_to_threads_lock);
}

struct frame *select_fm (void) {
  void *end = clock_point_max;
  if (clock_point != clock_point_init)
    end = clock_point - PGSIZE;

  struct frame *fm;
  for (;clock_point != end; clock_point += PGSIZE){
    if (clock_point >= clock_point_max) clock_point = clock_point_init;
    fm = find_fm(clock_point);
    if (!fm){
      continue;
    } else if (fm->locked || fm->isPinned){
      if (if_fm_accessed(fm)){
        hash_apply(&fm->ht_thread_uaddr, set_page_unaccessed);
      }
      continue;
    } else {
      if (if_fm_accessed(fm)){
        hash_apply(&fm->ht_thread_uaddr, set_page_unaccessed);
      } else {
        return fm;
      }
    }
  }

  fm = NULL;
  while(!fm){
    hash_first(&fmt_iter, &frames_table);
    while(hash_next(&fmt_iter)){
      fm = hash_entry(hash_cur(&fmt_iter), struct frame, elem);
      if (!fm->locked && !fm->isPinned){
        return fm;
      }
    }
    cond_wait(&frame_table_cond, &frame_table_lock);  
  }
}

void *fm_allocate (enum palloc_flags flags, bool lock) {
  lock_acquire(&frame_table_lock);
  void *kaddr = palloc_get_page(PAL_USER | flags);
  struct frame *fm;
  if (kaddr == NULL){
    fm = select_fm();
    fm->isPinned = true;
    fm->locked = lock;
    kaddr = fm->k_addr;
    struct hash *ht_thread_uaddr = &fm->ht_thread_uaddr;
    hash_first(&fm->iter_htu, ht_thread_uaddr);
    struct thread_uaddr *thread_uaddr;
    while (hash_next(&fm->iter_htu)){
      thread_uaddr = hash_entry(hash_cur(&fm->iter_htu), struct thread_uaddr, elem);
      struct page* p = find_page(thread_uaddr->uaddr, thread_uaddr->t);
      p->isLoaded = false;
      pagedir_clear_page(thread_uaddr->t->pagedir, p->vaddr);
      if (p->type == STACK){
        page_to_swap(p);
      } else if (p->type == SEGMENT){
        if (p->writable && (if_fm_dirty(fm) || p->isDirty)){
          p->isDirty = true;
          page_to_swap(p);
        }
      } else {
        write_mmap_page_to_file(p);
      }
    }
    hash_clear(&fm->ht_thread_uaddr, remove_thread_uaddr);
  } else {
    fm = malloc(sizeof(struct frame));
    fm->locked = lock;
    fm->k_addr = kaddr;
    fm->isPinned = true;
    hash_init(&fm->ht_thread_uaddr, get_thread_uaddr_hash, cmp_thread_uaddr_hash, NULL);
    hash_insert(&frames_table, &fm->elem);
  }

  lock_release(&frame_table_lock);
  return kaddr;
}

void release_fm (struct page *p, bool freepdir) {
  p->isLoaded = false;
  struct frame *fm = find_fm(p->kaddr);
  struct thread_uaddr *thread_to_uaddr;
  struct thread *curr = thread_current();
  if(fm){
    thread_to_uaddr = find_thread_uaddr(fm, curr);
    if(thread_to_uaddr){
      hash_delete(&fm->ht_thread_uaddr, &thread_to_uaddr->elem);

      if(fm->isPinned == NULL && hash_empty(&fm->ht_thread_uaddr)){
        if(freepdir){
          pagedir_clear_page(curr->pagedir, thread_to_uaddr->uaddr);
          palloc_free_page(p->kaddr);
        }
        hash_delete(&frames_table, &fm->elem);
        hash_destroy(&fm->ht_thread_uaddr, remove_thread_uaddr);
        free(fm);
      }else{
        pagedir_clear_page(curr->pagedir, thread_to_uaddr->uaddr);
        free(thread_to_uaddr);
      }
      
    }
  }   
}

void release_unused_fm (void *addr) {
  lock_acquire(&frame_table_lock);
  struct frame *fm = find_fm(addr);
  fm->isPinned = false;
  if(hash_empty(&fm->ht_thread_uaddr)){
    palloc_free_page(addr);
    hash_delete(&frames_table, &fm->elem);
    free(fm);
  }
  lock_release(&frame_table_lock);
}

struct frame *find_fm (void *address)
{
  struct frame fm;
  fm.k_addr = address;
  struct hash_elem *ele = hash_find(&frames_table, &fm.elem); 
  if(ele){
    return hash_entry(ele, struct frame, elem);
  }else{
    return NULL;
  }
}

bool if_fm_dirty (struct frame *f) {
    return apply_or_to_fmt (f, &pagedir_is_dirty);
}

bool if_fm_accessed (struct frame *f) {
    return apply_or_to_fmt (f, &pagedir_is_accessed);
}

void thread_fm_mapping (void *kaddr, void *uaddr) { 
  lock_acquire(&frame_table_lock);
  struct thread_uaddr *thread_uaddr = malloc(sizeof(struct thread_uaddr));
  thread_uaddr->t = thread_current();
  thread_uaddr->uaddr = uaddr;
  struct frame *fm = find_fm(kaddr);
  hash_insert(&fm->ht_thread_uaddr, &thread_uaddr->elem);
  fm->isPinned = false;
  cond_signal(&frame_table_cond, &frame_table_lock);
  lock_release(&frame_table_lock);
}

unsigned get_frame_hash (const struct hash_elem *e, void *aux UNUSED) {
    struct frame *fm = hash_entry(e, struct frame, elem);
    return (uintptr_t)fm->k_addr;
}

bool
cmp_frame_hash (const struct hash_elem *first, const struct hash_elem *second, void *aux UNUSED)
{
    struct frame *fm_first = hash_entry (first, struct frame, elem);
    struct frame *fm_second = hash_entry (second, struct frame, elem);
    return (uintptr_t)fm_first->k_addr < (uintptr_t)fm_second->k_addr;
}

struct thread_uaddr *find_thread_uaddr (struct frame *f, struct thread *t)
{
  struct thread_uaddr thread_to_uaddr;
  thread_to_uaddr.t = t;
  struct hash_elem *ele = hash_find(&f->ht_thread_uaddr, &thread_to_uaddr.elem);
  if(ele){
    return hash_entry(ele, struct thread_uaddr, elem);
  }else{
    return NULL;
  }
}

unsigned get_thread_uaddr_hash (const struct hash_elem *e, void *aux UNUSED) {
  struct thread_uaddr *thread_to_uaddr = hash_entry(e, struct thread_uaddr, elem);
  return hash_bytes(thread_to_uaddr->t, sizeof thread_to_uaddr->t);
}

bool cmp_thread_uaddr_hash (const struct hash_elem *first, const struct hash_elem *second, void *aux UNUSED) {
  struct thread_uaddr *u_first = hash_entry (first, struct thread_uaddr, elem);
  struct thread_uaddr *u_second = hash_entry (second, struct thread_uaddr, elem);
  return u_first->t < u_second->t;
}

void remove_thread_uaddr (struct hash_elem *e, void *aux UNUSED) {
  struct thread_uaddr *thread_to_uaddr = hash_entry (e, struct thread_uaddr, elem);
  free(thread_to_uaddr);
}

void set_page_unaccessed (struct hash_elem *e, void *aux UNUSED) {
  struct thread_uaddr *thread_to_uaddr = hash_entry (e, struct thread_uaddr, elem);
  pagedir_set_accessed(thread_to_uaddr->t->pagedir, thread_to_uaddr->uaddr, false); 
}

bool apply_or_to_fmt (struct frame *fm, bool_fun b_fun) {
  hash_first(&fm->iter_bit_htu, &fm->ht_thread_uaddr);
  while(hash_next(&fm->iter_bit_htu)){
    struct thread_uaddr *thread_to_uaddr = hash_entry(hash_cur(&fm->iter_bit_htu), struct thread_uaddr, elem);
    if(b_fun(thread_to_uaddr->t->pagedir, thread_to_uaddr->uaddr)) return true;
  }
  return false;

}
