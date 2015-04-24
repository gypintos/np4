#ifndef VM_PAGE_H_
#define VM_PAGE_H_

#include <hash.h>
#include <inttypes.h>
#include <list.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "threads/thread.h"

struct hash ht_exec_to_threads;
struct lock ht_exec_to_threads_lock;		 

struct exe_to_threads {
  // char exe_key[16];
  block_sector_t inumber;       /* Executable file inumber */
  struct hash_elem hash_elem;
  struct list threads;
};

enum page_t {
  SEGMENT,
  STACK,
  MMAP
};

struct page {
  enum page_t type;       
  struct hash_elem elem;
  bool isDirty;        
  bool isSwapped;              
  bool writable;             
  bool isLoaded;              
  void *vaddr;                
  void *kaddr;               
  block_sector_t sec_addr;    
  int fd;                    
  int offset;                
  struct file *file;         
  uint32_t read_bytes;       
  uint32_t zero_bytes;      
};

unsigned hash_func_page (const struct hash_elem *p_, void *aux UNUSED);
bool cmp_page_hash (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux UNUSED);
unsigned hash_fun_exec_name(const struct hash_elem *elem, void *aux UNUSED);
bool cmp_exec_name(const struct hash_elem *a, const struct hash_elem *b,
                   void *aux UNUSED);
bool inc_stack(void * vaddr, bool lock, void *kaddr);
void insert_stack_page (void * vaddr, bool writable, void * faddr);
void insert_segment_page (void * vaddr, bool writable, off_t of,
                       uint32_t read_bytes, uint32_t zero_bytes);
void insert_mmap_page (void * vaddr, off_t ofs, struct file *file,
                    uint32_t read_bytes, uint32_t zero_bytes);
bool load_page_to_frame(struct page *p, bool pin);
void free_mmap_page_to_file (struct page *p);
void write_mmap_page_to_file (struct page *p);
// struct exe_to_threads* find_exe_to_threads_entry (char *exe_key);
struct exe_to_threads* find_exe_to_threads_entry (block_sector_t inumber);
void insert_exe_to_threads_entry (struct thread *t, struct file *file);
void delete_exe_to_threads_entry (struct thread *t);
struct page* find_page (const void *address, struct thread *t);
void remove_page (struct hash_elem *p_, void *aux UNUSED);
void page_to_swap(struct page *p);
void page_from_swap(struct page *p, void *k_addr);
#endif /* vm/page.h */




