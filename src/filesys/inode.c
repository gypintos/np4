#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define N_DIR_BLK 12
#define N_IN_DIR_BLK 1
#define N_DOU_IN_DIR_BLK 1
// #define DIRECT_INDEX 0
// #define INDIRECT_INDEX N_DIR_BLK
#define IN_DIR_END N_DIR_BLK + N_IN_DIR_BLK
#define N_PTR_INODE IN_DIR_END + N_DOU_IN_DIR_BLK
#define N_PTR_IN_DIR_BLK 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                
    unsigned magic;              
    uint32_t dir_ptr;            
    uint32_t indir_ptr;          
    uint32_t d_indir_ptr;        
    block_sector_t ptr[N_PTR_INODE]; 
    uint32_t unused[109]; 
  };

struct indir_blk
{
    block_sector_t ptr[N_PTR_IN_DIR_BLK];  
};

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock in_lock;                  
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;


/** NEW ADDED HERE **/
bool inode_alloc(struct inode_disk *disk_inode, off_t length);
void inode_dealloc (struct inode_disk *disk_inode);
void inode_dealloc_block (block_sector_t *sector, size_t size);
size_t
inode_extend_indirect_block (struct inode_disk *i_d, size_t sectors);
size_t
inode_extend_nested_block (struct inode_disk *i_d, size_t sectors,
                           struct indir_blk *block);
size_t
inode_extend_doubly_indirect_block (struct inode_disk *i_d, size_t sectors);


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}


/** NEW ADDED HERE **/
/* Returns the number of indirect sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_indirect_sectors (off_t size)
{
  // if (size <= BLOCK_SECTOR_SIZE * N_DIR_BLK)
  //     return 0;
  // size -= BLOCK_SECTOR_SIZE * N_DIR_BLK;
  // return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE * N_PTR_IN_DIR_BLK);

  if (size <= BLOCK_SECTOR_SIZE*N_DIR_BLK){
    return 0;
  } else {
    size -= BLOCK_SECTOR_SIZE*N_DIR_BLK;
    return DIV_ROUND_UP(size,BLOCK_SECTOR_SIZE*N_PTR_IN_DIR_BLK);
  }

}

/* Returns the number of doubly indirect sectors to allocate for an
   inode SIZE bytes long. */
static inline size_t
bytes_to_doubly_indirect_sector (off_t size)
{
  // off_t bound = BLOCK_SECTOR_SIZE * (N_DIR_BLK +
  //                                    N_IN_DIR_BLK * N_PTR_IN_DIR_BLK);
  // return size <= bound ? 0 : N_DOU_IN_DIR_BLK;

  if (size <= BLOCK_SECTOR_SIZE*(N_DIR_BLK+N_IN_DIR_BLK * N_PTR_IN_DIR_BLK)){
    return 0;
  } else {
    return N_DOU_IN_DIR_BLK;
  }
}
/** NEW ADDED HERE **/

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */

   /** NEW ADDED HERE **/
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos,  off_t inc_size) 
{
  ASSERT (inode != NULL);
  block_sector_t res;
  struct inode_disk *i_d = (struct inode_disk*)get_meta_inode(inode->sector);

  if (inc_size == 0) inc_size = i_d->length;
  if (pos > inc_size){
    res = -1;
  } else {
    uint32_t indir_blk[N_PTR_IN_DIR_BLK];
    uint32_t index;
    off_t direct_range = BLOCK_SECTOR_SIZE * N_DIR_BLK;
    off_t indirect_range = BLOCK_SECTOR_SIZE*(N_DIR_BLK + N_IN_DIR_BLK * N_PTR_IN_DIR_BLK);
    off_t indirect_size = BLOCK_SECTOR_SIZE * N_PTR_IN_DIR_BLK;

    if (pos < direct_range){
      index = pos/ BLOCK_SECTOR_SIZE;
      res = i_d->ptr[index];
    } else if (pos < indirect_range){
      pos -= direct_range;
      index = pos/indirect_size + N_DIR_BLK;
      get_sec_from_cache(i_d->ptr[index],&indir_blk, 0, BLOCK_SECTOR_SIZE);
      pos %= indirect_size;
      res = indir_blk[pos/BLOCK_SECTOR_SIZE];
    } else {
      get_sec_from_cache(i_d->ptr[IN_DIR_END], &indir_blk,0, 
        BLOCK_SECTOR_SIZE);
      pos -= indirect_range;
      index = pos/indirect_size;
      get_sec_from_cache(indir_blk[index], &indir_blk, 0,BLOCK_SECTOR_SIZE);
      pos %= indirect_size;
      res = indir_blk[pos/BLOCK_SECTOR_SIZE];
    }
  }

  free_meta_inode(inode->sector, false);
  return res;
}

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  // if (disk_inode != NULL)
  //   {
  //     disk_inode->magic = INODE_MAGIC;
  //     if(length == 0 || inode_alloc(disk_inode, length)) {
  //       disk_inode->length = length;
  //       buf_to_cache(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
  //       success = true;
  //     }
  //     free (disk_inode);
  //   }
  // return success;


  if (disk_inode){
    disk_inode->magic = INODE_MAGIC;
    if (length == 0 || inode_alloc(disk_inode, length) == true){
      disk_inode->length = length;
      buf_to_cache(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
      success = true;
    }
    free(disk_inode);
  } 
  return success;


}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->in_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

int
inode_get_open_cnt (const struct inode *inode)
{
  return inode->open_cnt;
}



/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct inode_disk *i_d =(struct inode_disk*) get_meta_inode(inode->sector);
          inode_dealloc(i_d);
          free_meta_inode(inode->sector, true);
          free_map_release (inode->sector, 1);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer, off_t size, off_t offset) 
{
  off_t read_cnt = 0;
  block_sector_t sec_id = 0;
  off_t len = inode_length(inode);

  if(len <= offset)
    return read_cnt;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      sec_id = byte_to_sector (inode, offset, 0);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = len - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      get_sec_from_cache (sec_id, buffer+read_cnt,sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      read_cnt += chunk_size;
    }

  block_sector_t pre_sec_id = byte_to_sector(inode, offset, BLOCK_SECTOR_SIZE);
  if (pre_sec_id < block_size(fs_device)) {
    lock_acquire(pre_read_lock_ptr);
    struct pre_read_elem *pre = malloc (sizeof(struct pre_read_elem));
    pre->sec_id = sec_id;
    list_push_back(&pre_read_que, &pre->elem);
    cond_signal(pre_read_cond_ptr, pre_read_lock_ptr);
    lock_release(pre_read_lock_ptr);
  }
  return read_cnt;


}

off_t
inode_write_at (struct inode *inode, const void *buffer, off_t size,
                off_t offset, bool lock_acquired)
{
  block_sector_t sec_id;
  struct inode_disk *i_d;
  int inc_size = 0;
  off_t write_cnt = 0;
  bool isInc = false;

  if (inode->deny_write_cnt)
    return 0;
  if(offset + size > inode_length(inode)) {
    /* File growth */
    if (lock_acquired == false){
      inode_acquire_lock(inode);
    }
    i_d = (struct inode_disk *) get_meta_inode(inode->sector);
    isInc = inode_alloc(i_d, offset + size);
    inc_size = offset + size;
    if (isInc == false) {
      if (lock_acquired = false){
        inode_release_lock(inode);
      }
      free_meta_inode(inode->sector, true);
      return write_cnt;
    }
  }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      sec_id = byte_to_sector (inode, offset, inc_size);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = isInc ? inc_size : inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      buf_to_cache (sec_id, buffer + write_cnt, sector_ofs,chunk_size);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      write_cnt += chunk_size;
    }

  if (isInc) {
    if (i_d->length < offset+size ) {
      i_d->length = offset + size;
      free_meta_inode(inode->sector, true);  
    }
    if (!lock_acquired){
      inode_release_lock(inode);
    }
  } else {
    block_sector_t pre_sec_id = byte_to_sector(inode, offset,BLOCK_SECTOR_SIZE);
    if (pre_sec_id < block_size(fs_device)) {
      lock_acquire(pre_read_lock_ptr);
      struct pre_read_elem *pre = malloc(sizeof(struct pre_read_elem));
      pre->sec_id = pre_sec_id;
      list_push_back(&pre_read_que, &pre->elem);
      cond_signal(pre_read_cond_ptr, pre_read_lock_ptr);
      lock_release(pre_read_lock_ptr);
    }
  }
  return write_cnt;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  off_t res;
  struct inode_disk *i_d = (struct inode_disk *) get_meta_inode(inode->sector);
  res = i_d->length;
  free_meta_inode(inode->sector, false);
  return res;
}


/* Allocate indirect blocks for inode.
   Return remaining size of sectors that need to allocate */
size_t
inode_extend_indirect_block (struct inode_disk *i_d, size_t sec_cnt)
{
  static char ZBlock[BLOCK_SECTOR_SIZE];
  struct indir_blk b;
  if (i_d->indir_ptr!=0){
    get_sec_from_cache(i_d->ptr[i_d->dir_ptr], &b, 0, BLOCK_SECTOR_SIZE);
  } else if (free_map_allocate(1, &i_d->ptr[i_d->dir_ptr]) == NULL){
    return sec_cnt;
  }
  for (; i_d->indir_ptr < N_PTR_IN_DIR_BLK; ){
    if (free_map_allocate(1, &b.ptr[i_d->indir_ptr])){
      buf_to_cache(b.ptr[i_d->indir_ptr], ZBlock, 0,BLOCK_SECTOR_SIZE);
      i_d->indir_ptr++;
      sec_cnt--;
      if (sec_cnt == 0) break;
    } else {
      return sec_cnt;
    }
  }
  buf_to_cache(i_d->ptr[i_d->dir_ptr], &b, 0, BLOCK_SECTOR_SIZE);
  if (i_d->indir_ptr == N_PTR_IN_DIR_BLK){
    i_d->dir_ptr++;
    i_d->indir_ptr = 0;
  }
  return sec_cnt;
}

size_t
inode_extend_nested_block (struct inode_disk *i_d, size_t sec_cnt,
                           struct indir_blk *b)
{
  static char ZBlock[BLOCK_SECTOR_SIZE];
  struct indir_blk nb;

  if (i_d->d_indir_ptr!=0){
    get_sec_from_cache(b->ptr[i_d->indir_ptr], &nb, 0, BLOCK_SECTOR_SIZE);
  } else if (free_map_allocate(1, &b->ptr[i_d->indir_ptr]) == NULL){
    return sec_cnt;
  }

  for (; i_d->d_indir_ptr < N_PTR_IN_DIR_BLK; ){
    if (free_map_allocate(1, &nb.ptr[i_d->d_indir_ptr])){
      buf_to_cache(nb.ptr[i_d->d_indir_ptr],ZBlock, 0, BLOCK_SECTOR_SIZE);
      i_d->d_indir_ptr++;
      sec_cnt--;
      if (sec_cnt == 0) break;
    } else {
      return sec_cnt;
    }
  }

  buf_to_cache(b->ptr[i_d->indir_ptr], &nb, 0,BLOCK_SECTOR_SIZE);
  if (i_d->d_indir_ptr == N_PTR_IN_DIR_BLK){
    i_d->indir_ptr++;
    i_d->d_indir_ptr = 0;
  }
  return sec_cnt;
}

size_t
inode_extend_doubly_indirect_block (struct inode_disk *i_d, size_t sec_cnt)
{
  struct indir_blk b;
  if (i_d->indir_ptr != 0 || i_d->d_indir_ptr != 0){
    get_sec_from_cache(i_d->ptr[i_d->dir_ptr], &b, 0,BLOCK_SECTOR_SIZE);
  } else {
    free_map_allocate(1, &i_d->ptr[i_d->dir_ptr]);
  }
  for (;i_d->indir_ptr < N_PTR_IN_DIR_BLK;){
    sec_cnt = inode_extend_nested_block(i_d, sec_cnt, &b);
    if (sec_cnt == 0) break;
  }

  buf_to_cache(i_d->ptr[i_d->dir_ptr], &b, 0,BLOCK_SECTOR_SIZE);
  return sec_cnt;
}

/* Allocate inode_disk with size as LENGTH*/
bool
inode_alloc(struct inode_disk *i_d, off_t length)
{
  static char ZBlock[BLOCK_SECTOR_SIZE];

  size_t size = bytes_to_sectors(length) - bytes_to_sectors(i_d->length);

  if(size == 0)
    return true;

  for (; i_d->dir_ptr < N_DIR_BLK;){
    if (!free_map_allocate(1, &i_d->ptr[i_d->dir_ptr])) 
      return false;
    buf_to_cache(i_d->ptr[i_d->dir_ptr], ZBlock, 0, BLOCK_SECTOR_SIZE);
    i_d->dir_ptr++;
    size--;
    if (size == 0) return true;
  }


  for(;i_d->dir_ptr < IN_DIR_END;){
    size = inode_extend_indirect_block(i_d, size);
    if (size == 0) return true;
  }

  if (i_d->dir_ptr == IN_DIR_END) {
    size = inode_extend_doubly_indirect_block(i_d, size);
  } 

  return size == 0;
}

/* Deallocate all sectors in an indirect block*/
void
inode_dealloc_block (block_sector_t *sector, size_t size)
{
  struct indir_blk b;
  get_sec_from_cache(*sector, &b, 0, BLOCK_SECTOR_SIZE);
  int i = 0; 
  for (; i<size; i++){
    free_map_release(b.ptr[i], 1);
  }
  free_map_release(*sector, 1);

}

/* Deallocate inode */
void
inode_dealloc (struct inode_disk *i_d)
{
  if (i_d->length == 0)
    return;
  unsigned int idx = 0;
  size_t sec_cnt = bytes_to_sectors(i_d->length);
  size_t i_sec_cnt = bytes_to_indirect_sectors(i_d->length);
  size_t d_sec_cnt = bytes_to_doubly_indirect_sector(i_d->length);

  for (; sec_cnt > 0 && idx < N_DIR_BLK; idx++){
    free_map_release(i_d->ptr[idx], 1);
    sec_cnt--;
  }

  for (;i_sec_cnt >0 && idx < IN_DIR_END; idx++){
    size_t in_size = 0;
    if (sec_cnt < N_PTR_IN_DIR_BLK){
      in_size = sec_cnt;
    } else {
      in_size = N_PTR_IN_DIR_BLK;
    }
    inode_dealloc_block(&i_d->ptr[idx], in_size);
    sec_cnt -= in_size;
    i_sec_cnt--;
  }

  if (d_sec_cnt > 0){
    struct indir_blk b;
    get_sec_from_cache(i_d->ptr[idx], &b, 0, BLOCK_SECTOR_SIZE);
    int i =0;
    for (; i<i_sec_cnt; i++){
      size_t in_size = 0;
      if (sec_cnt < N_PTR_IN_DIR_BLK){
        in_size = sec_cnt;
      } else {
        in_size = N_PTR_IN_DIR_BLK;
      }
      inode_dealloc_block(&b.ptr[i], in_size);
      sec_cnt -= in_size;
    }
    free_map_release(i_d->ptr[idx],1);
  }
}

/* Acquire lock in inode */
void
inode_acquire_lock (struct inode *inode)
{
  lock_acquire (&inode->in_lock);
}

/* Release lock in inode */
void
inode_release_lock (struct inode *inode)
{
  lock_release (&inode->in_lock);
}
