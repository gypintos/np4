#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
    bool isdir;                         /* Directory or not */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry));
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode, bool *isdir) 
{
  struct dir_entry de;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);
  
  inode_lock_acquire(dir->inode);

  if (lookup (dir, name, &de, NULL)){
    *inode = inode_open (de.inode_sector);
    *isdir = de.isdir;
  }
  else
    *inode = NULL;
  inode_lock_release(dir->inode);

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */

bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector,bool isdir)
{
  struct dir_entry e;
  off_t ofs;
  bool result = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  inode_lock_acquire(dir->inode);

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */

  memset(&e, 0, sizeof e);
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;


  e.isdir = isdir;
  result = inode_write_at (dir->inode, &e, sizeof e, ofs, true) == sizeof e;
  
 done:
  
  // inode_lock_release(dir_get_inode(dir));
 inode_lock_release(dir->inode);
  return result;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry de;
  struct inode *inode = NULL;
  bool result = false;
  off_t ofs;
  
  struct dir *dir_ = NULL;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);
  
  inode_lock_acquire(dir->inode);

  /* Find directory entry. */
  if (!lookup (dir, name, &de, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (de.inode_sector);
  if (inode == NULL)
    goto done;

  
  if (de.isdir) {
    dir_ = dir_open (inode);
    if (!dir_ || is_dir_removable(dir_))
      goto done;
  }

  /* Erase directory entry. */
  de.in_use = false;
  
  
  if (inode_write_at (dir->inode, &de, sizeof de, ofs, true) != sizeof de)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  result = true;

 done:
  
  inode_lock_release(dir->inode);
  inode_close (inode);
  return result;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry de;

  while (inode_read_at (dir->inode, &de, sizeof de, dir->pos) == sizeof de) 
    {
      dir->pos += sizeof de;
      if (de.in_use)
        {
          strlcpy (name, de.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}


// /* Returns true if the given directory DIR is the root directory
//    otherwise false */
// bool
// dir_is_root (struct dir *dir)
// {
//   ASSERT (dir != NULL);
//   return inode_get_inumber (dir_get_inode (dir)) == ROOT_DIR_SECTOR;
// }

// /* Returns true if the given directory DIR contains no entries other
//    than "." and "..", otherwise false */
// bool
// dir_is_empty (struct dir *dir)
// {
//   struct dir_entry de;
//   size_t ofs;

//   ASSERT (dir != NULL);

//   for (ofs = 0; inode_read_at (dir->inode, &de, sizeof de, ofs) == sizeof de;
//        ofs += sizeof de)
//   if (de.in_use
//       && (strcmp (".", de.name) != 0)
//     && (strcmp ("..", de.name) != 0))
//     return false;

//   return true;
// }

// /* Returns true if the given directory DIR is in use (i.e. opened by
//    a process). otherwise false */
// bool
// dir_in_use (struct dir *dir)
// {
//   ASSERT (dir != NULL);
//   struct inode* inode = dir_get_inode (dir);
//   int open_cnt = inode_get_open_cnt (inode);
//   /* To examine the DIR we have to open it first, therefore open count
//      is at least 1 */
//   ASSERT (open_cnt >= 1);
//   return (open_cnt > 1);
// }

bool is_dir_removable(struct dir* dir){
  bool isEmpty = true;
  bool isRoot = inode_get_inumber(dir->inode) == ROOT_DIR_SECTOR;
  bool inUse = false;

  struct dir_entry de;
  size_t off = 0;
  while (inode_read_at(dir->inode,&de, sizeof de,off) == sizeof de ){
    if (de.in_use && strcmp(".", de.name) != 0 
        && strcmp("..", de.name) != 0){
      isEmpty = false;
      break;
    } 
    off += sizeof de; 
  }

  int cnt = inode_get_open_cnt(dir->inode);
  inUse = cnt > 1;

  return !isEmpty || isRoot || inUse;
}

