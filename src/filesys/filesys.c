#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/cache.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
static struct dir* filesys_get_dir (const char* path);
static char* filesys_get_name (const char* path);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  /** NEW ADDED HERE **/
  all_cache_to_disk (true);
}

/* Creates a file named NAME with the given INITIAL_SIZE.*/
bool
filesys_create (const char *name, off_t initial_size, bool isdir) 
{
  if (strlen(name) == 0) return false;
  block_sector_t inode_sector = 0;

  struct dir *dir_ = filesys_get_dir(name);
  char *name_ = filesys_get_name(name);
  bool success = false;

  if (strcmp (name_, "") == 0) goto done;
  success = (dir_ && free_map_allocate (1, &inode_sector)
    && inode_create (inode_sector, initial_size) 
    && dir_add (dir_, name_, inode_sector, isdir));

  struct inode *ninode = NULL;
  struct dir *ndir = NULL;
  bool success1 = true;
  if (success && isdir){
    success1 = ((ninode = inode_open (inode_sector))
      && (ndir = dir_open (ninode))
      && dir_add (ndir, ".", inode_sector, true)
      && dir_add (ndir, "..",inode_get_inumber (dir_get_inode (dir_)), true));
  }

  if (inode_sector != 0 && !success) 
    free_map_release (inode_sector, 1);

  if (success && !success1) {
    success = false;
    printf("Failure: create dir: %s\n", name);
    dir_remove (dir_, name_);
  }

  done:
    dir_close (dir_);

  free(name_);
  if (!ndir && ninode){
    inode_close(ninode);
  } else if (ndir) {
    dir_close(ndir);
  }

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
*/
void
filesys_open (const char *name, struct file **file, struct dir **dir, bool *isdir)
{
  if (strlen(name) == 0) {
    if (file) *file = NULL;
    if (dir) *dir = NULL;
    if (isdir) *isdir = false;
    return;
  }
  struct dir *dir_ = filesys_get_dir (name);
  char *name_ = filesys_get_name (name);
  struct inode *inode = NULL;
  bool isdir_ = false;

  if (strcmp (name_, "") == 0) {
    if (file ) *file = NULL;
    if (dir) *dir = dir_;
    if (isdir) *isdir = true;
    free (name_);
  }  else if (dir_ && !dir_lookup (dir_, name_, &inode, &isdir_)) {
    if (file) *file = NULL;
    if (dir) *dir = NULL;
    if (isdir) *isdir = false;
    dir_close (dir_);
    free (name_);
  } else {
    dir_close (dir_);
    free (name_);
    if (isdir_) {
      if (file) *file = NULL;
      ASSERT (dir);
      *dir = dir_open (inode);
      if (isdir) *isdir = true;
    } else {
      ASSERT (file);
      *file = file_open (inode);
      if (dir) *dir = NULL;
      if (isdir) *isdir = false;
    }
  }
}

/* Deletes the file named NAME. */
bool 
filesys_remove (const char *name) 
{
  bool result = false;
  if (strlen(name) == 0){
    return false;
  } else {
    struct dir* dir_ = filesys_get_dir(name);
    char* name_ = filesys_get_name(name);
    if (strlen(name_) != 0) {
      result = dir_ != NULL && dir_remove (dir_, name_);
    }
    dir_close (dir_);
    free(name_); 
    return result;
  }

}

bool filesys_cd (const char* dir)
{
  bool result = false;
  char* name_;
  if (strlen(dir) == 0) {
    return false;
  } else {
    struct dir* dir_ = filesys_get_dir(dir);
    name_ = filesys_get_name(dir);
    struct inode* inode = NULL;
    bool isdir = false;

    if (strcmp(name_, "") == 0) {
      if (thread_current()->cur_dir) 
        dir_close(thread_current()->cur_dir);
      thread_current()->cur_dir = dir_;
      result = true;
    } else if (dir_lookup(dir_, name_, &inode, &isdir) ==NULL ||
               isdir == NULL) {
      dir_close(dir_);
      result = false;
    } else if (isdir != NULL){
      if (thread_current()->cur_dir)
        dir_close(thread_current()->cur_dir);
      thread_current()->cur_dir = dir_open(inode);
      dir_close(dir_);
      result = true;
    }
  }
  free(name_);
  return result;
}

/* Formats the file system. */
static void do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 2))
    PANIC ("root directory creation failed");

  if (dir_add(dir_open_root (), ".", ROOT_DIR_SECTOR, true) ==  NULL ||
      dir_add(dir_open_root (), "..", ROOT_DIR_SECTOR, true) == NULL ){
    PANIC ("root directory added . or .. failed");
  }
  
  free_map_close ();
  printf ("done.\n");
}

static struct dir* filesys_get_dir (const char* path)
{
  struct dir* dir;
  int len = strlen(path);
  char *p = (char *)malloc(sizeof(char) * (len + 1));
  memcpy(p, path, len);
  p[len]='\0';

  bool openRoot = p[0]=='/' || thread_current ()->cur_dir == NULL;
  dir = openRoot ? dir_open_root() : dir_reopen(thread_current()->cur_dir);

  char *save_ptr;
  char *token = strtok_r(p, "/", &save_ptr);
  char *next_token = token!=NULL ? strtok_r(NULL, "/", &save_ptr): NULL;
  struct inode *inode;
  bool isdir;

  while (next_token!=NULL){
    if (dir_lookup(dir, token, &inode, &isdir) == NULL) return NULL;
    dir_close(dir);
    dir = dir_open(inode);
    if (isdir == false){
      dir_close(dir);
      return NULL;
    }
    token = next_token;
    next_token = strtok_r(NULL, "/", &save_ptr);
  }
  return dir;

}

static char* filesys_get_name (const char* path)
{
  int len = strlen(path);
  char *p = (char *)malloc(sizeof(char) * (len + 1));
  memcpy(p, path, len);
  p[len]='\0';

  char *save_ptr;
  char *token = strtok_r(p, "/", &save_ptr);
  char *next_token = token!=NULL ? strtok_r(NULL, "/", &save_ptr): NULL;

  while (next_token!= NULL){
    token = next_token;
    next_token = strtok_r(NULL, "/", &save_ptr);
  }

  if (token == NULL){
    char* result = (char*) malloc(sizeof(char));
    result[0] = '\0';
    return result;
  } else {
    char *lst = (char*)malloc(sizeof(char) * (strlen(token) +1) );
    memcpy(lst, token, strlen(token));
    lst[strlen(token)] = '\0';
    return lst;
  }
}








