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

/** NEW ADDED HERE **/
static struct dir* path_to_dir (const char* path);
static char* path_to_name (const char* path);

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

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir) 
{
  /** NEW ADDED HERE **/
  if (strlen(name) == 0) return false;
  block_sector_t inode_sector = 0;

  struct dir *dir_ = path_to_dir(name);
  char *name_ = path_to_name(name);
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
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
void
filesys_open (const char *name, struct file **file, struct dir **dir, bool *isdir)
{
  if (strlen(name) == 0) {
    if (file) *file = NULL;
    if (dir) *dir = NULL;
    if (isdir) *isdir = false;
    return;
  }

  struct dir *dir_ = path_to_dir (name);
  char *name_ = path_to_name (name);
  struct inode *inode = NULL;
  bool isdir_ = false;

  /* name is "/", open root */
  if (strcmp (name_, "") == 0) {
    if (file ) *file = NULL;
    if (dir) *dir = dir_;
    if (isdir) *isdir = true;
    free (name_);
    // return;
  }

  // if (dir_)
  else if (dir_ && !dir_lookup (dir_, name_, &inode, &isdir_)) {
    if (file) *file = NULL;
    if (dir) *dir = NULL;
    if (isdir) *isdir = false;
    dir_close (dir_);
    free (name_);
    // return;
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

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  // struct dir *dir = dir_open_root ();
  // bool success = dir != NULL && dir_remove (dir, name);
  // dir_close (dir);

  /** NEW ADDED HERE **/
  // if (strlen(name) == 0) return false;
  
  // struct dir* dir_ = path_to_dir(name);
  // char* name_ = path_to_name(name);
  // bool success = false;

  //  can't remove root 
  // if (strcmp (name_, "") == 0) goto done;

  // success = dir_ != NULL && dir_remove (dir_, name_);

  // done:
  // dir_close (dir_);
  // free(name_); 

  // return success;

  bool result = false;
  if (strlen(name) == 0){
    return false;
  } else {
    struct dir* dir_ = path_to_dir(name);
    char* name_ = path_to_name(name);
    if (strlen(name_) != 0) {
      result = dir_ != NULL && dir_remove (dir_, name_);
    }
    dir_close (dir_);
    free(name_); 
    return result;
  }

}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 2))
    PANIC ("root directory creation failed");

  /** NEW ADDED HERE **/
  // if (!dir_add (dir_open_root (), ".", ROOT_DIR_SECTOR, true)
  //     || !dir_add (dir_open_root (), "..", ROOT_DIR_SECTOR, true))
  //   PANIC ("add entry . and .. for root directory failed");

  if (dir_add(dir_open_root (), ".", ROOT_DIR_SECTOR, true) ==  NULL ||
      dir_add(dir_open_root (), "..", ROOT_DIR_SECTOR, true) == NULL ){
    PANIC ("root directory added . or .. failed");
  }
  
  free_map_close ();
  printf ("done.\n");
}


/** NEW ADDED HERE **/

/* Change current thread's work directory to DIR.
   Returns true if successful, otherwise false */
bool filesys_cd (const char* dir)
{
  // if (strlen(dir) == 0) return false;

  // struct dir* dir_ = path_to_dir(dir);
  // char* name_ = path_to_name(dir);
  // struct inode* inode = NULL;
  // bool isdir = false;

  // bool success = false;

  // /* Change work directory to root */
  // if (strcmp(name_, "") == 0) {
  //   if (thread_current()->cwd) dir_close(thread_current()->cwd);
  // thread_current()->cwd = dir_;
  // success = true;
  // goto done;
  // }

  // if (!dir_lookup(dir_, name_, &inode, &isdir)) {
  //   dir_close(dir_);
  // success = false;
  // goto done;
  // }

  // if (!isdir) {
  //   dir_close(dir_);
  // success = false;
  // } else {
  //   if (thread_current()->cwd) dir_close(thread_current()->cwd);
  //   thread_current()->cwd = dir_open(inode);
  //   dir_close(dir_);
  //   success = true;
  // }

  // done:
  // free(name_);
  // return success;


  bool result = false;
  char* name_;
  if (strlen(dir) == 0) {
    return false;
  } else {
    struct dir* dir_ = path_to_dir(dir);
    name_ = path_to_name(dir);
    struct inode* inode = NULL;
    bool isdir = false;

    if (strcmp(name_, "") == 0) {
      if (thread_current()->cwd) 
        dir_close(thread_current()->cwd);
      thread_current()->cwd = dir_;
      result = true;
    } else if (dir_lookup(dir_, name_, &inode, &isdir) ==NULL ||
               isdir == NULL) {
      dir_close(dir_);
      result = false;
    } else if (isdir != NULL){
      if (thread_current()->cwd)
        dir_close(thread_current()->cwd);
      thread_current()->cwd = dir_open(inode);
      dir_close(dir_);
      result = true;
    }
  }
  free(name_);
  return result;
}

/* Traverse directory hierachy according to tokens in PATH, except
   for the last token.
   Examples:
   PATH = "", returns a struct dir* that points to current thread's work directory
   PATH = "/", returns a struct dir* that points to root
   PATH = "a", returns a struct dir* that points to current thread's work directory
   PATH = "/a", returns a struct dir* that points to root
   PATH = "/a/b", returns a struct dir* that points to directory "a"  under root
   PATH = "a/b", returns a struct dir* that points to directory "a"
   under current thread's work directory
   PATH = "/a/./../b", returns a struct dir* that points to root
   If failed, returns NULL. If successful, caller is responsible
   for closing the struct dir* */
static struct dir* path_to_dir (const char* path)
{
  // struct dir* dir;
  // char *s = (char *)malloc(sizeof(char) * (strlen(path) + 1));
  // memcpy(s, path, strlen(path));
  // s[strlen(path)] = '\0';

  // /* If first char in path is '/' or if current thread's work directory
  //    is NULL (which means work directory is root), open root.
  //    Otherwise, open current thread's work directory */
  // if (s[0] == '/' || !thread_current ()->cwd){
  //   dir = dir_open_root ();
  // } else {
  //   dir = dir_reopen(thread_current()->cwd);
  // }

  // char *save_ptr;
  // char *token;
  // char *next_token;
  // token = strtok_r(s, "/", &save_ptr);

  // if (token)
  //   next_token = strtok_r(NULL, "/", &save_ptr);
  // else
  //   next_token = NULL;

  // if (next_token == NULL) return dir;

  // struct inode *inode;
  // bool isdir;
  // for (; next_token != NULL; token = next_token,
  //      next_token = strtok_r(NULL, "/", &save_ptr)) {

  //   if (!dir_lookup(dir, token, &inode, &isdir)) return NULL;

  //   dir_close(dir);
  //   dir = dir_open(inode);

  //   if (!isdir){
  //     dir_close(dir);
  //     return NULL;
  //   }
  // }

  // return dir;

  struct dir* dir;
  int len = strlen(path);
  char *p = (char *)malloc(sizeof(char) * (len + 1));
  memcpy(p, path, len);
  p[len]='\0';

  bool openRoot = p[0]=='/' || thread_current ()->cwd == NULL;
  dir = openRoot ? dir_open_root() : dir_reopen(thread_current()->cwd);

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

/* Returns last token in PATH
   Examples:
   PATH = "", returns ""
   PATH = "/", returns ""
   PATH = "a", returns "a"
   PATH = "/a", returns "a"
   PATH = "/a/b", returns "b"
   PATH = "a/b", returns "b"
   PATH = "/a/./../b", returns "b"
   Caller is responsible for freeing the char* */
static char* path_to_name (const char* path)
{
  if (strcmp(path, "") == 0) goto done_empty;

  char *s = (char *)malloc(sizeof(char) * (strlen(path) + 1));
  memcpy(s, path, strlen(path));
  s[strlen(path)] = '\0';

  char *save_ptr;
  char *token;
  char *next_token;
  token = strtok_r(s, "/", &save_ptr);

  if (token)
    next_token = strtok_r(NULL, "/", &save_ptr);
  else
    goto done_empty;

  if (next_token == NULL) goto done;

  for (; next_token != NULL; token = next_token,
       next_token = strtok_r(NULL, "/", &save_ptr))
    ;

  done:
  ;
  char *name = (char *)malloc(sizeof(char) * (strlen(token) + 1));
  memcpy(name, token, strlen(token));
  name[strlen(token)] = '\0';
  return name;

  done_empty:
  ;
  char *empty = (char *)malloc(sizeof(char));
  empty[0] = '\0';
  return empty;
}
