#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include <hash.h>
#include <limits.h>
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/exception.h"
#include "vm/frame.h"
#include "vm/page.h"

#define BUFFER_SIZE 300

static void syscall_handler (struct intr_frame *);
struct semaphore sys_sema;

void remove_fds (struct hash_elem *e, void *aux);
void remove_id_addr_entry (struct hash_elem *e, void *aux UNUSED);
void remove_child_info (struct hash_elem *e, void *aux UNUSED);

static struct dir * get_thread_dir_by_fd (int fd);
static bool is_fd_dir (int fd);
static bool chdir (const char *dir);
static bool readdir (int fd, char *name);
static bool mkdir (const char *dir);
static int inumber (int fd);
static bool isdir (int fd);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init(&sys_sema, 1);
}

void validate_addr (void *addr, void *esp, bool writable) {
    if (!addr || addr >= PHYS_BASE || addr < USER_VADDR_BASE )
        exit(-1);

    lock_acquire(&frame_table_lock);
    struct page *p = find_page(addr, thread_current());
    struct frame *fm = NULL;
    if (p != NULL && p->isLoaded){
        fm = find_fm(p->kaddr);
        fm->locked = true;
    }
    lock_release(&frame_table_lock);

    if (p != NULL && !p->isLoaded ) {
        bool load_result = load_page_to_frame(p, true);
        if (!load_result) exit(-1);
    }

    if (p != NULL ){
        if (writable && !p->writable)
            exit(-1);
    } else if (esp != NULL){
        bool is_valid= false;
        if (addr >= esp - DEFAUTL_STACK_GROUTH &&
            STACK_MAX_SIZE >= PHYS_BASE - pg_round_down(addr)){
            is_valid = inc_stack(addr, true, NULL);
        }
        if (!is_valid)
            exit(-1);
    } else {
        exit(-1);
    }
}

void validate_buf (char* buf, int size, void* esp, bool writable) {
    validate_addr (buf, esp, writable);
    int page_cnt= size / PGSIZE;
    int remain= size % PGSIZE;
    int i;
    for (i = 1; i <= page_cnt; i++) {
        validate_addr(buf+ i * PGSIZE, esp, writable);
    }
    if (remain > 0) {
        validate_addr(buf+ size, esp, writable);
    }
}


/* Resolves the called function from system call number,
 * validates arguments, passes control to the called function and
 * sets its return value, if any, to eax */
static void
syscall_handler (struct intr_frame *f)
{
 int* syscall = (int *)f->esp;
 validate_addr(syscall, NULL, false);
 void *args[3];
 char *buf;
    switch (*syscall) 
    {
        case SYS_HALT: 
            halt();
            break;
        case SYS_EXIT: 
            get_args(syscall, 1, args);
            f->eax = *(int *)args[0];
            int exit_code = *(int *)args[0];
            exit(exit_code);
            break;
        case SYS_EXEC: 
            get_args(syscall, 1, args);
            buf = (char *)*(int *)args[0];
            validate_addr(buf, f->esp, false);
            f->eax = exec(buf);
            release_args(syscall, 1, args);
            break;
        case SYS_WAIT: 
            get_args(syscall, 1, args);
            f->eax = wait(*(int *) args[0]);
            release_args(syscall, 1, args);
            break;
        case SYS_CREATE: 
            get_args(syscall, 2, args);
            buf = (char *)*(int *)args[0];
            validate_addr(buf, f->esp, false);
            f->eax = create(buf, *(int *)args[1]);
            release_args(syscall, 2, args);
            break;
        case SYS_REMOVE: 
            get_args(syscall, 1, args);
            buf = (char *)*(int *)args[0];
            validate_addr(buf, f->esp, false);
            f->eax = remove (buf);
            release_args(syscall, 1, args);
            break;
        case SYS_OPEN: 
            get_args(syscall, 1, args);
            buf = (char *)*(int *)args[0];
            validate_addr(buf, f->esp,  false);
            f->eax = open (buf);
            release_args(syscall, 1, args);
            break;
        case SYS_FILESIZE: 
            get_args(syscall, 1, args);
            int file_sz = filesize(*(int *)args[0]);
            f->eax = file_sz;
            release_args(syscall, 1, args);
            break;
        case SYS_READ: 
            get_args(syscall, 3, args);
            buf = (char *)*(int *)args[1];
            validate_buf(buf, *(unsigned *)args[2], f->esp, true);
            f->eax = read (*(int *)args[0], buf, *(unsigned *)args[2]);
            release_args(syscall, 3, args);
            break;
        case SYS_WRITE: 
            get_args(syscall, 3, args);
            buf = (char *)*(int *)args[1];
            validate_buf (buf, *(int *)args[2], NULL,  false);
            f->eax = write (*(int *)args[0], buf, *(int *)args[2]);
            release_args(syscall, 3, args);
            break;
        case SYS_SEEK: 
            get_args(syscall, 2, args);
            seek (*(int *)args[0], *(unsigned *)args[1]);
            release_args(syscall, 2, args);
            break;
        case SYS_TELL: 
            get_args(syscall, 1, args);
            f->eax = tell(*(int *)args[0]);
            release_args(syscall, 1, args);
            break;   
        case SYS_CLOSE:
            get_args(syscall, 1, args);
            close (*(int *)args[0]);
            release_args(syscall, 1, args);
            break;
        case SYS_MMAP: 
            get_args(syscall, 2, args);
            f->eax = mmap(*(int *)args[0], (char *)*(int *)args[1]);
            release_args(syscall, 2, args);
            break;
        case SYS_MUNMAP: 
            get_args(syscall, 1, args);
            munmap((mapid_t)*(int *)args[0]);
            release_args(syscall, 1, args);
            break;
        case SYS_CHDIR: {
           void *args[1];
           get_args(syscall, 1, args);
           char *buff_ptr = (char *)*(int *)args[0];
           validate_addr(buff_ptr, f->esp, false);
           f->eax = chdir(buff_ptr);
           release_args(syscall, 1, args);
           break;
       }
       case SYS_MKDIR: {
           void *args[1];
           get_args(syscall, 1, args);
           char *buff_ptr = (char *)*(int *)args[0];
           validate_addr(buff_ptr, f->esp, false);
           f->eax = mkdir(buff_ptr);
           release_args(syscall, 1, args);
           break;
       }
       case SYS_READDIR: {
           void *args[2];
           get_args(syscall, 2, args);
           char *buff_ptr = (char *)*(int *)args[1];
           validate_buf(buff_ptr, READDIR_MAX_LEN + 1, f->esp, true);
           f->eax = readdir(*(int *)args[0], buff_ptr);
           release_args(syscall, 2, args);
           break;
       }
       case SYS_ISDIR: {
           void *args[1];
           get_args(syscall, 1, args);
           f->eax = isdir(*(int *)args[0]);
           release_args(syscall, 1, args);
           break;
       }
       case SYS_INUMBER: {
           void *args[1];
           get_args(syscall, 1, args);
           f->eax = inumber(*(int *)args[0]);
           release_args(syscall, 1, args);
           break;
       } 
    }
}

void get_args (int *ptr, int count, void **argv) {
    int i;
    for (i = 0; i < count; ++i)
    {
        void *tmp_ptr= (void*) ++ptr;
        validate_addr(tmp_ptr, NULL, NULL);
        argv[i] = tmp_ptr;

    }
}

void release_args (int *ptr, int count, void **argv) {
    int i;
    for (i = 0; i < count; i++){
        void* tmp_ptr = (void*) ++ptr;
        lock_acquire(&frame_table_lock);
        struct page *p = find_page(ptr, thread_current());
        if (p && p->isLoaded){
            struct frame *fm = find_fm(p->kaddr);
            fm->locked = false;
        }
        lock_release(&frame_table_lock);
        argv[i] = tmp_ptr;
    }
}


void release_buf (const char* buf, int size) {
    lock_acquire(&frame_table_lock);
    struct page  *p  = find_page(buf, thread_current());
    struct frame *fm = find_fm(p->kaddr);
    fm->locked = false;
    int page_cnt = size/PGSIZE;
    int remain   = size%PGSIZE;
    int i;
    for (i= 1; i <= page_cnt; i++) {
        p = find_page(buf + i * PGSIZE, thread_current());
        fm = find_fm(p->kaddr);
        fm->locked = false;
    }
    if (remain > 0) {
        p = find_page(buf + size, thread_current());
        fm = find_fm(p->kaddr);
        fm->locked = false;
    }
    cond_signal(&frame_table_cond, &frame_table_lock);
    lock_release(&frame_table_lock);
}

void halt (void) {
    shutdown_power_off();
}

void exit (int status) {
    struct thread* curr= thread_current();
    printf ("%s: exit(%d)\n", curr->name, status);
    hash_destroy(&curr->ht_id_addr, remove_id_addr_entry);

    if (curr->cur_dir)
        dir_close(curr->cur_dir);

    hash_destroy(&curr->fds, remove_fds);

    lock_acquire(&ht_exec_to_threads_lock);
    delete_exe_to_threads_entry(curr);
    lock_release(&ht_exec_to_threads_lock);

    
    file_close(curr->exe);
    

    hash_destroy(&curr->page_table, remove_page);

    sema_down(&sys_sema);
    hash_destroy(&thread_current()->children, remove_child_info);
    if (curr->parent != NULL){
        struct thread *p = curr->parent;
        struct child_info* ci = find_child_info(p, thread_current()->tid);
        if (ci){
            lock_acquire(&ci->wait_lock);
            ci->state = CHILD_EXITING;
            ci->cthread = NULL;
            ci->exit_code = status;
            cond_signal(&ci->wait_cond, &ci->wait_lock);
            lock_release(&ci->wait_lock);
        }
    }
    sema_up(&sys_sema);
    thread_exit();
}

tid_t exec (const char *file_name){
    
    tid_t pid = process_execute(file_name);
    
    return pid;
}

int wait (tid_t pid) {
    return process_wait(pid);
}

bool create (const char *file_name, unsigned initial_size) {
    if(!file_name) exit(-1);
    
    int result = filesys_create(file_name, initial_size,false);
    
    return result;
}

int open (const char *file_name) {
    struct thread* curr = thread_current();
    if (hash_size(&curr->fds) == MAX_OPEN_FILES)
        return -1;

    struct file* f_ptr = NULL;
    struct dir* dir_ptr = NULL;
    bool isdir = false;

    
    filesys_open(file_name, &f_ptr, &dir_ptr, &isdir);

    if (!isdir) {
        if (f_ptr == NULL){
            return -1;
        }
    } else {
        if (dir_ptr == NULL){
            return -1;
        }
    }
    struct file_desc *fd_open = malloc(sizeof(struct file_desc));
    fd_open->fptr = f_ptr;
    fd_open->dir_ptr = dir_ptr;
    fd_open->isdir = isdir;
    insert_fd(curr, fd_open);
    return fd_open->fid;    
}

void insert_fd(struct thread *t, struct file_desc *fd) {
     fd->fid = ++t->fd_seq;
     while(!hash_insert(&t->fds, &fd->elem)){
        ;
     }

}

 bool remove (const char *file_name) {
    bool result = filesys_remove(file_name);
    return result;
 }

 int filesize (int fd) {
    struct file *fptr = get_file_by_id(fd);
    int fsize = -1;
    if (fptr != NULL) {
        fsize = file_length(fptr);
     }
     return fsize;
  }

 struct file * get_file_by_id (int fid) {
    struct file_desc fd;
    struct file_desc *fd_ptr ;
    fd.fid = fid;
    struct hash_elem *e = hash_find(&thread_current()->fds, &fd.elem);
    if (e == NULL) {
        return NULL;
    }
    fd_ptr = hash_entry(e, struct file_desc, elem);
    return fd_ptr->fptr;
 }

 static struct dir * get_thread_dir_by_fd (int fd) {
    struct file_desc f_desc;
    f_desc.fid = fd;
    struct hash_elem *e = hash_find(&thread_current()->fds, &f_desc.elem);
    if (!e) return NULL;
    struct file_desc *f_desc_ptr = hash_entry(e, struct file_desc, elem);
    return f_desc_ptr->dir_ptr;
 }

 static bool is_fd_dir (int fd) {
    struct file_desc f_desc;
    f_desc.fid = fd;
    struct hash_elem *e = hash_find(&thread_current()->fds, &f_desc.elem);
    if (!e) return NULL;
    struct file_desc *f_desc_ptr = hash_entry(e, struct file_desc, elem);
    return f_desc_ptr->isdir;
 }

int read (int fd, void *buffer, unsigned length) {

    if (fd == STDOUT_FILENO){
        return -1;
    } else if (fd == STDIN_FILENO){
        int i;
        char *tmp = (char *) buffer;
        for( i = 0; i < length; i++){
            tmp[i] = input_getc();
        }
        release_buf(buffer, length);
        return length;
    } else {
        
        struct file* fptr = get_file_by_id(fd);
        if (fptr == NULL){
            
            return -1;
        }
        int result = file_read(fptr, buffer, length);
        
        return result;
    }

}

int write (int fd, const void *buffer, unsigned length) {
    if (fd == STDIN_FILENO) {
        return 0;
    } else if (fd == STDOUT_FILENO){
        int cnt = length/BUFFER_SIZE;
        int remain = length%BUFFER_SIZE;
        int i;
        for (i = 0; i < cnt; i++){
            putbuf(buffer + i* BUFFER_SIZE, BUFFER_SIZE);
        }
        if (remain > 0){
            putbuf(buffer + cnt * BUFFER_SIZE, remain);
        }
        release_buf(buffer, length);
        return length;
    } else {
        struct file *f_ptr = get_file_by_id(fd);
        if (f_ptr) {
            
            length = file_write(f_ptr, buffer, length);
            
            release_buf(buffer, length);
            return length;
        };
        return -1;
    }
}


void close (int fid) {
    struct file_desc fd;
    fd.fid = fid;
    struct hash_elem* elem = hash_delete(&thread_current()->fds, &fd.elem);
    if (!elem){
        return;  
    } else {
        struct file_desc* fdp = hash_entry(elem, struct file_desc, elem);
        
        if (fdp->fptr){
            file_close(fdp->fptr);
        } else {
            dir_close(fdp->dir_ptr);
        }
        free(fdp);
    } 
}

void seek (int fd, unsigned pos) {
    struct file *fptr = get_file_by_id(fd);
    if (!fptr){
        return;
    }
    file_seek(fptr, pos);
    
}

unsigned tell (int fd) {
    struct file* fptr = get_file_by_id(fd);
    if (!fptr){
        return -1;
    }
    unsigned pos = file_tell(fptr);
    return pos;
}

void remove_fds (struct hash_elem *e, void *aux) {
    struct file_desc *fdp = hash_entry (e, struct file_desc, elem);
    file_close(fdp->fptr);
    dir_close(fdp->dir_ptr);
    free(fdp);
}

void remove_id_addr_entry (struct hash_elem *e, void *aux UNUSED) {
    struct id_addr *m = hash_entry (e, struct id_addr, elem);
    munmap_helper (m, thread_current ());
    free(m);
}

void remove_child_info (struct hash_elem *e, void *aux UNUSED) {
    struct child_info *ct = hash_entry (e, struct child_info, elem);
    if (ct->cthread != NULL) {
        ct->cthread->parent = NULL;
    }
    free(ct);
}

mapid_t mmap (int fd, void *addr) {

    if (fd == STDIN_FILENO || fd == STDOUT_FILENO || addr == NULL 
        || pg_ofs(addr)) {
        return MAP_FAILED;
    }

    int size = filesize(fd);
    if (size == -1 || size == 0) {
        return MAP_FAILED;
    }

    struct file* fptr = get_file_by_id(fd);
    if(!fptr) {
        return MAP_FAILED;
    }

    int page_cnt= size / PGSIZE;
    int remain= size % PGSIZE;
    if (remain){
        page_cnt++;
    }

    struct thread *curr = thread_current();

    void *exist_addr = addr;
    int exist_cnt = 0;
    while(exist_cnt < page_cnt) {
        if(find_page(exist_addr, curr)){
            return MAP_FAILED;
        }
        exist_addr += PGSIZE;
        exist_cnt++;
    }

    
    struct file *re_fptr = file_reopen(fptr);
    
    if(!re_fptr) return MAP_FAILED;

    int offset = 0;
    void *naddr = addr;
    while(size > 0){
         uint32_t rbytes = 0;
         uint32_t zbytes = 0;
        if(size >= PGSIZE){
            rbytes = PGSIZE;
        } else {
            rbytes = size;
        }
        zbytes = PGSIZE - rbytes;
        insert_mmap_page(naddr, offset, re_fptr, rbytes, zbytes);
        size -= rbytes;
        offset += rbytes;
        naddr += PGSIZE;
    }

    struct id_addr *new_addr;
    new_addr = (struct id_addr *)malloc(sizeof(struct id_addr));
    new_addr->addr = addr;
    new_addr->page_cnt = page_cnt;

    if(curr->id_addrs_seq == USHRT_MAX){
        curr->id_addrs_seq = 1;
    }
    curr->id_addrs_seq++;
    new_addr->mapid = curr->id_addrs_seq;

    while(!hash_insert(&curr->ht_id_addr, &new_addr->elem)){
        ;
    }
    return new_addr->mapid;
}

void munmap (mapid_t id) {
    struct thread *curr = thread_current();
    struct id_addr new_addr;
    new_addr.mapid = id;
    struct id_addr *e_addr;
    struct hash_elem *ele = hash_find(&curr->ht_id_addr, &new_addr.elem);

    if(ele)    e_addr = hash_entry(ele, struct id_addr, elem);
    else    return;

    munmap_helper(e_addr, curr);

}

void munmap_helper (struct id_addr *id, struct thread *t) {
    void *addr = id->addr;
    int i = 1;
    while( i <= id->page_cnt){
        struct page *p = find_page(addr, t);
        ASSERT(p && p->type == MMAP);
        free_mmap_page_to_file(p);
        hash_delete(&t->page_table, &p->elem);
        free(p);
        addr += PGSIZE;
        i++;
        
    }
    hash_delete(&t->ht_id_addr, &id->elem);
}

static int inumber (int fd) {
   if (!is_fd_dir(fd)) {
        struct file *file = get_file_by_id(fd);
        ASSERT (file != NULL);
        return inode_get_inumber(file_get_inode(file));
   } else {
        struct dir *dir = get_thread_dir_by_fd(fd);
        ASSERT (dir != NULL);
        return inode_get_inumber(dir_get_inode(dir));
   }
}

static bool chdir (const char *dir) {
   bool success = filesys_cd(dir);
   return success;
 }

static bool readdir (int fd, char *name) {
    if (!is_fd_dir(fd)) return false;
    struct dir *dir = get_thread_dir_by_fd(fd);
    if (!dir) return false;
    if (!dir_readdir(dir, name)) 
        return false;
    while( strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ){
        if (!dir_readdir(dir, name)) 
            return false;
    }
    return true;
}

static bool mkdir (const char *dir) {
   bool success = filesys_create(dir, 2 * SIZE_DIR, true);
   return success;
}

static bool isdir (int fd) {
   return is_fd_dir(fd);
}


