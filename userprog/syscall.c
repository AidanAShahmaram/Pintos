#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"

static struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);

static void validate_user_ptr(const void *uaddr) {
  if (uaddr == NULL || !is_user_vaddr(uaddr) || pagedir_get_page(thread_current()->pagedir, uaddr) == NULL) {
    sys_exit(-1);
  }
}

bool validate_user_string(const char *str) {
  if(str == NULL){
    return false;
  }
  while (true) {
      if (!is_user_vaddr(str)) 
        return false;
      if (pagedir_get_page(thread_current()->pagedir, str) == NULL)
        return false;
      if (*str == '\0') 
        break;
      str++;
  }
  return true;
}

bool validate_user_buffer(const void *buffer, size_t size) {
  if(buffer == NULL){
    return false;
  }
  const uint8_t *ptr = (const uint8_t *)buffer;
  for (size_t i = 0; i < size; i++) {
    if (!is_user_vaddr((ptr + i)) || pagedir_get_page(thread_current()->pagedir, (ptr + i)) == NULL) {
      return false;
    }
  } 
  return true;
}

void syscall_init(void) {
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void sys_exit(int code){
  struct thread *cur = thread_current();
  cur->exit_status = code;
  printf("%s: exit(%d)\n", cur->name, code);
  thread_exit();  // Does not return
}

int sys_open(const char *file){
  if(file == NULL){
    sys_exit(-1);
  }
  if(!validate_user_string(file)){
    sys_exit(-1);
  }
  size_t len = strlen(file);
  if(len == 0 || len > 14){ //max file name of 14 in pintos reference
    return -1;
  }
  lock_acquire(&filesys_lock);
  
  struct file *f = filesys_open(file);
  if(f == NULL){
    lock_release(&filesys_lock);
    return -1;
  }

  struct fd_entry *new_fd  = fd_create(f);
  if(new_fd == NULL){
    file_close(f);
    lock_release(&filesys_lock);
    return -1;
  }

  lock_release(&filesys_lock);
  return new_fd->fd;
}

bool sys_create(const char *file, off_t initial_size){
  if(file == NULL){
    sys_exit(-1);
  }
  if(!validate_user_string(file)){
    sys_exit(-1);
  }
  size_t len = strlen(file);
  if(len == 0 || len > 14){ //max file name of 14 in pintos reference
    return false;
  }
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool sys_remove(const char *file){
  if(file == NULL){
    return false;
  }
  validate_user_string(file);
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

int sys_filesize(int fd){
  lock_acquire(&filesys_lock);
  struct fd_entry *fd_ent = fd_lookup(fd);
  int size = file_length(fd_ent->file);
  lock_release(&filesys_lock);
  return size;
}

int sys_read(int fd, void *buffer, unsigned size){
  if(buffer == NULL){
    sys_exit(-1);
  }
  if(size > 0){
    if(!validate_user_buffer(buffer, size)){
      sys_exit(-1);
    }
  }
  if(fd == STDOUT_FILENO){
    return -1;
  }

  if (fd == STDIN_FILENO) {
    unsigned count = 0;
    uint8_t *buf = buffer;
    while (count < size) {
      buf[count++] = input_getc();
    }
    return count;
  }

  struct fd_entry *fd_ent = fd_lookup(fd);
  if(fd_ent == NULL){
    return -1;
  }
  lock_acquire(&filesys_lock);
  int bytes_read = file_read(fd_ent->file, buffer, size);
  lock_release(&filesys_lock);
  return bytes_read;
}

int sys_write(int fd, const void *buffer, unsigned size){
  if(buffer == NULL){
     sys_exit(-1);
  }
  if(!validate_user_buffer(buffer, size)){
    sys_exit(-1);
  }
  if(fd == STDIN_FILENO){
    return -1;
  }

  if (fd == STDOUT_FILENO) {
    putbuf (buffer, size);
    return (int) size;
  }

  lock_acquire(&filesys_lock);
  struct fd_entry *fd_ent = fd_lookup(fd);
  if(fd_ent == NULL){
    lock_release(&filesys_lock);
    return -1;
  }
  int bytes_written = file_write(fd_ent->file, buffer, size);
  lock_release(&filesys_lock);
  return bytes_written;
}

void sys_seek(int fd, unsigned position){
  lock_acquire(&filesys_lock);
  struct fd_entry *fd_ent = fd_lookup(fd);
  file_seek(fd_ent->file, position);
  lock_release(&filesys_lock);
}

unsigned sys_tell(int fd){
  lock_acquire(&filesys_lock);
  struct fd_entry *fd_ent = fd_lookup(fd);
  int next_byte = file_tell(fd_ent->file);
  lock_release(&filesys_lock);
  return next_byte;
}

void sys_close(int fd){
  /*file itself is closed within the fd_close call, makes it so that only one traversal needs to be done */
  lock_acquire(&filesys_lock);
  fd_close(fd);
  lock_release(&filesys_lock);
}

int sys_exec(const char *cmd_line){
  /*create new proces*/
  if(cmd_line == NULL){
    return -1;
  }
  validate_user_string(cmd_line);
  char *input = palloc_get_page(0);
  size_t len = strlen(cmd_line) + 1;
  if(input == NULL){
    return -1;
  }
  strlcpy(input, cmd_line, PGSIZE);
  tid_t child = process_execute(input);
  return child;
}

void sys_halt(void){
  shutdown_power_off();
}

static void syscall_handler(struct intr_frame *f UNUSED) {
  validate_user_ptr(f->esp);
  uint32_t *args = ((uint32_t *) f->esp);

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */

    /* printf("System call number: %d\n", args[0]); */
    validate_user_ptr(f->esp + 0*sizeof(uint32_t));
    if (args[0] == SYS_EXIT) {
        validate_user_ptr(f->esp + 1*sizeof(uint32_t));
        sys_exit(args[1]);
    } else if (args[0] == SYS_INCREMENT){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      f->eax = args[1] + 1;
    } else if(args[0] == SYS_OPEN){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      const char *file_name = args[1];
      f->eax = sys_open(file_name);
    } else if(args[0] == SYS_CREATE){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      validate_user_ptr(f->esp + 2*sizeof(uint32_t));
      const char *file_name = (const char *)args[1];
      int init_size = args[2];
      f->eax = sys_create(file_name, init_size);
    } else if(args[0] == SYS_REMOVE){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      const char *file_name = args[1];
      f->eax = sys_remove(file_name);
    } else if(args[0] == SYS_FILESIZE){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      int fd_arg = args[1];
      f->eax = sys_filesize(fd_arg);
    } else if(args[0] == SYS_READ){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      validate_user_ptr(f->esp + 2*sizeof(uint32_t));
      validate_user_ptr(f->esp + 3*sizeof(uint32_t));
      int fd_arg = args[1];
      const void *buf = args[2];
      unsigned size = args[3];
      if(buf == NULL){
        sys_exit(-1);
      }

      struct fd_entry *fde = fd_lookup(fd_arg);
      if(fde = NULL){
        sys_exit(-1);
      }
      f->eax = sys_read(fd_arg, buf, size);
    } else if(args[0] == SYS_WRITE){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      validate_user_ptr(f->esp + 2*sizeof(uint32_t));
      validate_user_ptr(f->esp + 3*sizeof(uint32_t));
      int fd_arg = args[1];
      const void *buf =	args[2];
      unsigned size = args[3];
      f->eax = sys_write(fd_arg, buf, size);
    } else if(args[0] == SYS_SEEK){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      validate_user_ptr(f->esp + 2*sizeof(uint32_t));
      int fd_arg = args[1];
      int pos = args[2];
      sys_seek(fd_arg, pos);      
    } else if(args[0] == SYS_TELL){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      int fd_arg = args[1];
      f->eax = sys_tell(fd_arg);
    } else if(args[0] == SYS_CLOSE){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      int fd_arg = args[1];
      sys_close(fd_arg);
    } else if(args[0] == SYS_HALT){
      sys_halt();
    } else if(args[0] == SYS_EXEC){
      validate_user_ptr(f->esp + 1*sizeof(uint32_t));
      validate_user_string(args[1]);
      char *cmd = args[1];
      sys_exec(cmd);
    }
}
