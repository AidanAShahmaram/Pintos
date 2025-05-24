#ifndef USERPROG_FD_H
#define USERPROG_FD_H

#include "threads/thread.h"
#include "filesys/file.h"
#include <list.h>

struct fd_entry {
    int fd;
    struct file *file;
    struct list_elem elem;  // For the thread’s fd_list
};

struct fd_entry *fd_create(struct file *f);
struct fd_entry *fd_lookup(int fd);
bool fd_close(int fd);
void fd_close_all(void);
#endif /* USERPROG_FD_H */
