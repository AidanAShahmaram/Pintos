#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>

#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */

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

/* Block device that contains the file system. */
extern struct block *fs_device;

void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(const char *name, off_t initial_size);
struct file *filesys_open(const char *name);
bool filesys_remove(const char *name);

#endif /* filesys/filesys.h */
