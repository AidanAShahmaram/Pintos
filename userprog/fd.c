#include "userprog/fd.h"
#include "threads/malloc.h"
#include <stddef.h>

struct fd_entry *fd_create(struct file *f) {
    struct thread *cur = thread_current();
    struct fd_entry *fde = malloc(sizeof(struct fd_entry));
    if (!fde) return NULL;

    fde->fd = cur->next_fd_num++;
    fde->file = f;
    list_push_back(&cur->fd_list, &fde->elem);
    return fde;
}

struct fd_entry *fd_lookup(int fd) {
    struct list *fds = &thread_current()->fd_list;
    struct list_elem *e;
    for (e = list_begin(fds); e != list_end(fds); e = list_next(e)) {
        struct fd_entry *fde = list_entry(e, struct fd_entry, elem);
        if (fde->fd == fd)
            return fde;
    }
    return NULL;
}

bool fd_close(int fd) {
    struct list *fds = &thread_current()->fd_list;
    struct list_elem *e;

    for (e = list_begin(fds); e != list_end(fds); e = list_next(e)) {
        struct fd_entry *fde = list_entry(e, struct fd_entry, elem);
        if (fde->fd == fd) {
            file_close(fde->file);               // Close the file
            list_remove(&fde->elem);             // Remove from fd_list
            free(fde);                           // Free the struct
            return true;
        }
    }

    return false;  // fd not found
}

void fd_close_all(void) {
    struct list *fds = &thread_current()->fd_list;
    while (!list_empty(fds)) {
        struct list_elem *e = list_pop_front(fds);
        struct fd_entry *fde = list_entry(e, struct fd_entry, elem);
        file_close(fde->file);
        free(fde);
    }
}
