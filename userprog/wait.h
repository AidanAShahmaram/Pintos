// wait.h
#ifndef USERPROG_WAIT_H
#define USERPROG_WAIT_H

#include "threads/synch.h"
#include "threads/thread.h"

struct child_status {
  int child_tid;
  int exit_code;
  bool has_exited;

  int ref_count;
  struct lock ref_lock;
  struct semaphore exit_sema;

  bool load_success;

  struct list_elem elem; // To be used in parent->children list
};

struct child_status *child_status_create();


void child_status_exit(struct child_status *cs, int exit_code);

int child_status_wait(struct child_status *cs);

void child_status_release(struct child_status *cs);

void set_child_tid(struct child_status *cs, int tid);

struct child_status *find_child_status(struct thread *parent, int child_tid);

#endif /* USERPROG_WAIT_H */
