// wait.h
#ifndef USERPROG_WAIT_H
#define USERPROG_WAIT_H

#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/kernel/list.h"

struct child_status {
  int child_tid;
  int exit_code;
  bool has_exited;

  int ref_count;
  struct lock ref_lock;
  struct semaphore exit_sema;

  bool load_success;
  struct semaphore load_sema;
  
  struct list_elem elem; // To be used in parent->children list
};

/* Allocates and initializes a new child_status struct. */
struct child_status *child_status_create(void);

/* Mark child as exited and store its exit code. */
void child_status_exit(struct child_status *cs, int exit_code);

/* Parent waits for child to exit. Returns exit code. */
int child_status_wait(struct child_status *cs);

/* Releases a reference to the struct and frees it if no longer in use. */
void child_status_release(struct child_status *cs);

void set_child_tid(struct child_status *cs, int tid);
  
struct child_status *find_child_status(struct thread *parent, int child_tid);

#endif /* USERPROG_WAIT_H */