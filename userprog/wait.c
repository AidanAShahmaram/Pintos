// wait.c
#include "userprog/wait.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Create and initialize a new child_status object. */
struct child_status *child_status_create() {
  struct child_status *cs = malloc(sizeof(struct child_status));
  if (cs == NULL) return NULL;

  cs->child_tid = -1;
  cs->exit_code = -1;
  cs->has_exited = false;

  cs->ref_count = 2; // One for parent, one for child
  lock_init(&cs->ref_lock);
  sema_init(&cs->exit_sema, 0);

  return cs;
}

void set_child_tid(struct child_status *cs, int tid){
  cs->child_tid = tid;
}
  

/* Called by the child at exit. */
void child_status_exit(struct child_status *cs, int exit_code) {
  cs->exit_code = exit_code;
  cs->has_exited = true;
  sema_up(&cs->exit_sema);
  thread_current()->self_to_parent = NULL;
  child_status_release(cs); // Drop child's reference
}

/* Called by parent to wait on the child. */
int child_status_wait(struct child_status *cs) {
  if(cs == NULL){
    return -1;
  }
  sema_down(&cs->exit_sema);
  int exit_code = cs->exit_code;
  list_remove(&cs->elem);
  child_status_release(cs); // Drop parent's reference
  return exit_code;
}

/* Releases a reference to the struct and frees it if unused. */
void child_status_release(struct child_status *cs) {
  lock_acquire(&cs->ref_lock);
  cs->ref_count--;
  bool should_free = (cs->ref_count == 0);
  lock_release(&cs->ref_lock);

  if (should_free) {
    free(cs);
  }
}


struct child_status *find_child_status(struct thread *parent, tid_t child_tid){
  struct list_elem *e;
  for(e = list_begin(&parent->self_to_children); e != list_end(&parent->self_to_children); e = list_next(e)){
    struct child_status *cs = list_entry(e, struct child_status, elem);
    if(cs->child_tid == child_tid){
      return cs;
    }
  }
  return NULL; //Child not found
}
