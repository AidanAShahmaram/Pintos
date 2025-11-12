# Pintos Operating System – User Programs, Loader, and System Calls

## Overview

This repository contains my implementation of the **user program subsystem** for the [Pintos](https://web.stanford.edu/class/cs140/projects/pintos/pintos_1.html) educational operating system as part of **UCLA CS 111 (Operating Systems Principles)**.  
The project required extending Pintos’ kernel to support **user-space execution**, **process management**, and **file system interaction** through a robust system-call interface.  

The work spans multiple components of the Pintos kernel, with a focus on:
- Building a **process loader and stack initializer** that correctly transfers control from kernel to user mode.
- Implementing a **complete system-call layer** that safely mediates between user and kernel space.
- Managing **concurrency, synchronization, and resource cleanup** for processes and open files.
- Enforcing **memory protection and privilege separation** to prevent kernel compromise by user programs.

This implementation passes all user-program tests (`make check`) in the `userprog/` suite, including validation of argument passing, synchronization, and file system correctness.

---

## Project Structure

### 1. Loader and Process Initialization

**Files modified:**  
`userprog/process.c`, `threads/init.c`, `threads/thread.c`, `lib/user/entry.c`

- Implemented the **ELF binary loader**, correctly parsing program headers and mapping code/data segments into user virtual memory.
- Designed the **user stack layout** following x86 ABI conventions, aligning the stack to 16 bytes, and placing arguments (`argv`, `argc`) and a fake return address.
- Implemented argument parsing to support commands such as:
`pintos -q run 'echo hello world'`
resulting in a memory layout identical to that of real UNIX processes.

- Fixed privilege-level transitions using `iret` to switch from kernel mode to user mode and restore the process’s stack pointer and instruction pointer safely:contentReference[oaicite:0]{index=0}.

- Added safeguards against invalid memory access by ensuring the user stack starts at `PHYS_BASE - 12`, preventing page faults from out-of-bounds references near kernel space:contentReference[oaicite:1]{index=1}.

### 2. Process Management

- Implemented **parent-child synchronization** between `process_execute()` and `start_process()` using semaphores, ensuring the parent waits until the child finishes loading.
- Managed **thread control blocks (TCBs)** to track per-process states, including:
- PID
- Exit status
- File descriptors
- Kernel stack pointer
- Implemented the `process_wait()` function to synchronize parent termination, correctly handling zombie processes and reaping children only once.

- Extended thread lifecycle management to ensure **clean resource deallocation**, including closing all open files and freeing page directories on process exit:contentReference[oaicite:2]{index=2}.

### 3. System Call Interface

**Files modified:**  
`userprog/syscall.c`, `lib/user/syscall.c`, `lib/syscall-nr.h`

#### Supported System Calls

| Category | System Calls Implemented |
|-----------|--------------------------|
| **File System** | `create`, `remove`, `open`, `filesize`, `read`, `write`, `seek`, `tell`, `close` |
| **Process Control** | `halt`, `exit`, `exec`, `wait` |

Each system call includes:
- **Argument validation**: Prevents invalid or kernel-space pointers using page-table verification before dereferencing:contentReference[oaicite:3]{index=3}.
- **Synchronization**: A global lock prevents concurrent access to the non-thread-safe Pintos file system:contentReference[oaicite:4]{index=4}.
- **Error handling**: Returns POSIX-like error codes and terminates user processes with `-1` on illegal memory access.

#### File Descriptor Management
- Designed a **per-process file descriptor table** (implemented as a hash map).
- FD 0 and 1 are reserved for `STDIN_FILENO` and `STDOUT_FILENO`.
- Each `open` call allocates a unique descriptor, while `close` reclaims it.
- Guaranteed that all open FDs are closed upon process termination.

#### Concurrency
- Used kernel-level locks to serialize file operations while allowing multiple user processes to execute concurrently.
- Prevented data races between user I/O and process exit.

#### Memory Protection
- Implemented validation for all system call arguments, including recursive checks for buffer ranges during `read` and `write`.
- Guarded kernel against segmentation faults by using `pagedir_get_page()` to verify virtual memory mappings before access.

---

## 4. The Loader (Vitamin 4 Extension)

The loader is responsible for parsing ELF binaries and setting up a correct initial user environment.  
Although the official spec was not available, this implementation:
- Reads ELF headers, verifies segment validity, and allocates memory with `pagedir_set_page`.
- Constructs the stack frame according to the x86 calling convention (see Pintos Reference §2.7):contentReference[oaicite:5]{index=5}.
- Handles stack alignment and pushes `argc`, `argv[]`, and the fake return address to mirror Linux process startup.

---

## 5. Synchronization and Resource Management

- Introduced semaphores in `process_wait()` and `process_execute()` to guarantee correct ordering between parent and child lifecycles:contentReference[oaicite:6]{index=6}.
- Extended the thread system with additional states (`THREAD_WAITING`, `THREAD_ZOMBIE`) for fine-grained control.
- Implemented reference counting for `struct file` objects to ensure executables remain **read-only while in use**, fulfilling the “rox” requirement:contentReference[oaicite:7]{index=7}.

---

## 6. Testing and Validation

All user program tests in `userprog/` were executed using:
```bash
make check
