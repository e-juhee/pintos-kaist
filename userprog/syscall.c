#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	int syscall_n = f->R.rax; /* 시스템 콜 넘버 */
	switch (syscall_n)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
	case SYS_FORK:
		fork(f->R.rdi);
	case SYS_EXEC:
		exec(f->R.rdi);
	case SYS_WAIT:
		wait(f->R.rdi);
	case SYS_CREATE:
		create(f->R.rdi, f->R.rsi);
	case SYS_REMOVE:
		remove(f->R.rdi);
	case SYS_OPEN:
		open(f->R.rdi);
	case SYS_FILESIZE:
		filesize(f->R.rdi);
	case SYS_READ:
		read(f->R.rdi, f->R.rsi, f->R.rdx);
	case SYS_WRITE:
		write(f->R.rdi, f->R.rsi, f->R.rdx);
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
	case SYS_TELL:
		tell(f->R.rdi);
	case SYS_CLOSE:
		close(f->R.rdi);
	}
}

void check_address(void *addr)
{
	if (addr == NULL)
		exit(-1);

	if (!is_user_vaddr(addr)) // 유저 영역이 아니거나 NULL이면 프로세스 종료
		exit(-1);

	if (pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status; // 이거 wait에서 사용?
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

int open(const char *file_name)
{
	check_address(file_name);
	struct file *file = filesys_open(file_name);
	if (file == NULL)
		return -1;

	int fd = process_add_file(file);
	if (fd == -1)
		file_close(file);

	return fd;
}

int filesize(int fd)
{
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return -1;
	return file_length(file);
}
/**************************************************/

int read(int fd, void *buffer, unsigned size)
{
}

int write(int fd, const void *buffer, unsigned size)
{
}

void seek(int fd, unsigned position)
{
}

unsigned tell(int fd)
{
}

void close(int fd)
{
}

pid_t fork(const char *thread_name)
{
}

int exec(const char *file)
{
}

int wait(pid_t pid)
{
}
