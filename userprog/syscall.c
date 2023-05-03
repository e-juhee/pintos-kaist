#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create (const char *file , unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint32_t *sp = f -> rsp; /* 유저 스택 포인터 */
	check_address((void *)sp);

	char *fn_copy;
	int siz;
	
	switch (f->R.rax)
	{
	case SYS_HALT:
		printf("halt!\n");
		halt();
		break;
	case SYS_EXIT:
		// printf("exit!\n");
		exit(f->R.rdi);
		break;
	// case SYS_FORK:
	// 	printf("fork!\n");
	// 	// f->R.rax = fork(f->R.rdi, f);
	// 	break;
	// case SYS_EXEC:
	// 	printf("exec!\n");
	// 	// if (exec(f->R.rdi) == -1)
	// 	// 	exit(-1);
	// 	break;
	// case SYS_WAIT:
	// 	printf("wait!\n");
	// 	// f->R.rax = process_wait(f->R.rdi);
	// 	break;
	case SYS_CREATE:
		// printf("create!\n");
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		// printf("remove!\n");
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		// printf("open!\n");
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		printf("filesize!\n");
		// f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		printf("read!\n");
		// f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		// printf("write!\n");
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		printf("seek!\n");
		// seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		printf("tell!\n");
		// f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		printf("close!\n");
		// close(f->R.rdi);
		break;
	// case SYS_DUP2:
	// 	printf("dup2!\n");
	// 	// f->R.rax = dup2(f->R.rdi, f->R.rsi);
	// 	break;
	default:
		// printf("default exit!\n");
		exit(-1);
		break;
	}
}

void check_address(void *addr)
{
	struct thread *curr = thread_current();
	if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(curr->pml4, addr) == NULL)
	{
		// 주소가 null이 아니고, 커널 스택의 주소 아니고, 해당 가상 주소에 대한 PTE가 존재할 때만 시스템 콜을 호출할 자격이 있는 포인터다.
		exit(-1);
	}
	/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
	/* 잘못된 접근(유저 영역을 벗어난 영역)일 경우 프로세스 종료(exit(-1)) */
}

void halt(void)
{
	power_off();
	//pintos 종료시키는 시스템 콜
	/* power_off()를 사용하여 pintos 종료 */
}

void exit(int status)
{
	/*
	- 실행중인 스레드 구조체 가져오기
	- 현재 프로세스 종료시키는 시스템 콜
	- 종료 시 메시지 출력
	출력 양식: 프로세스 이름:exit(status)
	- 정상적으로 종료 시 status는 0
	*/
	struct thread *cur = thread_current (); 
			/* 프로세스 디스크립터에 exit status 저장 */
	printf("%s: exit(%d)\n" , cur -> name , status);
	thread_exit();

}

bool create (const char *file , unsigned initial_size)
{
	/*
	- 파일 생성하는 시스템 콜
	- 성공일 경우 true, 실패일 경우 false 리턴
	- file: 생성할 파일의 이름 및 경로 정보
	- initial_size: 생성할 파일 크기
	*/
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove (const char *file)
{
	/*	
  - 파일을 삭제하는 시스템 콜
	- file : 제거할 파일의 이름 및 경로 정보
	- 성공 일 경우 true, 실패 일 경우 false 리턴
	*/
	check_address(file);
	return filesys_remove(file);
}

/*
* 파일을 열고 해당 파일 객체에 파일 디스크립터 부여하고 파일 디스크립터 반환
*/
int open (const char *file)
{
	check_address(file);
	/* 파일을 open */
	struct file *fileobj = filesys_open(file);

	/* 해당 파일이 존재하지 않으면 -1 리턴 */
	if (fileobj == NULL)
	{
		return -1;
	}

	/* 해당 파일 객체에 파일 디스크립터 부여 */ 
	int fd = process_add_file(fileobj);

	if (fd == -1)
	{
		file_close(fileobj);
	}
	/* 파일 디스크립터 리턴 */
	return fd;
}

/*
* fd에 해당하는 파일을 찾고 그 파일의 크기를 반환한다.
*/
int filesize(int fd)
{
	struct file *open_file = process_get_file(fd);
	if(open_file == NULL)
	{
		return -1;
	}
	return file_length(open_file);
}
/*
* fd를 이용해서 파일 객체를 검색하고 입력을 버퍼에 저장하고, 버퍼에 저장한 크기를 반환 
*/
int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	off_t read_byte;
	uint8_t *read_buffer = buffer;
	if (fd == 0)
	{
		char key;
		for (read_byte = 0; read_byte < size; read_byte++)
		{
			key = input_getc(); // 키보드에 한 문자 입력받기
			*read_buffer++ = key; // read_buffer에 받은 문자 저장
			if (key == '\0')
			{
				break;
			}
		}
	}
	else if (fd == 1)
	{
		return -1;
	}
	else
	{
		struct file *read_file = process_get_file(fd);
		if (read_file == NULL)
		{
			return -1;
		}
		lock_acquire(&filesys_lock);
		read_byte = file_read(read_file, buffer, size);
		lock_release(&filesys_lock);
	}
	return read_byte;
}

/*
* fd에 해당하는 파일을 열어서 buffer에 저장된 데이터를 size만큼 파일에 기록 후 기록한 바이트 수 리턴하는 함수
*/
int write(int fd, const void *buffer, unsigned size)
{
	struct file *write_file = process_get_file(fd);
	lock_acquire(&filesys_lock);
	if(fd < 2)
	{
		if (fd == 1)
		{
			putbuf(buffer, size);
		}
		return -1;
	}
	else
	{
		file_write(write_file, buffer, size);
	}
	lock_release(&filesys_lock);
}

/*
* 파일에서 position으로 이동하는 함수
*/
void seek(int fd, unsigned position)
{
	struct file *seek_file = process_get_file(fd);
	if (seek_file <= 2)
	{
		return;
	}
	file_seek(seek_file, position);
}

/*
* 열린 파일의 위치를 반환하는 함수
*/
unsigned tell(int fd)
{
	struct file *tell_file = process_get_file(fd);
	if (tell_file <= 2)
	{
		return;
	}
	return file_tell(tell_file);
}

/*
* 파일 디스크립터 엔트리 초기화
*/
void close (int fd)
{
	struct file *close_file = process_get_file(fd);
	if (close_file == NULL)
	{
		return;
	}
	file_close(close_file);
}
