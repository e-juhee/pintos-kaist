/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
// file-backed page의 하위 시스템을 초기화합니다.
void vm_file_init(void)
{
	// todo: file-backed page와 관련된 모든 설정을 수행할 수 있습니다.
}

/* Initialize the file backed page */
// file-backed page를 초기화합니다.
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	// 먼저 page->operations에 file-backed pages에 대한 핸들러를 설정합니다.
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	// todo: page struct의 일부 정보(such as 메모리가 백업되는 파일과 관련된 정보)를 업데이트할 수도 있습니다.
	struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *)page->uninit.aux;
	file_page->file = lazy_load_arg->file;
	file_page->ofs = lazy_load_arg->ofs;
	file_page->read_bytes = lazy_load_arg->read_bytes;
	file_page->zero_bytes = lazy_load_arg->zero_bytes;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
	struct file_page *file_page UNUSED = &page->file;
	return lazy_load_segment(page, file_page);
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
	if (pml4_is_dirty(thread_current()->pml4, page->va))
	{
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}

	// 페이지와 프레임의 연결 끊기
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(thread_current()->pml4, page->va);
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
// 변경된 내용을 file에 작성하고, frame 구조체를 반환하는 함수
static void
file_backed_destroy(struct page *page)
{
	// page struct를 해제할 필요는 없습니다. (file_backed_destroy의 호출자가 해야 함)
	struct file_page *file_page UNUSED = &page->file;
	if (pml4_is_dirty(thread_current()->pml4, page->va))
	{
		file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}
	pml4_clear_page(thread_current()->pml4, page->va);

	// 이 페이지에 매핑되었던 frame 구조체 반환
	// lock_acquire(&frame_table_lock);
	// if (page->frame)
	// {
	// 	list_remove(&page->frame->frame_elem); // frame_table에서 삭제
	// 	free(page->frame);
	// }
	// lock_release(&frame_table_lock);
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	struct file *f = file_reopen(file);
	void *start_addr = addr; // 매핑 성공 시 파일이 매핑된 가상 주소 반환하는 데 사용
	int total_page_count = length <= PGSIZE ? 1 : length % PGSIZE ? length / PGSIZE + 1
																  : length / PGSIZE; // 이 매핑을 위해 사용한 총 페이지 수

	size_t read_bytes = file_length(f) < length ? file_length(f) : length;
	size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(addr) == 0);	 // upage가 페이지 정렬되어 있는지 확인
	ASSERT(offset % PGSIZE == 0) // ofs가 페이지 정렬되어 있는지 확인;

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* 이 페이지를 채우는 방법을 계산합니다.
		파일에서 PAGE_READ_BYTES 바이트를 읽고
		최종 PAGE_ZERO_BYTES 바이트를 0으로 채웁니다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *)malloc(sizeof(struct lazy_load_arg));
		lazy_load_arg->file = f;
		lazy_load_arg->ofs = offset;
		lazy_load_arg->read_bytes = page_read_bytes;
		lazy_load_arg->zero_bytes = page_zero_bytes;

		// vm_alloc_page_with_initializer를 호출하여 대기 중인 객체를 생성합니다.
		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, lazy_load_segment, lazy_load_arg))
			return NULL;

		struct page *p = spt_find_page(&thread_current()->spt, start_addr);
		p->mapped_page_count = total_page_count;

		/* Advance. */
		// 읽은 바이트와 0으로 채운 바이트를 추적하고 가상 주소를 증가시킵니다.
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}

	return start_addr;
}

/* Do the munmap */
void do_munmap(void *addr)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *p = spt_find_page(spt, addr);
	int count = p->mapped_page_count;
	for (int i = 0; i < count; i++)
	{
		if (p)
			destroy(p);
		// {
		// 	if (pml4_get_page(thread_current()->pml4, p->va))
		// 		// 매핑된 프레임이 있다면 = swap out 되지 않았다면 -> 페이지를 제거하고 연결된 프레임도 제거
		// 		spt_remove_page(spt, p);
		// 	else
		// 	{ // swap out된 경우에는 매핑된 프레임이 없으므로 페이지만 제거
		// 		hash_delete(&spt->spt_hash, &p->hash_elem);
		// 		free(p);
		// 	}
		// }
		// pml4_clear_page(thread_current()->pml4, p->va);
		addr += PGSIZE;
		p = spt_find_page(spt, addr);
	}
}
