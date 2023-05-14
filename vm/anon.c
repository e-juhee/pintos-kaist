/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
// 익명 페이지 하위 시스템을 초기화합니다.
// 이 함수에서는 익명 페이지와 관련된 모든 설정을 수행할 수 있습니다.
void vm_anon_init(void)
{
	/* TODO: Set up the swap_disk. */
	swap_disk = NULL;
}

/* Initialize the file mapping */
// 이 함수는 익명 페이지의 핸들러를 page->operations에 설정합니다.
// 현재는 빈 구조체인 anon_page에서 일부 정보를 업데이트해야 할 수도 있습니다.
// 이 함수는 익명 페이지(즉, VM_ANON)의 초기화 함수로 사용됩니다.
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in(struct page *page, void *kva)
{
	struct anon_page *anon_page = &page->anon;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
// 익명 페이지를 destroy합니다. PAGE는 호출자에 의해 해제될 것입니다
static void
anon_destroy(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
	// anonymous page에 의해 유지되던 리소스를 해제합니다.
	// page struct를 명시적으로 해제할 필요는 없으며, 호출자가 이를 수행해야 합니다.
}
