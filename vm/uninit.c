/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"

static bool uninit_initialize(struct page *page, void *kva);
static void uninit_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void uninit_new(struct page *page, void *va, vm_initializer *init,
				enum vm_type type, void *aux,
				bool (*initializer)(struct page *, enum vm_type, void *))
{
	ASSERT(page != NULL);

	*page = (struct page){
		.operations = &uninit_ops, // operations->swap_in : uninit_initialize
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page){
			.init = init, // lazy_load_segment
			.type = type,
			.aux = aux,
			.page_initializer = initializer, // anon_initializer | file_backed_initializer
		}};
}

/* Initalize the page on first fault */
// 첫 번째 페이지 폴트 시 페이지를 초기화합니다.
static bool
uninit_initialize(struct page *page, void *kva)
{
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	// page_initializer 함수가 값을 덮어쓸 수 있으므로 이전에 가져온 값들을 먼저 저장해야 한다
	vm_initializer *init = uninit->init; // lazy_load_segment
	void *aux = uninit->aux;			 // lazy_load_arg

	/* TODO: You may need to fix this function. */
	return uninit->page_initializer(page, uninit->type, kva) &&
		   (init ? init(page, aux) : true);
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
// uninit_page가 유지하고 있는 리소스를 해제합니다.
// 대부분의 페이지는 다른 페이지 객체로 변환되지만,
// 프로세스가 종료될 때 실행 중에 참조되지 않은 초기화되지 않은 페이지(uninit pages)가 존재할 수 있습니다.
// PAGE는 호출자에 의해 해제될 것입니다.
static void
uninit_destroy(struct page *page)
{
	struct uninit_page *uninit UNUSED = &page->uninit;
	/* TODO: Fill this function.
	 * TODO: If you don't have anything to do, just return. */
	// page struct에 의해 유지되고 있던 리소스를 해제합니다.
	// 페이지의 vm 유형을 확인하고 그에 맞게 처리하는 것이 좋습니다.
}
