#ifndef THREADS_VADDR_H
#define THREADS_VADDR_H

#include <debug.h>
#include <stdint.h>
#include <stdbool.h>

#include "threads/loader.h"

/* Functions and macros for working with virtual addresses.
 *
 * See pte.h for functions and macros specifically for x86
 * hardware page tables. */

#define BITMASK(SHIFT, CNT) (((1ul << (CNT)) - 1) << (SHIFT))

/* Page offset (bits 0:12). */
#define PGSHIFT 0 /* Index of first offset bit. */					   // virtual address의 offset 파트의 비트 index
#define PGBITS 12 /* Number of offset bits. */						   // virtual address의 offset 파트의 비트 수
#define PGSIZE (1 << PGBITS) /* Bytes in a page. */					   // 페이지 크기(4096bytes)
#define PGMASK BITMASK(PGSHIFT, PGBITS) /* Page offset bits (0:12). */ // 페이지 오프셋의 비트가 1로 설정되고 나머지 비트가 0(0xfff)으로 설정된 비트 마스크

/* Offset within a page. */
#define pg_ofs(va) ((uint64_t)(va)&PGMASK) // va의 page offset

#define pg_no(va) ((uint64_t)(va) >> PGBITS) // va의 page number

/* Round up to nearest page boundary. */
#define pg_round_up(va) ((void *)(((uint64_t)(va) + PGSIZE - 1) & ~PGMASK)) // va를 페이지 경계에 가장 가까운 상위 페이지 경계로 올림(round up)한 값을 반환하는 함수

/* Round down to nearest page boundary. */
#define pg_round_down(va) (void *)((uint64_t)(va) & ~PGMASK) // va가 속한 페이지의 시작 위치, 즉 페이지 오프셋이 0인 가상 페이지의 시작 주소를 반환하는 함수

/* Kernel virtual address start */
#define KERN_BASE LOADER_KERN_BASE // 커널 가상 메모리의 기본 시작 주소

/* User stack start */
#define USER_STACK 0x47480000

/* Returns true if VADDR is a user virtual address. */
#define is_user_vaddr(vaddr) (!is_kernel_vaddr((vaddr)))

/* Returns true if VADDR is a kernel virtual address. */
#define is_kernel_vaddr(vaddr) ((uint64_t)(vaddr) >= KERN_BASE)

// FIXME: add checking
/* Returns kernel virtual address at which physical address PADDR
 *  is mapped. */
#define ptov(paddr) ((void *)(((uint64_t)paddr) + KERN_BASE))

/* Returns physical address at which kernel virtual address VADDR
 * is mapped. */
#define vtop(vaddr)                                \
	({                                             \
		ASSERT(is_kernel_vaddr(vaddr));            \
		((uint64_t)(vaddr) - (uint64_t)KERN_BASE); \
	})

#endif /* threads/vaddr.h */
