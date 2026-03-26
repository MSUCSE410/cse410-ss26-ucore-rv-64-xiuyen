#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

/*
 * Task 1: Fix sys_gettimeofday for virtual memory.
 * The user passes a virtual address (val is a VA in user space).
 * We must build the TimeVal on the kernel stack, then copyout to user space.
 */
uint64 sys_gettimeofday(uint64 val_va, int _tz)
{
	struct proc *p = curr_proc();
	TimeVal tv;
	uint64 cycle = get_cycle();
	tv.sec = cycle / CPU_FREQ;
	tv.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	if (copyout(p->pagetable, val_va, (char *)&tv, sizeof(tv)) < 0)
		return -1;
	return 0;
}

/*
 * Task 1: Fix sys_task_info for virtual memory.
 * Same idea — build TaskInfo on kernel stack, copyout to user VA.
 */
uint64 sys_task_info(uint64 ti_va)
{
	struct proc *p = curr_proc();
	struct TaskInfo ti;
	ti.status = Running;
	memmove(ti.syscall_times, p->syscall_times, sizeof(p->syscall_times));
	ti.time = get_time_ms() - p->start_time;
	if (copyout(p->pagetable, ti_va, (char *)&ti, sizeof(ti)) < 0)
		return -1;
	return 0;
}

/*
 * Task 2: sys_mmap — anonymous mapping.
 *
 * Allocate physical pages and map them into the process's page table
 * at virtual address [start, start + len).
 *
 * port bits: 0=R, 1=W, 2=X
 * PTE bits:  PTE_R=bit1, PTE_W=bit2, PTE_X=bit3, PTE_U=bit4
 * So we shift port left by 1 to convert to PTE R/W/X flags, then add PTE_U.
 */
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
	// len == 0: return success immediately
	if (len == 0)
		return 0;

	// start must be page-aligned
	if (start % PGSIZE != 0)
		return -1;

	// port validation: other bits besides lower 3 must be 0
	if ((port & ~0x7) != 0)
		return -1;

	// port must have at least one of R/W/X set
	if ((port & 0x7) == 0)
		return -1;

	// len upper limit: 1 GiB
	if (len > 1024ULL * 1024 * 1024)
		return -1;

	// Round len up to page boundary
	uint64 len_aligned = PGROUNDUP(len);

	struct proc *p = curr_proc();

	// Check that no pages in [start, start + len_aligned) are already mapped
	for (uint64 va = start; va < start + len_aligned; va += PGSIZE) {
		pte_t *pte = walk(p->pagetable, va, 0);
		if (pte != 0 && (*pte & PTE_V) != 0) {
			return -1; // already mapped
		}
	}

	// Convert port to PTE permission flags
	// port bit 0 (R) -> PTE_R (bit 1)
	// port bit 1 (W) -> PTE_W (bit 2)
	// port bit 2 (X) -> PTE_X (bit 3)
	int perm = ((port & 0x7) << 1) | PTE_U;

	// Map page by page (kalloc doesn't give contiguous pages)
	for (uint64 va = start; va < start + len_aligned; va += PGSIZE) {
		void *pa = kalloc();
		if (pa == 0)
			return -1; // out of memory (no rollback per spec)
		memset(pa, 0, PGSIZE);
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) != 0) {
			kfree(pa);
			return -1;
		}
	}
	return 0;
}

/*
 * Task 2: sys_munmap — unmap virtual memory.
 *
 * Verify all pages in [start, start + len) are currently mapped,
 * then unmap and free them.
 */
uint64 sys_munmap(uint64 start, uint64 len)
{
	if (len == 0)
		return 0;

	// start must be page-aligned
	if (start % PGSIZE != 0)
		return -1;

	uint64 len_aligned = PGROUNDUP(len);
	struct proc *p = curr_proc();

	// Verify all pages are mapped
	for (uint64 va = start; va < start + len_aligned; va += PGSIZE) {
		pte_t *pte = walk(p->pagetable, va, 0);
		if (pte == 0 || (*pte & PTE_V) == 0) {
			return -1; // unmapped page found in range
		}
	}

	// Unmap and free physical pages
	uint64 npages = len_aligned / PGSIZE;
	uvmunmap(p->pagetable, start, npages, 1);
	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: update syscall counter for task info
	*/
	struct proc *p = curr_proc();
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		p->syscall_times[id]++;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_task_info:
		ret = sys_task_info(args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}