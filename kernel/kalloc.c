// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

struct run {
  struct run *next;
};

struct kmemperCPU{
  struct spinlock lock;
  struct run *freelist;
}kmem[NCPU];

int getCPU() {
  push_off(); // turn interrupt off
  int cpu = cpuid();
  pop_off(); // turn interrupt on
  return cpu;
}

int getIndex(uint64 pa) {
  uint64 step = (PHYSTOP - PGROUNDUP((uint64)end)) / NCPU;
  int index = (pa - PGROUNDUP((uint64)end)) / step;
  return index;
}

void
kinit()
{
  uint64 step = (PHYSTOP - PGROUNDUP((uint64)end)) / NCPU;
  uint64 start = PGROUNDUP((uint64)end);
  for (int i = 0; i < NCPU; i++) {
    initlock(&kmem[i].lock, "kmem");
    uint64 rangeStart =  PGROUNDUP((start + step*i));
    uint64 rangeEnd =  start + step*(i+1);
    if (rangeEnd > PHYSTOP) {
      rangeEnd = PHYSTOP;
    }
    freerange((void*)rangeStart, (void*)rangeEnd);
  }
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kfree(p);
}

// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;
  // lab code start 
  int index = getIndex((uint64)pa);

  acquire(&kmem[index].lock);
  r->next = kmem[index].freelist;
  kmem[index].freelist = r;
  release(&kmem[index].lock);

}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  push_off();
  struct run *r;
  int current_CPU = cpuid();
  acquire(&kmem[current_CPU].lock);
  r = kmem[current_CPU].freelist;

  if (r == 0) {
    for (int i = 0; i < NCPU; i ++) {
      if (i == current_CPU) {
        continue;
      }
      acquire(&kmem[i].lock);
      struct run *start = kmem[i].freelist;
      if (start) {
        struct run *end = start;
        int count = 0;
        while (count < 64 && end->next != 0) {
          end = end->next;
          count ++;
        }
        kmem[i].freelist = end->next;
        end->next = kmem[current_CPU].freelist;
        kmem[current_CPU].freelist = start;
        r = start;
      }
      release(&kmem[i].lock);
      if (r) {
        break;
      }
    }    
  }

  if (r) {
    kmem[current_CPU].freelist = r->next;
    release(&kmem[current_CPU].lock);
    memset((char*)r, 5, PGSIZE); // fill with junk
    pop_off();
    return (void*)r;
  } else {
    release(&kmem[current_CPU].lock);
    pop_off();
    return 0;
  }
}
