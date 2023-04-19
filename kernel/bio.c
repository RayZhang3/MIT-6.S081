// Buffer cache.
//
// The buffer cache is a linked list of buf structures holding
// cached copies of disk block contents.  Caching disk blocks
// in memory reduces the number of disk reads and also provides
// a synchronization point for disk blocks used by multiple processes.
//
// Interface:
// * To get a buffer for a particular disk block, call bread.
// * After changing buffer data, call bwrite to write it to disk.
// * When done with the buffer, call brelse.
// * Do not use the buffer after calling brelse.
// * Only one process at a time can use a buffer,
//     so do not keep them longer than necessary.

#include "types.h"
#include "param.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "riscv.h"
#include "defs.h"
#include "fs.h"
#include "buf.h"

#define NBUCKETS 13
#define hash(blockno, dev) (((uint64)blockno << 32 | dev) % NBUCKETS)
char* lockName[13] = {
  "bcacheLock0",
  "bcacheLock1",
  "bcacheLock2",
  "bcacheLock3",
  "bcacheLock4",
  "bcacheLock5",
  "bcacheLock6",
  "bcacheLock7",
  "bcacheLock8",
  "bcacheLock9",
  "bcacheLock10",
  "bcacheLock11",
  "bcacheLock12"
};

struct {
  struct spinlock lock;

  // Linked list of all buffers, through prev/next.
  // Sorted by how recently the buffer was used.
  // head.next is most recent, head.prev is least.
  struct buf buckets[NBUCKETS];
  struct buf buf[NBUF];
  struct spinlock bucketsLock[NBUCKETS];
} bcache;

void
binit(void)
{
  struct buf *b;
  initlock(&bcache.lock, "bcache");
  // create buckets and locks
  for (int i = 0; i < NBUCKETS; i++){
    initlock(&bcache.bucketsLock[i], lockName[i]);
    b = &bcache.buckets[i];
    b->valid = 0;
  }
  // initiate all the bcache, store in BUCKET 0
  for(b = bcache.buf; b < bcache.buf + NBUF; b++){
    b->next = bcache.buckets[0].next;
    b->refcnt = 0;
    bcache.buckets[0].next = b;
    initsleeplock(&b->lock, "buffer");
  }
}

void
updateTicks(struct buf* target) {
  acquire(&tickslock);
  target->timestamp = ticks;
  release(&tickslock);
}

// Look through buffer cache for block on device dev.
// If not found, allocate a buffer.
// In either case, return locked buffer.
int debug = 0;

static struct buf*
bget(uint dev, uint blockno)
{
  struct buf *b;
  acquire(&bcache.lock); // need to remove it
  if (debug) {
    printf("acquire bcache lock\n");
  }
  int index = hash(blockno, dev);
  if (debug) {
      printf("acquire bucket lock%d\n", index);
  }
  acquire(&bcache.bucketsLock[index]);
  // Is the block already cached?
  for(b = bcache.buckets[index].next; b; b = b->next){
    if(b->dev == dev && b->blockno == blockno){
      b->refcnt++;
      if (debug) {
        printf("release bcache lock\n");
      }
      if (debug) {
        printf("release bucket lock%d\n", index);
      }
      release(&bcache.bucketsLock[index]);
      release(&bcache.lock);
      acquiresleep(&b->lock);
      return b;
    }
  }


  // Not cached.
  // check all the bucket to find the LRU
  uint globalticks;
  acquire(&tickslock);
  globalticks = ticks;
  release(&tickslock);

  struct buf *target;
  target = 0;
  int srcBUCKET = 0;
  int dstBUCKET = hash(blockno, dev);
  for (int i = 0; i < NBUCKETS; i++) {
    for(b = bcache.buckets[i].next; b ; b = b->next){
      if (b->timestamp <= globalticks && b->refcnt == 0) {
        target = b;
        globalticks = b->timestamp;
        srcBUCKET = i;
      }
    }
  }
  if (debug) {
      printf("the target is %p, globalticks: %d\n", target, globalticks);
  }
  if (!target) {
    panic("bget: no buffers");
  } else {
    if (debug) {
        printf("the target is %p, src: %d -> dst: %d\n", target, srcBUCKET, dstBUCKET);
    }
    //evict b and insert b
    if (srcBUCKET != dstBUCKET) {
      for (b = &bcache.buckets[srcBUCKET]; b ; b = b->next) {
        if (b->next == target) {
          if (debug) {
            printf("evict %p, src: %d -> dst: %d\n", target, srcBUCKET, dstBUCKET);
          }
          b->next = target->next;
        }
      }
      //insert b
      target->next = bcache.buckets[dstBUCKET].next;
      bcache.buckets[dstBUCKET].next = target;
      if (debug) {
            printf("insert %p, src: %d -> dst: %d\n", target, srcBUCKET, dstBUCKET);
      }
    }
      b = target;
      b->dev = dev;
      b->blockno = blockno;
      b->valid = 0;
      b->refcnt = 1;
      updateTicks(b);
      if (debug) {
        printf("acquire buffer %p sleep lock\n", b);
      }
      acquiresleep(&b->lock);
      if (debug) {
        printf("release bucket lock%d\n", index);
      }
      release(&bcache.bucketsLock[index]);
      if (debug) {
        printf("release bcache lock\n");
      }
      release(&bcache.lock);
      return b;
  }

}


// Return a locked buf with the contents of the indicated block.
struct buf*
bread(uint dev, uint blockno)
{
  struct buf *b;

  b = bget(dev, blockno);
  if(!b->valid) {
    virtio_disk_rw(b, 0);
    b->valid = 1;
  }
  return b;
}

// Write b's contents to disk.  Must be locked.
void
bwrite(struct buf *b)
{
  if(!holdingsleep(&b->lock))
    panic("bwrite");
  virtio_disk_rw(b, 1);
}

// Release a locked buffer.
// Move to the head of the most-recently-used list.
void
brelse(struct buf *b)
{
  if(!holdingsleep(&b->lock))
    panic("brelse");
  if (debug) {
    printf("release buffer %p sleep lock\n", b);
  }
  releasesleep(&b->lock);
  int index = hash(b->blockno, b->dev);
  acquire(&bcache.bucketsLock[index]);
  updateTicks(b);
  b->refcnt--;
  release(&bcache.bucketsLock[index]);
}

void
bpin(struct buf *b) {
  int index = hash(b->blockno, b->dev);
  acquire(&bcache.bucketsLock[index]);
  b->refcnt++;
  release(&bcache.bucketsLock[index]);
}

void
bunpin(struct buf *b) {
  int index = hash(b->blockno, b->dev);
  acquire(&bcache.bucketsLock[index]);
  b->refcnt--;
  release(&bcache.bucketsLock[index]);
}


