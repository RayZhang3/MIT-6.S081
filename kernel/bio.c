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
  uint globalticks;
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
    b->refcnt = 0;
    b->timestamp = 0;
    initsleeplock(&b->lock, "buffer");

    // Link buffer to the first bucket (bucket 0)
    b->next = bcache.buckets[0].next;
    bcache.buckets[0].next = b;
  }
}

void
updateTicks(struct buf* target) {
  //acquire(&tickslock);
  target->timestamp = ticks;
  //release(&tickslock);
}

// Look through buffer cache for block on device dev.
// If not found, allocate a buffer.
// In either case, return locked buffer.

static struct buf*
bget(uint dev, uint blockno)
{
  
  struct buf *b;
  int dstBUCKET = hash(blockno, dev);

  acquire(&bcache.bucketsLock[dstBUCKET]);

  // Is the block already cached?
  for(b = bcache.buckets[dstBUCKET].next; b; b = b->next){
    if(b->dev == dev && b->blockno == blockno){
      b->refcnt++;
      release(&bcache.bucketsLock[dstBUCKET]);
      acquiresleep(&b->lock);
      return b;
    }
  }
  release(&bcache.bucketsLock[dstBUCKET]);

  //If interrup: other process may add cache to dstBUCKET
  acquire(&bcache.lock);

  // check if the cache exist again, because we release the bucket lock and acquire global lock
  acquire(&bcache.bucketsLock[dstBUCKET]);

  for(b = bcache.buckets[dstBUCKET].next; b; b = b->next){
      if(b->dev == dev && b->blockno == blockno){
        b->refcnt++;
        release(&bcache.bucketsLock[dstBUCKET]);
        release(&bcache.lock);
        acquiresleep(&b->lock);
        return b;
      }
  }

  release(&bcache.bucketsLock[dstBUCKET]);

  // Not cached. holds the global lock
  // check all the bucket to find the LRU? No, we need to lock and unlock every bucket, it may lead to race.
  
  bcache.globalticks = ticks;

  //find the LRU cache
  struct buf *target;
  target = 0;
  int srcBUCKET = 0;
  
  for (b = bcache.buf; b < bcache.buf + NBUF; b++) {
    if (b->refcnt == 0 && b->timestamp <= bcache.globalticks) {
      target = b;
      if (b->timestamp == 0) {
        break;
      }
    }
  }

  // No free cache
  if (!target) {
    panic("bget: no buffers");
  } else {
    // Free cache found, find the src BUCKET
    if (target->timestamp == 0) {
      srcBUCKET = 0;
    } else {
      srcBUCKET = hash(target->blockno, target->dev);
    }

    if (dstBUCKET == srcBUCKET) {
      acquire(&bcache.bucketsLock[dstBUCKET]);
      b = target;
      b->dev = dev;
      b->blockno = blockno;
      b->valid = 0;
      b->refcnt = 1;
      release(&bcache.bucketsLock[dstBUCKET]);
      release(&bcache.lock);
      acquiresleep(&b->lock);
      return b;

    } else {
      acquire(&bcache.bucketsLock[srcBUCKET]);
      acquire(&bcache.bucketsLock[dstBUCKET]);
      //remove the target in src list
      for(b = &bcache.buckets[srcBUCKET]; b; b = b->next){
        if (b->next == target) {
          b->next = target->next;
        }
      }
      // add the target to dst list
      target->next = bcache.buckets[dstBUCKET].next;
      bcache.buckets[dstBUCKET].next = target;

      b = target;
      b->dev = dev;
      b->blockno = blockno;
      b->valid = 0;
      b->refcnt = 1;
      
      release(&bcache.bucketsLock[dstBUCKET]);
      release(&bcache.bucketsLock[srcBUCKET]);
      release(&bcache.lock);
      acquiresleep(&b->lock);
      
      return b;
    }
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
  releasesleep(&b->lock);
  int index = hash(b->blockno, b->dev);
  acquire(&bcache.bucketsLock[index]);
  b->refcnt--;
  if (!b->refcnt)
    updateTicks(b);
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


