#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "e1000_dev.h"
#include "net.h"

#define TX_RING_SIZE 16
static struct tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));
static struct mbuf *tx_mbufs[TX_RING_SIZE];

#define RX_RING_SIZE 16
static struct rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
static struct mbuf *rx_mbufs[RX_RING_SIZE];

// remember where the e1000's registers live.
static volatile uint32 *regs;

struct spinlock e1000_lock;

// called by pci_init().
// xregs is the memory address at which the
// e1000's registers are mapped.
void
e1000_init(uint32 *xregs)
{
  int i;

  initlock(&e1000_lock, "e1000");

  regs = xregs;

  // Reset the device
  regs[E1000_IMS] = 0; // disable interrupts
  regs[E1000_CTL] |= E1000_CTL_RST;
  regs[E1000_IMS] = 0; // redisable interrupts
  __sync_synchronize();

  // [E1000 14.5] Transmit initialization
  memset(tx_ring, 0, sizeof(tx_ring));
  for (i = 0; i < TX_RING_SIZE; i++) {
    tx_ring[i].status = E1000_TXD_STAT_DD;
    tx_mbufs[i] = 0;
  }
  regs[E1000_TDBAL] = (uint64) tx_ring;
  if(sizeof(tx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_TDLEN] = sizeof(tx_ring);
  regs[E1000_TDH] = regs[E1000_TDT] = 0;
  
  // [E1000 14.4] Receive initialization
  memset(rx_ring, 0, sizeof(rx_ring));
  for (i = 0; i < RX_RING_SIZE; i++) {
    rx_mbufs[i] = mbufalloc(0);
    if (!rx_mbufs[i])
      panic("e1000");
    rx_ring[i].addr = (uint64) rx_mbufs[i]->head;
  }
  regs[E1000_RDBAL] = (uint64) rx_ring;
  if(sizeof(rx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_RDH] = 0;
  regs[E1000_RDT] = RX_RING_SIZE - 1;
  regs[E1000_RDLEN] = sizeof(rx_ring);

  // filter by qemu's MAC address, 52:54:00:12:34:56
  regs[E1000_RA] = 0x12005452;
  regs[E1000_RA+1] = 0x5634 | (1<<31);
  // multicast table
  for (int i = 0; i < 4096/32; i++)
    regs[E1000_MTA + i] = 0;

  // transmitter control bits.
  regs[E1000_TCTL] = E1000_TCTL_EN |  // enable
    E1000_TCTL_PSP |                  // pad short packets
    (0x10 << E1000_TCTL_CT_SHIFT) |   // collision stuff
    (0x40 << E1000_TCTL_COLD_SHIFT);
  regs[E1000_TIPG] = 10 | (8<<10) | (6<<20); // inter-pkt gap

  // receiver control bits.
  regs[E1000_RCTL] = E1000_RCTL_EN | // enable receiver
    E1000_RCTL_BAM |                 // enable broadcast
    E1000_RCTL_SZ_2048 |             // 2048-byte rx buffers
    E1000_RCTL_SECRC;                // strip CRC
  
  // ask e1000 for receive interrupts.
  regs[E1000_RDTR] = 0; // interrupt after every received packet (no timer)
  regs[E1000_RADV] = 0; // interrupt after every packet (no timer)
  regs[E1000_IMS] = (1 << 7); // RXDW -- Receiver Descriptor Write Back
}

/*
First ask the E1000 for the TX ring index at which it's expecting the next packet, 
by reading the E1000_TDT control register.Then check if the the ring is overflowing. 

If E1000_TXD_STAT_DD is not set in the descriptor indexed by E1000_TDT, 
the E1000 hasn't finished the corresponding previous transmission request, so return an error.

Otherwise, use mbuffree() to free the last mbuf that was transmitted from that descriptor (if there was one).
Then fill in the descriptor. m->head points to the packet's content in memory, and m->len is the packet length. 
Set the necessary cmd flags (look at Section 3.3 in the E1000 manual) and stash away a pointer to the mbuf for later freeing.

Finally, update the ring position by adding one to E1000_TDT modulo TX_RING_SIZE.
If e1000_transmit() added the mbuf successfully to the ring, return 0. 
On failure (e.g., there is no descriptor available to transmit the mbuf), return -1 so that the caller knows to free the mbuf.
*/

int
e1000_transmit(struct mbuf *m)
{
  //
  // Your code here.
  //
  // the mbuf contains an ethernet frame; program it into
  // the TX descriptor ring so that the e1000 sends it. Stash
  // a pointer so that it can be freed after sending.
  //
  acquire(&e1000_lock);
  //This register contains the tail pointer for the transmit descriptor ring.  
  //It holds a value that is an offset from the base, and indicates the location beyond the last descriptor hardware can process.
  //This is the location where software writes the first new descriptor.  
  //It points to a 16-byte datum.  Software writes the tail pointer to add more descriptors to the transmit ready queue.  
  //Hardware attempts to transmit all packets referenced by descriptors between head and tail.
  uint32 p_tail = regs[E1000_TDT];
  struct tx_desc* tail_desc = &tx_ring[p_tail];
  //Descriptor Done
  //Indicates that the descriptor is finished and is written back either after the descriptor 
  //has been processed 
  if (!(tail_desc->status && E1000_TXD_STAT_DD)) {
    release(&e1000_lock);
    printf("the ring is overflowing");
    return -1;
  }
  if (tx_mbufs[p_tail]){
    mbuffree(tx_mbufs[p_tail]);
  }
  // Fill in the descriptor. 
  // m->head points to the packet's content in memory, m->len is the packet length. 
  // Set the necessary cmd flags and stash away a pointer to the mbuf for later freeing.
  tail_desc->addr = (uint64)m->head;
  tail_desc->length = (uint16)m->len;
  // EOP: End Of Packet, When set, indicates the last descriptor making up the packet.
  // RS: Report Status, When set, the Ethernet controller needs to report the status information 
  tail_desc->cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS;
  tx_mbufs[p_tail] = m;
  //update the ring position by adding one to E1000_TDT modulo TX_RING_SIZE.
  //If e1000_transmit() added the mbuf successfully to the ring, return 0. 
  regs[E1000_TDT] = (p_tail + 1) % TX_RING_SIZE;
  release(&e1000_lock);
  return 0;
}
/*
First ask the E1000 for the ring index at which the next waiting received packet (if any) is located, 
by fetching the E1000_RDT control register and adding one modulo RX_RING_SIZE.

Then check if a new packet is available by checking for the E1000_RXD_STAT_DD bit in the status portion of the descriptor. 
If not, stop.
Otherwise, update the mbuf's m->len to the length reported in the descriptor. 
Deliver the mbuf to the network stack using net_rx().

Then allocate a new mbuf using mbufalloc() to replace the one just given to net_rx(). 
Program its data pointer (m->head) into the descriptor. Clear the descriptor's status bits to zero.

Finally, update the E1000_RDT register to be the index of the last ring descriptor processed.
e1000_init() initializes the RX ring with mbufs, and you'll want to look at how it does that and perhaps borrow code.
At some point the total number of packets that have ever arrived will exceed the ring size (16); make sure your code can handle that.
*/

static void
e1000_recv(void)
{
    uint32 p_tail = (regs[E1000_RDT] + 1) % RX_RING_SIZE; /* RX Descriptor Tail - RW */
    struct rx_desc* tail_desc = &rx_ring[p_tail];
    // Check if a new packet is available by checking for the E1000_RXD_STAT_DD bit in the status 
    // portion of the descriptor. If not, stop.
    while (tail_desc->status & E1000_RXD_STAT_DD) {
      //Otherwise, update the mbuf's m->len to the length reported in the descriptor. 
      //Deliver the mbuf to the network stack using net_rx().
      rx_mbufs[p_tail]->len = tail_desc->length;
      net_rx(rx_mbufs[p_tail]);
      //Then allocate a new mbuf using mbufalloc() to replace the one just given to net_rx(). 
      //Program its data pointer (m->head) into the descriptor. Clear the descriptor's status bits to zero.
      rx_mbufs[p_tail] = mbufalloc(0);
      tail_desc->addr = (uint64)rx_mbufs[p_tail]->head;
      tail_desc->status = 0;
      //Finally, update the E1000_RDT register to be the index of the last ring descriptor processed.
      regs[E1000_RDT] = p_tail;
      p_tail = (regs[E1000_RDT] + 1) % RX_RING_SIZE;
      tail_desc = &rx_ring[p_tail];
    }
  //
  // Your code here.
  //
  // Check for packets that have arrived from the e1000
  // Create and deliver an mbuf for each packet (using net_rx()).
  //
}

void
e1000_intr(void)
{
  // tell the e1000 we've seen this interrupt;
  // without this the e1000 won't raise any
  // further interrupts.
  regs[E1000_ICR] = 0xffffffff;

  e1000_recv();
}
