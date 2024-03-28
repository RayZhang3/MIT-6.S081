# 总览
Lab及对应的Branch
| Lab Feature                | Branch          | Description                                                                                     |
|-----------------------|---------------------|------------------------------------------------------------------------------------------------|
| Xv6 and Unix utilities | util      | 实现几个用户态程序、unix实用工具，包括pingpong, 用多线程实现并行化的素数筛                        |
| system calls          | syscall     | 添加syscall系统追踪，sysinfo系统调用                                                           |
| page tables           | pgtbl | 理解进程页表、内核页表概念，为每个进程维护独立的内核态页表，加速copyin, copyout的过程，允许内核态解引用用户态的指针                     |
| traps                 | traps  | 中断、中断处理机制(trap, trampoline, 函数调用、现场保存、页表/特权切换、调用栈、栈指针、返回指针)   |
| lazy page allocation  | lazy     | lazy-allocation，内存懒分配，调用sbrk()时不立即分配内存，只作记录，在访问到这一部分内存也并触发缺页异常时才进行实际的物理内存分配。|
| copy-on-Write Fork    | cow            | 写时复制的fork, 在进程fork后与父进程共享进程页，仅当其中一方尝试对内存页进行修改时才对内存也进行复制。|
| multithreading        | THREAD        | 实现简单的用户态线程库，尝试使用线程为程序提速。                                                |
| locks                 | lock   | 降低锁竞争，提高多核系统的性能。包括并发的内存分配、物理缓存页管理。                    |
| file system           | fs | 为xv6的文件系统添加多级索引以及符号链接的支持。                                                  |
| mmap                  | mmap  | unix调用mmap的简单版本，支持将文件映射到一片用户虚拟内存区域内，并支持将对其的修改写回磁盘。         |
| networking            | net         | 熟悉系统驱动与外围设备的交互、内存映射寄存器与DMA数据传输，实现与E1000网卡交互的核心方法：transmit和recv. |

# Lab 1. Xv6 and Unix utilities
### 相关知识
1. 管道(pipe): pipe是单向的，数据只能往一个方向流动，每个管道有一个相关联的内核缓冲区，暂时存储写入管道的数据。可以通过创建两个管道实现双向通信。
### 素数筛实现
1. 素数筛使用了多进程和管道的原理，sieve()函数的功能是，每个stage筛选掉某个素数的所有倍数，每次调用时，会首先从之前的sieve()进程中读取首个数（素数，因为没有被任何比它小的数筛掉），随后创建一个子进程，并在筛掉所有该素数的倍数后将剩下的数传给下个stage，在最后一个stage完成后，依次退出各个进程（例如，原函数是实现了35以内的素数筛，最后写入一个-1，当读取到-1时子进程通过break退出while循环，不再等待读取）。
2. 难点：xv6每个进程能打开的文件描述符是有16个的上限，每个管道会占用两个，并且fork之后会复制父进程的文件描述符，因此在fork之前需要及时关闭不需要使用的文件描述符。
3. 解决方法：
	1. 首先是使管道变成只读/只写，每个进程只需要从左侧读取数据并写到右侧。因此左侧的进程只需要保留写入端，右侧的进程只需要保留读取端。
	2. fork时，父进程与祖父进程之间的文件描述符也会复制，因此需要关闭子进程和祖父进程之间的文件描述符。、

### 简单的find()实现
1. Goal: Write a simple version of the UNIX find program: find all the files in a directory tree with a ==specific name.==
   find接收两个参数，path和target，void find(char *path, char* target)，在该文件夹及子文件夹中递归地搜索同名文件。
2. 要点：
	1. 根据文件的类型，T_FILE是普通文件，判断文件名即可，T_DIR是目录文件，需要使用read读取对应文件的inum和filename，随后比较filename
	2. 及时关闭文件描述符
	3. 在目录中递归查找时忽略. 和..

### 简单的xargs()实现
1. 先从命令行参数中读取参数，(argv[0]是xargs，忽略，args[1]是目标程序)，随后从标准输入中逐行读取参数，并将这些数据整理成命令行参数的格式，通过fork创建子进程，并在子进程中通过系统调用exec(argv[1], cmdbuf) 使用参数执行目标程序。

# Lab 2. System calls
修改了 
Makefile
kernel/kalloc.c, proc.c, proc.h, syscall.c, syscall.h. 
user/user.h, usys.pl
### 创建系统调用
1. ==在内核映像(/kernel下)中实现系统调用==
2. ==在syscall.h中添加系统调用号==
3. ==在系统调用表的最后加入一个表项==，extern 全局声明新的内核调用函数，syscalls映射表中，加入系统调用号到系统调用函数指针的映射。
4. ==在用户空间下添加访问系统调用的方式== （内联汇编的C函数，通过汇编代码直接访问寄存器）
   通过在脚本文件usys.pl 中，加入内核态到用户态的跳板函数，随后脚本文件会生成usys.S汇编文件，自动生成相应的汇编代码，sleep的用户态跳板函数的汇编代码如下。先将系统调用号放置到a7中，随后调用ecall。
``` usys.S中的汇编代码，用户态调用时，将指定的系统调用号写入到a7寄存器中，随后执行ecall
.global sleep
sleep:
 li a7, SYS_sleep
 ecall
 ret   
```
5. 在用户态的头文件中加入定义，使用户态程序找到跳板入口函数。

### 系统调用流程
1. user/user.h 用户态程序调用跳板函数sleep()
2. user/usys.S 跳板函数sleep()先将对应的系统调用号压入指定的寄存器中，执行ecall指令跳转到内核态
3. kernel/syscall.c 到达内核态系统调用处理函数syscall()
4. kernel/syscall.c syscall()从trapframe中读取对应的系统调用号，查询syscalls[]表，调用对应的内核函数
5. 到达sys_sleep()函数，执行内核操作。

### 系统调用流程繁琐的原因
1. 由于页表不同，内核页表不含用户页表项，指针也不能互通访问，内核不能通过用户态传进来的指针进行解引用，用户地址无效。需要通过copyin, copyout方法结合进程的页表，才能找到用户态指针（逻辑地址）对应的物理内存地址。
2. 用户空间的程序不能调用内核空间中的函数，因为内核驻留在受保护的地址空间上。

### Linux中的相关知识
1. Linux中对应copy_from_user和copy_to_user函数，用于在内核空间和用户空间之间安全的复制数据，使内核可以读取或写入用户空间的数据。copy_from_user和copy_to_user包含了指针的合法性检查，包括指针指向的内存区域是否属于用户空间、属于该进程、读写属性等。可能引起阻塞，当包含用户数据的页被置换到磁盘中时，进程休眠，直到缺页处理程序完成后继续执行。
2. 与xv6类似，Linux系统调用在内核态下的返回值是long类型，在用户空间为int类型，这是为了兼容32位和64位的系统。在64位系统下，系统调用可能需要返回更大的数值，例如文件字节数等，超过了32位能表示的范围，因此使用long类型，而使用long类型并不影响32位系统，因为32位系统中，long和int类型都是32位的。
3. 与xv6类似，Linux系统系统调用的执行过程是：用户程序触发一个软中断（陷阱）进入内核模式，内核查看用户程序传入的系统调用号和参数，执行相关的系统调用，随后返回到用户模式。主要的差异如下： 
	1. xv6使用简单的方式处理中断和陷阱：发生系统调用时，直接跳转到固定的地址开始执行代码(TODO)。xv6只支持单处理器。xv6系统调用的系统调用号和参数是通过寄存器传递的。在risc-V中，系统调用号通过a7传递，参数通过a0-a5传递，系统调用出错或正常返回后，会将返回值写入trapframe中的a0。（trapframe这个结构体是在中断或异常发生时，由硬件和操作系统内核一起建立的，保存了中断或异常发生时CPU的所有寄存器状态，中断或异常处理完毕后，就可以恢复到trapframe的状态了，使程序继续运行）。
	2. Linux([Linux内核设计与实现 P60])：x86中，系统调用号通过eax传递给内核，并在ebx,ecx,edx,esi,edi存放前五个参数，也可以通过指针传递，但需要一个单独的寄存器指向存放所有参数的指针（在用户空间）。给用户的返回值页放置在eax中。在Linux中，线程上下文被保存在pt_regs中，中断、异常发生时也会保存线程上下文到结构中。

### sys_trace()系统调用的实现
1. 在进程控制块中添加需要追踪的系统调用信息，这里使用bit实现。
2. 在syscall()中根据系统调用号打印对应的进程标识值(pid)、系统调用名(a7)和参数(a0)。
```C
void
syscall(void)
{
  int num;
  struct proc *p = myproc();

  num = p->trapframe->a7;
  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    p->trapframe->a0 = syscalls[num]();

    //print trace info
    if (p->traceId & 1 << (num)) {
      char* sysCallName = syscall_name(num);
      printf("%d: syscall %s -> %d\n", p->pid, sysCallName, p->trapframe->a0);
    }
    //
  } else {
    printf("%d %s: unknown sys call %d\n",
            p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
```

### sys_sysinfo()系统调用的实现
1. 目的：添加系统调用，返回空闲内存、以及创建的进程数量。
2. xv6的空闲内存页记录方式是：将空闲内存页本身直接用做链表节点，形成空闲页链表，每当需要分配时，就把链表头部的页分配出去，每次需要回收，就在头部加入新的空闲页。(kalloc()将返回空闲页链表的头部节点)。
3. 常见记录空间页的方法有：空闲表法、空闲链表法、位图、成组链接法等等。
4. 获取空闲内存数：统计空闲页链表长度，需要持有锁。
5. 获取运行的进程数：在进程列表中统计所有非UNUSED状态的进程。
6. sysinfo()：内核态下从trapframe中获取struct sysinfo的地址，在内核态下获取空闲内存数和运行中的进程数，初始化结构体并调用copy_out函数，根据用户态进程的页表和指针（虚拟地址），找到物理地址，将结构体深拷贝到对应的物理地址供用户进程使用。
```c 
// 系统调用
uint64
sys_sysinfo(void)
{
  uint64 mem = freeMem();
  uint64 nproc = numProcess();
  uint64 addr;
  struct sysinfo info = {
    mem,nproc
  };
  if (argaddr(0, &addr) < 0)
    return -1;
  if (copyout(myproc()->pagetable, addr, (char*) &info, sizeof(info)) < 0)
    return -1;
  return 0;
}
```

# Lab 3. Page tables 页表
### 目标
1. xv6原本的设计是，用户进程在用户态使用各自的用户态页表，在进入到内核态时，切换到内核页表（通过在trampoline.S中修改satp(Supervisor Address Translation and Protection Register寄存器），然而该内核态页表是全局共享的。
2. ==Lab目标==：每一个==进程进入到内核态后，都拥有自己的独立内核态页表==，并在此基础上，在内核态页表中维护一个用户态页表的映射，==允许内核解引用用户指针==。（虚拟地址）
3. 优势：原本的copyin是通过软件模拟访问页表的过程进行地址转换的，现在我们在内核态页表维护映射副本，可以利用CPU的硬件寻址功能直接进行寻址。

### 相关知识
1. RISC-V的寻址方式：三级页表 9+9+9+12bit页内偏移(4kb)
2. xv6原本的设计中，内核页表只有一个，所有处于内核态的进程共享同一个页表（共享页表=共享同一个地址空间），由于xv6支持多核/多进程调度，同一时间内可能有多个进程处于内核态，因此需要对所有处于内核态的进程创建其独立的内核栈，供内核代码运行使用。
3. xv6启动过程中，会为所有的进程为预分配好内核栈kstack，在高地址空间内，每个进程使用一个页作为kstack，每两个不同的kstack之间隔着一个guard page用于检测溢出错误。
4. 页表项的标志位pte, 页表项指向更低一级页表时：PTE_V && !(PTE_R || PTE_W_ || PTE_X)
5. 页表中硬件设备的地址映射（MMIO(将硬件设备的寄存器映射到CPU的地址空间)的页表项有）：
	1. UART：串行通信接口，用于异步串行通信
	2. VIRTTIO：标准化设备虚拟化方法，让宿主机和虚拟机访问更加高效
	3. CLINT(Core local interrupt): RISC-V中，用于时钟中断和软件中断
	4. PLIC(Platform-Level Interrupt Controller)：平台级中断控制器，处理外部设备中断。
6. xv6的内核态地址空间和物理地址空间
   ![](images/mit6s081-lab3-figure-3-3.png)
   物理地址高于0x80000000会走向DRAM芯片
   物理地址低于0x80000000会走向不同的I/O设备
    ^be0680
7. 用户态地址空间 ![|650](images/user_memory_space.png)
### 实现（Exercise 2 进程独立的内核页表）
1. 进程控制块中添加新的内核态页表, 内核栈p->kStack已经有了
2. 内核栈：由于每个进程有了自己的独立内核页表，地址空间是部分独立的，因此，现在应该把所有进程的内核栈map到各自内核页表的固定位置，指向不同的物理内存。
3. 初始化进程时，初始化进程页表，添加内核页表项，分配内核栈空间(补充这些信息)
4. 添加虚拟地址到物理地址的映射函数
5. 调度器在将CPU交给进程之前，需要切换进程页表(w_satp(p->kernelpgtbl))，flush TLB。 进程执行一段时间后，将CPU重新交给调度器时，应重新切换回全局内核页表(调度器使用的)，同样flush TLB。
6. 添加释放进程内核页表、内核栈的代码，在进程结束后调用，避免内存泄漏。

### 实现（Exercise 3 内核态页表维护用户态页表映射副本）
1. 需要在内核对用户页表进行修改时，将同样的修改也同步到内核页表上。
2. 使得两个页表的程序段（0 到 PLIC 段）地址空间的映射同步.
3. 添加拷贝用户页表映射关系到内核页表的函数(逐页进行，先walk再mappages)，添加增减程序内存(p->sz)的函数
4. 内核页表中存在CLINT的地址映射，因此可能与用户页表项冲突。
5. 在exec中加入检查，防止程序大小超过PLIC映射的虚拟空间地址
6. 同步映射：fork()复制页表, exec()切换页表, growproc()用户页表映射增减,  userinit()，init进程是由userinit()创建的，而不是fork来的 
7. 实现copyin_new(先判断copy内存后是否p->sz，调用memmove()), copyinstr(拷贝字符串)


# Lab 4 traps
### 相关知识
1. Risc-V和x86对比？
	1. RISC-V是精简指令集，x86是复杂指令集。
	2. RISC-V的指令更加简单，x86的很多指令执行了一系列复杂操作。
	3. RISC-V是开源的
2. 程序需要在内核空间和用户空间之间切换
	1. 程序执行系统调用
	2. 程序出现page fault，运算除以0之类的错误
	3. 设备触发中断，当前程序运行需要响应内核设备驱动
3.  RISC-V寄存器：
	1. 32个用户寄存器(包括stack pointer )
	2. 程序计数器PC
	3. 表明当前mode的标志位(supervisor mode/ user mode), 
	4. SATP: 包含指向pagetable的物理地址
	5. STVEC: 指向内存中处理trap的起始地址
	6. SEPC: 在trap过程中保存pc的值
4. trap过程需要的操作
	1. 保存用户寄存器和程序计数器
	2. 修改cpu mode
	3. 使satp指向内核页表
	4. 堆栈寄存器sp指向内核地址
	5. 跳入内核C代码
5. supervisor mode可以进行的操作： 读写控制寄存器, SATP(页表指针), STVEC(处理trap的内存指令地址), SEPC(读写发生trap时的程序计数器) 
6. xv6中有跳板函数，被映射在用户空间和内核空间的高地址，位于同样的虚拟地址，这样切换页表时它仍可以正常工作。跳板函数包括uservec（处理用户空间开始的陷阱）和userret（内核态切换到用户态)。 由于stvec指向uservec，处理trap时会先跳转到这里，此时CPU处于特权模式，但是处于用户页表
	1. uservec: 保存现场（用户寄存器）到trapframe中，加载内核栈指针和内核页表，随后跳转到异常处理函数usertrap()进行处理。
	2. userret: 从trapframe恢复用户模式的寄存器，加载用户页表，通过sret返回用户模式
7. ==write系统调用执行过程==：
	1. ==用户程序设置好write库函数的参数，并将对应的系统调用号加载到a7寄存器，执行ECALL指令，RISC-V ECALL指令会做三件事：切换到supervisor mode（监督模式)，修改程序计数器，保存当前程序计数器到SEPC中，跳转到STVEC寄存器指向的地址（也就是跳板函数）。==
	2. 现在处于supervisor mode，已经==跳转到（内核处理代码）trampoline page的uservec()。现在需要保存用户寄存器、保存CPU核的编号、切换到内核页表、切换到内核栈、加载后续执行函数的指针==。
	3. usertrap()用来处理系统调用、运算除0、缺页错误、设备中断。它会==检查SCAUSE寄存器检查触发trap的原因，并执行相应的处理。== 在用户态下进行ecall时，会将SCAUSE寄存器设置为8 (Environment call from U-mode). 
	   首先使STVEC指向kernelvec，这是因为现在处于内核空间，对于trap需要有不一样的处理。usertrap() 中，在处理系统调用而不是其他中断时，需要保存程序计数器到trapframe中，并保持中断打开，此时再调用syscall()函数
	4. ==syscall() 根据trapframe中保存的系统调用号，查找系统调用表调用对应的函数sys_write并执行。==
	5. ==执行sys_write()，从trapframe中获取参数并执行。==
	6. usertrap()继续调用usertrapret()函数：关中断，更新STVEC寄存器指向trampoline page的uservec，更改trapframe,以便下次用户空间转换到内核空间时使用。更改特权模式，通过sret指令，设置程序计数器为SEPC寄存器的值，[省略一部分](https://mit-public-courses-cn-translatio.gitbook.io/mit6-s081/lec06-isolation-and-system-call-entry-exit-robert/6.7-usertrapret)
	7. 最后==调用trampoline代码中的userret函数，加载trapframe保存的寄存器值，执行sret指令：切换回user mode，将SEPC寄存器的值拷贝到PC，重新打开中断。==

### Lab目标
1. 实现backtrace() 功能，打印出调用栈便于调试。[slides](https://www.cs.cornell.edu/courses/cs3410/2019sp/schedule/slides/10-calling-notes-bw.pdf)
2. 添加简单的系统调用alarm,在进程使用CPU时定时发出警报，用于限制进程消耗的CPU时间和定期操作。这个alarm实际上是用户级中断/异常处理程序的原始形式，主要是为了page fault做铺垫。
3. 需要新增一个sigalarm(interval, handler)的系统调用，它会使得调用这个系统调用的进程在CPU每走过interval个ticks时自动地调用handler函数。handler函数默认会调用sigreturn()，因此需要在sig_return()中恢复寄存器值。

### backtrace()实现
 栈帧结构：栈从高地址往低地址增长，fp指向当前栈帧开始地址，sp指向栈帧结束地址，因此fp - 8存储return address, fp - 16存储previous address， 即上一层栈帧的fp开始地址。
 栈帧从上往下保存的依次是：return address, previous fp, 保存的寄存器值，本地变量值
 
### 添加系统调用 sigalarm() 和 sigreturn()
1. Alarm()实现：在进程控制块中添加以下数据结构，添加一个额外的陷阱帧结构。在每次时钟中断时，如果进程有已经设置的alarm(alarm_interval != 0)，就进行倒数，当倒数到小于等于0的时候，把目前的trapframe保存到alarmtrapframe中(usertrap的 //#note)，随后执行alarm处理函数，从alarm处理函数返回后，再从alarmtrapframe中恢复原有的trapframe(sys_sigreturn()的功能），这样从被中断代码的视角来看，就是不可感知的中断。
```C // proc.h
  //alarm interval and the pointer to the handler function in new fields in the proc structure
  int alarmitv; //alarm interval
  void (*handler)(void); 
  int ticksCount;
  struct trapframe *alarmframe;
  int inalarm;
```
2. sysproc.c中实现sys_sigalarm()和sys_sigreturn() 系统调用，将对应进程的属性赋值
```C
uint64 
sys_sigalarm(void)
{
  int n;
  uint64 p;
  if(argint(0, &n) < 0)
    return -1;
  if (argaddr(1, &p) < 0)
    return -1;
  
  acquire(&tickslock);
  myproc()->alarmitv = n;
  myproc()->handler = (void*)p;
  release(&tickslock);
  return 0;
}

uint64
sys_sigreturn(void)
{
  copyframe(myproc()->alarmframe, myproc()->trapframe);
  myproc()->inalarm = 0;
  return 0;
}
```
3. 在usertrap函数中，每次时钟中断时处理alarm，并先跳转到handler()，也就是sigreturn中进行处理
```C
  if(which_dev == 2){
    myproc()->ticksCount++;
    if (myproc()->alarmitv > 0 && myproc()->alarmitv == myproc()->ticksCount){
      if (myproc()->inalarm == 0)
      {
        myproc()->inalarm = 1;
        copyframe(myproc()->trapframe, myproc()->alarmframe); //#note
        myproc()->trapframe->epc = (uint64) myproc()->handler;
        myproc()->ticksCount = 0;
      } else 
      {
        myproc()->ticksCount--;
      }
    }
    yield();
  }
```
# Lab 5 Lazy Page Allocation
### 相关知识
1. sbrk() 用于调整进程中堆的大小(堆结束的位置)。堆是一个动态内存区域，进程可以在运行时动态分配或释放这个区域的内存。接收一个整型参数并调整。当增加堆的大小时，操作系统将会把新增的部分初始化为零。当减小堆的大小时，被减去的部分的内存将会被操作系统回收。
2. 通常不使用sbrk()。
	1. mmap(): mmap在程序中创建一个匿名内存区，不与任何文件相关联，而是与交换空间相关联。
	2. malloc()和free()在库层面提供了内存管理的抽象，开发者无需直接操作内存布局。
	3. calloc() 分配内存，并在返回之前置0
	4. realloc() 创建一个更大的内存区域，将旧区域放入其中
3. RISC-V syscall 相关知识 https://tinylab.org/riscv-syscall-part2-procedure/  
4. 当trap发生时，处理器会设置trap发生的原因(SCAUSE)、trap对应trap发生的指令地址(SEPC)，当出现缺页错误时STVAL寄存器存储需要访问的内存地址。
	   SCAUSE =13时表示读错误， SCAUSE =15时表示写错误， SCAUSE=12表示指令错误，例如(jump)
   ![|550](images/scause_code.png)
5. 用户程序的地址空间 .text(代码区), .data(已初始化全局变量), .bss(未被初始化或初始化为0的全局/静态变量)
6. 虚拟内存和物理内存区别？ 使用虚拟内存有什么优势？
   "计算机科学领域的任何问题都可以通过增加一个间接的中间层来解决"
7. page fault: 动态映射地址关系，通过page fault， 内核可以更新page table
### 目的
1. 使sbrk()系统调用具有内存懒分配的机制。在调用sbrk()时，不立即分配内存，而是只作记录，在访问到这一部分内存时才进行实际的物理内存分配。
2. 原本的sys_sbrk()调用了uvmalloc()或uvmdealloc()直接进行物理内存的分配和释放。实际上应用程序很难预测自己需要多少内存，通常会申请多余的内存，增加了系统的内存消耗。修改后的sys_sbrk()在减少堆空间时释放物理内存，在增加堆大小时只增加p->sz，在某个时间点，应用程序触发page fault后才进行实际分配，并重新执行指令。

### 实现
1. 在用户态trap()处理函数中添加缺页检测，
   如果是缺页异常(r_scause() == 13 || r_scause() == 15)，
   且异常的地址(uint64 va = r_stval())合法，
   且缺页是lazy page allocation造成的(va <= p->sz)，
   那么分配物理内存页并在页表中添加va->ka的映射关系，权限为R_W_U，否则终止进程。
```C
else if (r_scause() == 15 || r_scause() == 13) // 15:store 13:load 
  {
    uint64 va = r_stval();
    // Kill a process if it page-faults on a virtual memory address higher than any allocated with sbrk().
    if (va >= p->sz || va <= p->trapframe->sp) {
      p->killed = 1;
    } else {
      uint64 ka = (uint64)kalloc(); 
      if (ka == 0) {
        p->killed = 1;
      } else {
        memset((void*)ka, 0, PGSIZE);
        va = PGROUNDDOWN(va);
        if (mappages(myproc()->pagetable, va, PGSIZE, ka, PTE_R | PTE_W | PTE_U) != 0) {
          kfree((void*)ka);
          p->killed = 1;
        }
      }
    }
    // end 
  }
```

2. 修改取消虚拟地址映射的函数uvmunmap. (!PTE_V则跳过，不作处理，不触发panic)
3. copyin()(user to kernel)和copyout()(kernel to user)内核和用户态之间互相拷贝数据
   由于可能会访问到懒分配但是还没实际分配的页面，由于是软件实现的地址转换(pagewalk)，所以不会触发trap，只会返回一个空的物理地址，此时应及时分配对应的物理页面并继续执行。
4. sys_sbrk()：不再直接分配堆空间，而是修改堆大小(p->sz)，使堆缩小时应调用uvmdealloc()。


# Lab 6 Copy-on-write fork fork懒拷贝
### 相关知识
1. 写时复制(Copy-on-write)：如果有多个调用者同时请求相同资源，例如内存或磁盘存储，他们会共享同样的指针，指向同样的资源，直到调用者试图修改资源内容时，系统复制一份专用副本给该调用者，其他调用辙持有的资源仍然不变。该过程对调用者是透明的。COW需要MMU的硬件支持，当试图写入COW的只读内存页时，MMU抛出缺页异常，内核分配页面并复制数据，修改页表项，重新执行写操作。
2. COW的优势：节省内存，减少不必要的数据拷贝，但会增加操作系统I/O过程复杂性。劣势：处理pagefault需要时间，可能导致性能问题，需要额外的同步机制，增加内存管理复杂性。
3. COW的应用: [https://mit-public-courses-cn-translatio.gitbook.io/mit6-s081/lec08-page-faults-frans/8.3-zero-fill-on-demand](按需填零) BSS包含了未被初始化或者初始化为0的全局/静态变量，所有page内容都为0，只需要分配一个全零的物理页面，将所有虚拟地址空间的全0的页面都映射到这一个物理页面上，可以在程序启动时节省大量物理内存分配。尝试写bss中的page时，需要创建一个新的page并填零，重新执行指令。
### 实现
1. 修改uvmcopy()：
   原有：根据父进程的页表项、虚拟地址、物理页，分配新的物理页并复制数据，添加页表项到子进程中（将同样的虚拟地址映射到新的物理地址）。
   修改后：如果父进程的PTE_W标志位有效，清除父进程的PTE_W标志位，设置PTE_RSW标志位。如果父进程的PTE_W标志为无效，是只读页面，不作变更。如果父进程的页面将父进程的物理页直接map到子进程同样的虚拟地址中，增加页引用次数。
2. 修改trap代码，捕获写操作并执行页面复制。实现COWhandler()函数
```C
else if (r_scause() == 15) { // the interrupt is caused by store(write)
    if (COWhandler(p->pagetable, r_stval()) < 0) {
      panic("usertrap: page fault");
    }
```
COWhandler()的功能：首先检查该页面是否合法（存在对应页表项、虚拟地址处于0->p->sz之间、不是栈的guard page，这里的guard page是存在于栈空间的底部，当程序试图往栈中写入过多的数据时，栈继续增长，就会尝试访问这个页面，这个页面不应该被分配物理页和建立映射），如果合法分配新物理页面，复制页面数据，将虚拟地址映射到新的物理界面，清除PTE_RSW位，设置可写。
3. 注意软件实现的pagewalk, copyout()，将内核中的页面复制到指定页表的指定虚拟地址时，要先确保虚拟地址已经映射到非COW页面。
4. 维护页面统计的数组全局变量(在修改数组数据时需要使用锁)。根据[xv6内核态地址空间和物理地址空间](6.S081%20Part%201%20Lab1-4.md#^be0680)， xv6的RAM大小是KERNBASE-PHYSTOP (128MB)，每个页面(4kB) ，约有64k个页表项，因此这个数组并不大。在kfree()函数中减少对应页面的refCount计数，仅当refCount == 0时才真正释放该物理页面。在kalloc时设置refCount=1, 在COW(uvmcopy())时refCount++

# Lab 7 多线程
### 相关知识
1. 进程、线程和协程的主要区别
2. 并发和并行有什么区别：并发(Concurrent)指的是几个程序都处在已启动运行到运行完毕之间，且几个程序都在同一个处理器上运行。 并行(Parallel)指的是多个CPU可以分别执行各自的进程，可以同时运行。
3. 进程：代码编译后生成二进制可执行文件，装载到内存中运行，就是进程。进程有运行、阻塞、就绪的状态。
4. 线程：可以并发运行、共享地址空间、文件等资源，但拥有自己的寄存器和栈(局部变量)。C/C++语言中，一个线程崩溃时会导致所属进程的所有线程崩溃。
5. 协程：进程、线程有CPU时间片的概念，进行抢占式调度。协程比线程更轻量级，是对内核透明的，由用户自己调度，占用内存极小(goroutine: 2kb)，切换开销小（不涉及内核态和用户态的切换，goroutine上下文切换时只涉及程序计数器、栈指针、寄存器值）。
6. 进程控制块(PCB)：包括了进程描述符(pid)、用户描述符(归属的用户)、进程优先级、进程当前状态(running, interruptible, uninterruptible, dead)、页表指针、打开文件列表、进程上下文。 进程控制块通常通过链表的方式组织形成队列，根据不同的状态组成就绪队列、阻塞队列等。
7. 进程上下文切换：从一个可执行进程切换到另一个可执行进程，进程是由内核管理和调度的，进程的切换只能发生在内核态，上下文切换不仅包含了虚拟内存、栈、全局变量等用户空间的资源，也包括内核堆栈、寄存器等内核空间资源，通常把上下文包含在进程的PCB中。
8. 发生上下文切换的场景：调度算法、进程挂起、硬件中断
9. callee-saved register：如果被调用者需要使用callee-saved register，那么被调用函数需要在开始执行时保存这些寄存器的值，并在返回之前恢复这些值，保证了这些寄存器值在函数调用前后保持不变。对于调试和异常处理等场景有意义：发生异常或断点时，处理器能够恢复到函数调用前的状态。
10. ra寄存器：x86架构中，函数的返回地址通常保存在栈上。但RISC-V架构中由返回地址寄存器，因为访问寄存器更快，将返回地址存储在ra中可以使函数调用的速度更快。但处理嵌套和递归调用时还是需要使用栈。
11. 为什么线程调度只需要保存callee-saved寄存器？可以这么理解：caller-saved寄存器已经由调用者保存到栈中了，callee-saved寄存器则没有保存，是这个线程执行状态的一部分。
12. 线程切换或上下文切换：可能会在任何时刻发生，当操作系统决定停止线程执行时，需要保存被暂停线程的所有状态，以便再次恢复该线程。
13. xv6进程切换的过程：无论是通过时钟中断(usertrap)、还是线程主动放弃CPU(sleep, exit)，都会调用yield()，yield首先挂起当前进程，再通过调用sched()从当前进程swtch()到调度器线程， 再进一步调用swtch() 【在调用swtch()之前，会保存caller-saved register)。 由于上下文切换永远发生在swtch()调用，从就绪到恢复执行也就是swtch的返回过程，会从栈中恢复caller-saved寄存器的值，因此，用于保存上下文的context结构体只需要保存callee-saved寄存器、ra、sp即可。】。每个CPU有一个调度器进程，对于schedule()来说，从进程调度中返回后，首先修改cpu所运行的进程为他自己(0)，随后调度器进程遍历进程列表，寻找下一个RUNABLE进程，将cpu运行进程mycpu()->切换到该进程，并通过swtch()切换到该进程）。对每个进程而言，他们只是调用swtch()，然后返回，并不了解进程调度的过程。
    ==usertrap() -> yield() -> sched() -> A.swtch() -> return Scheduler.swtch() -> B.swtch()== 
    注意这里进程A的p->context存储的是它自身的上下文，每个CPU都有一个long-running的调度器进程，Scheduler()进程的context就存储在CPU中。
14. 中断机制：使用的是trapframe、中断可能在任意时刻发生，可能在函数执行中途，恢复的时候需要靠pc寄存器定位，并且几乎需要保存所有的寄存器，才能正确的恢复执行。
    中断通常是由硬件设备发起的，例如IO设备的数据传输请求，会向处理器发送中断信号，处理器调用中断处理程序响应中断。
    软中断：是由操作系统内核的软件机制产生的终端，用来处理紧急任务。
15. 中断的上半：硬件设备发出中断请求后，首先执行上半部本，这部分执行需要尽量快，以便释放中断总线和中断控制器。
    中断下半：上半部完成了初步处理后，剩余的工作交给下半处理。处理一些不太紧急的任务，例如数据拷贝、数据传输等，可被其他中断打断。
1. trap机制：系统调用、异常、中断都涉及到了陷入（trap）机制。系统调用通过特殊语句执行，是主动触发的陷入。当CPU执行过程中出现一些预期之外的情况时，例如除以零、访问非法内存地址等，就会触发异常。这是一种被动的陷入，发生时机是在指令执行过程中。处理器会暂停当前指令的执行，切换到内核模式，然后开始执行对应的异常处理程序。中断是外部设备发起的，例如I/O设备完成数据传输，时钟中断等，中断可以在任意指令边界发生。
```C
void
sched(void)
{
  ...
  struct proc *p = myproc();
  swtch(&p->context, &mycpu()->context);
}

void
scheduler(void)
{
	struct proc *p;
	struct cpu *c = mycpu();
	for (...) {
		...
		p->state = RUNNING;
		c->proc = p;
		swtch(&c->context, &p->context);
		c->proc = 0;
		...
	}
	
}
```

15. 无论是进程sleep还是时钟中断，都是在用户态保存绝大部分寄存器和程序计数器到trapframe，通过trampoline跳转到内核态，再通过yield()挂起线程和sched()和swtch()切换到调度器进程，实际上恢复上下文都是恢复到swtch()返回的状态
```C
# Context switch
#
#   void swtch(struct context *old, struct context *new);
# 
# Save current registers in old. Load from new.	
.globl swtch
swtch:
        sd ra, 0(a0)  // 修改了返回值
        sd sp, 8(a0)
        sd s0, 16(a0)
        sd s1, 24(a0)
        sd s2, 32(a0)
        sd s3, 40(a0)
        sd s4, 48(a0)
        sd s5, 56(a0)
        sd s6, 64(a0)
        sd s7, 72(a0)
        sd s8, 80(a0)
        sd s9, 88(a0)
        sd s10, 96(a0)
        sd s11, 104(a0)

        ld ra, 0(a1)
        ld sp, 8(a1)
        ld s0, 16(a1)
        ld s1, 24(a1)
        ld s2, 32(a1)
        ld s3, 40(a1)
        ld s4, 48(a1)
        ld s5, 56(a1)
        ld s6, 64(a1)
        ld s7, 72(a1)
        ld s8, 80(a1)
        ld s9, 88(a1)
        ld s10, 96(a1)
        ld s11, 104(a1)
        
        ret
```
14. 用户态陷入内核态时，通过trampoline.S中的uservec已经保存了大部分的用户级寄存器，包括ra,gp,tp,t0-t6,s0-s11, a0-a7【包括：保存用户寄存器、保存CPU核的编号、切换到内核页表、切换到内核栈、加载后续执行函数的指针】。
### 目的
1. 自己实现用户态的线程库。（线程库应该包括：线程创建、线程销毁、线程同步（互斥量pthread_mutex_lock、条件变量pthread_cond_wait, pthread_cond_signal）、线程调度（线程调度优先级通常由操作系统负责，但也可以设置线程优先级，或者主动让出CPU））缺点：线程数固定, 没有线程销毁的机制。
2. Lab中实现的更接近于协程，即完全基于用户态实现，多个线程运行于同一个CPU上，没有时钟中断强制执行调度，而是由线程在合适的时候主动yield释放CPU。
3. 用pthread提供的条件变量方法实现简单的同步屏障。

###  实现
1. 每个线程都有自己的栈、运行状态、（线程上下文和栈指针）。上下文结构体需要保存寄存器和程序计数器，这里只需要保存callee-saved register(s0->s11)即可，其他的会由调用者根据需要保存。
2. 在用户态实现线程调度和线程切换的过程
3. 线程调度：遍历线程，找到下一个就绪状态的线程并运行。
4. 线程初始化：初始化主线程为thread[0]，RUNNING。
5. 线程创建：初始化线程结构体，设置返回地址，设置栈指针。这里需要设置新的上下文来启动线程，需要修改栈指针寄存器和返回地址寄存器，将ra指向线程执行的代码，这样从thread_create返回时就已经开始执行新线程的代码。注意栈指针要指向最高处。

```c
  memset(&t->threadcontext, sizeof(t->threadcontext), 0);
  t->threadcontext.ra = (uint64) (func);
  t->threadcontext.sp = (uint64) (t->stack + STACK_SIZE - 1);
```
6. 线程销毁：状态设置为UNUSED
7. 线程切换过程：thread_yield()挂起当前线程，再调用thread_schedule()，如果没有其他就绪的线程则切换回主线程。
8. pthread的条件变量实现同步屏障
   线程总数是n, bstate.nthread表示已进入屏障的线程数量，线程每次进入barrier时，先将bstate.nthread++，判断是否等于n
   如果小于则睡眠pthread_cond_wait(&bstate.barrier_cond, &bstate.barrier_mutex);，
   如果等于n，broadcast, pthread_cond_broadcast(&bstate.barrier_cond);
   需要使用互斥锁barrier_mutex保护
```C
static void 
barrier()
{
  // Block until all threads have called barrier() and
  // then increment bstate.round.
  //
  pthread_mutex_lock(&bstate.barrier_mutex);
  bstate.nthread++;
  if (bstate.nthread < nthread) 
  {
    int thisRound = bstate.round;
    while (thisRound == bstate.round)
    {
      pthread_cond_wait(&bstate.barrier_cond, &bstate.barrier_mutex);
    }
  } else {
    bstate.round++;
    pthread_cond_broadcast(&bstate.barrier_cond);
    bstate.nthread = 0;
  }
  pthread_mutex_unlock(&bstate.barrier_mutex);
}
```


# Lab 8 Lock 锁优化
### 相关知识
1. 锁竞争优化的思路：只在必须共享的时候共享（拆分共享资源）、必须共享时，尽量减少在关键区中的停留时间、降低锁的粒度。
2. xv6的文件系统有boot sector, super block(存放文件元数据：log长度，inode数量，data block数量), log(允许通过事务更新多个磁盘块，确保数据一致性), inode, bitmap->datablock。
3. Buffer cache layer的作用：同步访问磁盘块，确保磁盘块在内存中只有一个数据副本，减少磁盘I/O次数。缓存区的大小是固定的，采用LRU机制，用设备号和扇区号来定位data block。==Buffer缓存的接口包括bread, bwrite，read返回一个可读写的内存副本，bwrite将副本写入磁盘，内核线程使用完buffer后必须brelse释放它。他们都会调用bget()先得到一个带锁的block, 首先锁定整个buffer遍历检查data block，如果不存在，第二次循环生成对应的buffer block。==
4. xv6的日志系统效率低下，采用与早期unix相同的inodes和目录的基本磁盘布局。并且目录是很低效的，每次查找过程都要对所有磁盘块进行线性扫描。
   对磁盘故障的处理很朴素，直接抛出panic，普通磁盘应该优雅的处理，使文件中一个块的丢失不影响其他部分的使用。
   文件系统大小不可变，且固定在单一磁盘设备上。采用RAID可以提高外部存储的可用性和稳定性。
### 目标
1. ==拆分kmem中的空闲内存链表，降低kalloc()实现中的kmem锁竞争。==
2. xv6原本的实现中，空闲页记录是采用链表的形式，将空闲物理页本身作为链表项，每次kalloc()和free()时都需要从链表头获取物理页，由于修改是多步操作，为了保持数据的一致性需要加锁，这就导致了无法并发申请内存，限制并发效率。通过对比几个互斥锁的获取和释放频率可以发现kmem锁竞争频繁（还有proc，bcache）
3.  Buffer cache：多个进程同时使用文件系统时，保护磁盘区块缓存的bcache.lock会出现锁竞争，由于该锁存在，多个进程不能同时申请或释放磁盘缓存。目标是建立一个hash表并实现桶级锁以减少锁竞争，BUCKETS=13，根据block no和device来计算key，并把cache block置于对应key的BUCKET中，每个BUCKET是一个链表，这样仅当两个进程同时访问的区块处于同一个锁时才会发生锁竞争。
4. xv6原本的实现中：使用双向链表存储所有的区块缓存，每次bwrite或bread调用bget寻找指定blockno和deviceno的block时都会遍历链表，并持有链表的锁，不允许并发访问。如果不存在，会根据LRU算法选取引用计数为0的buf块作为区块缓存返回。
```C
// Linked list of all buffers, through prev/next.
// Sorted by how recently the buffer was used.
// head.next is most recent, head.prev is least.
// Old:
struct {
  struct spinlock lock;
  struct buf buf[NBUF];
  struct buf head;
} bcache;

// new:
struct {
  struct spinlock lock;
  struct buf buckets[NBUCKETS];
  struct buf buf[NBUF];
  struct spinlock bucketsLock[NBUCKETS];
} bcache;
```
5. 注意：bcache的区块缓存是会被多个进程(多个CPU)共享的，因此不能像kmem一样为每个CPU单独分配一个链表。这里最好降低锁的粒度，降低出现竞争的概率。

### kmem锁优化 实现
1. 该Lab的目标是为每一个CPU分配独立的freelist，这样CPU就可以并发分配物理页，提高并行性。
2. 在CPU-A物理页不足的情况下，需要从其他CPU那里偷物理页。此时CPU-A也可能被其他CPU偷页。这里我原本方法是加一把全局的StealingLock，在有CPU偷页时不允许任何操作，进一步降低锁的粒度可能会导致死锁。进一步优化：每个list都有自己的锁，根据CPU的编号确定一个获取锁的顺序，编号较大的CPU要获取锁，只能先释放自身的锁再尝试获取，这样就避免了环形等待条件，但由于没有关闭中断，先释放锁的话，有可能出现多个进程为CPU偷页的情况。再进一步：再添加一个额外的偷锁，在放弃掉自身的锁之前获取偷锁，然后先释放list锁，从其他CPU偷页面，再获取list锁，并释放偷锁，添加页面，释放list锁，这样就保证了进程不会被调度，不会出现重复偷取。

### Buffer cache锁优化
1. 总目标是建立一个blockno->buf的hash表，并给每个桶单独加锁，这样仅当两个进程同时访问的区块处于同一个BUCKET时才会发生锁竞争，本质上是实现一个线程安全的哈希表，同时保留原有的LRU策略。
2. 实现：
	1. LRU：为每个节点记录一个ticks，需要驱逐buffer cache时，通过比较找到带有全局最小ticks且引用数为0的buffer cache block并驱逐。
	2. hash值计算：扇区号和设备号唯一地决定buffer cache， 设NBUCKETS = 13, (blockno << 32 | dev ) % NBUCKETS
	3. 每个BUCKET都有一个自旋锁，整个buffer cache有一个写锁。
	4. bget(uint dev, uint blockno)，首先根据dev和blockno计算出目标buffer cache block所在的bucket，首先获取该bucket的锁，检查bucket中是否有buffer cache block，如果没有就是一次cache missing。 cache missing时，首先释放自己BUCKET的自旋锁，并获取整个hashmap的写锁。
	5. 在获取写锁后，再次获取destination BUCKET的自旋锁，由于之前已经释放过了自己BUCKET的自旋锁，有一段时间是未持有的，此时需要再次检查BUCKET中是否已经有对应的cache。
	   如果没有，此时是持有写锁和自己BUCKET的自旋锁的，这时候按照BUCKET下标从小往大，获取所有BUCKET的锁，遍历hashmap寻找LRU的buffer cache block，用source BUCKET表示LRU buffer cache block所在的BUCKET。
	   首先需要判断source和destination是否相同：如果相同就不需要移动了，直接改LRU buffer cache block的dev 和blockno就行。如果不同，由于这时候已经持有两个BUCKET的锁了，直接操作即可，操作完毕后释放所有锁和写锁即可。
	   也就是说，仅当进程持有写锁的时候，它才能持有其他BUCKET的锁，否则只能持有自己的，并在cache miss时释放。我认为这个方法保证了正确性，但是牺牲了性能。
	  6. 此外需要实现的就是一些 ticks的更新，在每当bget和pin的时候需要更新ticks，在brelse中，我是这么设置的，当b->refcnt = 0 时，可以设ticks为零值，这样一来就比其他所有的都要小。

# 6.S081 Part 3 Lab 9 - Lab 11

# Lab 9 File system
### 相关知识
1. ext2文件系统的结构![|687](面试/images/ext2Structure.png)
   xv6的file system和Linux ext2 文件系统类似，除了boot sector以外，整个file system相当于ext2 的一个block group，由super block, inode bitmap, inode table, data block bit map, data block table，也就是超级块，inode表，inode位图，数据块位图，数据块组成。
   inode中同样存有指向数据块的指针，分为直接索引和间接索引。
   inode可能指向普通文件或目录文件。
   此外，xv6还有固定长度的日志区，在此基础上实现了简单的WAL(预写日志)功能，日志的大小是有限的，由此来支持单个事务数据操作的原子性。
2. xv6 文件系统的inode结构体：采用了混合索引的方式，前12个是直接索引，后3个是一级间接索引。indierct block number对应了磁盘上的一个block，这个block又包含了256个block number(每个4字节)。
3. xv6每个block的size是1k。
4. create inode的过程：解析路径名，找到最后一个路径，查看我文件是否存在，如果不存在就调用ialloc为文件x分配inode。这里需要遍历所有的inode来查找。
### 目标
1. 为xv6的混合索引机制添加二级索引页，扩大能支持的文件大小。
2. 为xv6的文件系统添加符号链接支持

### Exercise 添加二级间接索引
1. bmap(struct inode \*ip, uint bn)的用途是获取inode中第bn个块的块号，itrunc(struct inode \*ip) 的用途是释放inode中所有的数据块。
2. 需要修改这两个函数使其能够识别二级索引，基本上按照间接一级索引的逻辑来拓展。
3. 间接索引中的叶指针应该都是指向数据块的。
4. 一级间接索引的解析：首先获取一级间接块的地址ip->addrs[bn]，如果为零，通过balloc分配一个新的磁盘块，再读取间接块的内容到bp，转换bp->data到无符号整数指针a，查看a[bn]（所读取的块地址）是否为0，如果为0，分配一个新的磁盘块并写入日志。注意这里的写入都要通过log来实现。
5. 二级间接索引的解析：同样的，如果要获取二级间接索引内第bn个数据块的内容，由于每个数据块可以储存256个索引，应该使用bn / 256 计算出一级索引数据块的序号，bn % 256 计算出二级索引数据块的序号，然后逐级查找即可。
6. itrunc(struct inode \*ip) 的实现：依次进入到一级、二级索引、数据块依次遍历释放即可，注意释放时需要通过brelse释放buffer block，然后通过bfree释放磁盘数据块，最后需要将ip->addrs[]置零。
```c
  if(bn < NINDIRECT){
    // Load indirect block, allocating if necessary.
    if((addr = ip->addrs[NDIRECT]) == 0)
      ip->addrs[NDIRECT] = addr = balloc(ip->dev);
    bp = bread(ip->dev, addr);
    a = (uint*)bp->data;
    if((addr = a[bn]) == 0){
      a[bn] = addr = balloc(ip->dev);
      log_write(bp);
    }
    brelse(bp);
    //printf("allocate indirect block\n");
    return addr;
  }
  bn -= NINDIRECT;
```


### 实现符号链接
1. 在内核映像中实现sys_symlink()系统调用，用于创建符号链接。符号链接和普通的文件一样，需要占用inode块，使用inode
```
// stat.h 添加符号链接的定义
#define T_DIR     1   // Directory
#define T_FILE    2   // File
#define T_DEVICE  3   // Device
#define T_SYMLINK 4   // here: symbol link
// fcntl.h 修改inode的文件权限定义
#define O_RDONLY  0x000
#define O_WRONLY  0x001
#define O_RDWR    0x002
#define O_CREATE  0x200
#define O_TRUNC   0x400
#define O_NOFOLLOW 0x010 // 
```
2. 修改sys_open()系统调用，如果读取到链接，就需要递归地读取指向的符号链接文件，直到O_NOFOLLOW标志位为0

# Lab 10 mmap
## 相关知识
1. xv6的用户态内存空间
   ![](images/mit6s081-lab10-useraddrspace.png)
2.  
## 目标
1. 实现Linux系统调用mmap()的简单版：支持将设备映射到虚拟内存中，并将修改的部分写回磁盘。
## 实现
1. 用户的地址空间中，未映射的区域是顶部trapframe以下，heap以上的区域。 由于堆是向上生长的，尽量映射到高地址避免内存映射冲突。如果mmap有多个文件，向下增长。
2. 实现vma结构体，包括mmap映射内存区域的有关信息：开始地址、==文件大小、所映射文件、权限==等，在进程控制块中添加vma数组。
```C
//Keep track of what mmap has mapped for each process.
struct vma {
  int valid;
  uint64 vm_start;
  uint64 vm_end;
  uint64 length;
  int perm;
  int flags;
  struct file *f;
  struct spinlock lock;
};
```
3. 实现sys_mmap()系统调用以及mmap()函数，找到可用的空槽，计算出当前所有vma使用的最低虚拟地址，作为新插入vma的起点。mmap系统调用中需要调用filedup()。
```C
uint64 get_vma_addr(struct vma vmalist[], uint64 length) {
  uint64 addr = 0x20000000;
  struct vma* vma_item = myproc()->vma_list;
  for (; vma_item < &vmalist[NOFILE]; vma_item++) {
    if (vma_item->valid && vma_item->vm_end > addr) {
      addr = vma_item->vm_end;
    }
  }
  if (addr >= VMA_END || addr + length >= VMA_END) {
    printf("addr error, addr = %p\n", addr);
    return 0;
  }
  printf("addr = %p\n", addr);
  return addr;
}

int insert_vma(struct vma vmalist[], struct vma* target, int length, int perm, int flags, struct file *f) {
  uint64 dst = get_vma_addr(vmalist, length);
  if (dst == 0) {
    printf("addr error: 0\n");
    return -1;
  }
  if (!f->readable && (perm & PROT_READ)) {
    printf("perm error: read\n");
    return -1;
  }
  if (!f->writable && (perm & PROT_WRITE) && !(flags & MAP_PRIVATE)) {
    printf("perm error: write\n");
    return -1;
  }
  target->f = f;
  target->length = length;
  target->perm = perm;
  target->flags = flags;
  target->vm_start = dst;
  target->vm_end = dst + length;
  target->valid = 1;
  return 0;
}
//Lab code end
```
4. 实现sys_munmap()系统调用以及munmap()，munmap()用于解除映射区域，根据参数的地址和长度寻找对应的vma，根据对应vma的标志，可能会写回文件。然后在进程页表中调整vma的大小或者完全删除。
```c
int munmap(void *addr, int length) {
  uint64 munmap_addr = (uint64) addr;
  struct vma* vma_item = find_vma(myproc()->vma_list, munmap_addr);
  struct file* f = vma_item->f;
  //int ret = 0;
  if (vma_item == 0) {
    return -1;
  }
  if (vma_item->vm_start < munmap_addr && munmap_addr + length < vma_item->vm_end) {
    return -1;
  }
  if (find_vma(myproc()->vma_list, munmap_addr) == 0) {
    return -1;
  }
  munmap_addr = PGROUNDDOWN(munmap_addr);
  int npages = PGROUNDDOWN(length) / PGSIZE;
  if (vma_item->flags & MAP_SHARED && (vma_item->perm & PROT_WRITE)){
    printf("write %d pages at %p\n", npages, addr);
    filewrite(f, (uint64)addr, length);
  }
  if (vma_item->length == length) {
    uvmunmap(myproc()->pagetable, munmap_addr, npages, 1);
    fileclose(vma_item->f);
    vma_item->valid = 0;
  } else if (vma_item->vm_start == (uint64)addr) {
    uvmunmap(myproc()->pagetable, munmap_addr, npages, 1);
    vma_item->vm_start += length;
    vma_item->length -= length;
  } else if (vma_item->vm_end == (uint64)addr + length) {
    uvmunmap(myproc()->pagetable, munmap_addr, npages, 1);
    vma_item->vm_end -= length;
    vma_item->length -= length;
  }
  printf("munmap length %d at %p, prot is %d\n", length, addr);
  return 0;
};
```
5. 由于对映射的页实现懒加载，同样需要在usertrap中调用handler()进行处理，当进程访问未被映射或权限不足的页面时，就会引发页面错误，然后调用函数，函数会首先寻找VMA是否映射了所访问的内存，如果映射了，就分配物理内存并读取文件内容到内存中（注意读取前和读取后需要加锁和释放锁），在内核页表建立新的映射，并对页表项设置权限。
```c
   int handler(struct proc* p){
    uint64 va = r_stval();
    if (va < VMA_START || va >= VMA_END) {
      p->killed = 1;
    } else {
      printf("page fault at %p\n", va);
      uint64 ka = (uint64)kalloc();
      if (ka == 0) {
        p->killed = 1;
        return -1;
      } else {
        memset((void*)ka, 0, PGSIZE);
        va = PGROUNDDOWN(va);
        struct vma* target;
        // search vma list
        target = find_vma(myproc()->vma_list, va);
        if (target == 0) {
          printf("can not find vma\n");
          p->killed = -1;
          return -1;
        }
        //read the file, read the page at (va - vm_start) to ka, map va --> ka 
        struct file* f = target->f;
        int offset = va - target->vm_start;
        ilock(f->ip);
        readi(f->ip, 0, ka, offset, 4096);
        iunlock(f->ip);
        //Perm: you can assume that prot is PROT_READ or PROT_WRITE or both.
        int perm = target->perm & 0xf;
        int PTE_perm = 0;
        PTE_perm |= PTE_U;
        if (perm & PROT_READ) {
          PTE_perm |= PTE_R;
        }
        if (perm & PROT_WRITE) {
          PTE_perm |= PTE_W;
        }
        if (perm & PROT_EXEC) {
          PTE_perm |= PTE_X;
        }

        if (mappages(p->pagetable, va, PGSIZE, ka, PTE_perm) != 0) {
          kfree((void*)ka);
          p->killed = 1;
          return -1;
        }
      }
    }
    return 0;
}
```
