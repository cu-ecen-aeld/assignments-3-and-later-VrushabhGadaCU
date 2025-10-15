Booting Linux on physical CPU 0x0000000000 [0x410fd034]
Linux version 6.1.44 (vrushabh@vrushabh-OMEN-by-HP-Laptop-PC) (aarch64-buildroot-linux-gnu-gcc.br_real (Buildroot 2024.02.13) 12.4.0, GNU ld (GNU Binutils) 2.40) #1 SMP Sat Oct 11 23:33:16 MDT 2025
random: crng init done
Machine model: linux,dummy-virt
efi: UEFI not found.
Zone ranges:
  DMA      [mem 0x0000000040000000-0x0000000047ffffff]
  DMA32    empty
  Normal   empty
Movable zone start for each node
Early memory node ranges
  node   0: [mem 0x0000000040000000-0x0000000047ffffff]
Initmem setup node 0 [mem 0x0000000040000000-0x0000000047ffffff]
psci: probing for conduit method from DT.
psci: PSCIv1.1 detected in firmware.
psci: Using standard PSCI v0.2 function IDs
psci: Trusted OS migration not required
psci: SMC Calling Convention v1.0
percpu: Embedded 18 pages/cpu s33896 r8192 d31640 u73728
pcpu-alloc: s33896 r8192 d31640 u73728 alloc=18*4096
pcpu-alloc: [0] 0 
Detected VIPT I-cache on CPU0
CPU features: detected: ARM erratum 843419
CPU features: detected: ARM erratum 845719
alternatives: applying boot alternatives
Built 1 zonelists, mobility grouping on.  Total pages: 32256
Kernel command line: rootwait root=/dev/vda console=ttyAMA0
Dentry cache hash table entries: 16384 (order: 5, 131072 bytes, linear)
Inode-cache hash table entries: 8192 (order: 4, 65536 bytes, linear)
mem auto-init: stack:all(zero), heap alloc:off, heap free:off
Memory: 115252K/131072K available (7616K kernel code, 876K rwdata, 1816K rodata, 1280K init, 436K bss, 15820K reserved, 0K cma-reserved)
SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
rcu: Hierarchical RCU implementation.
rcu:    RCU restricting CPUs from NR_CPUS=256 to nr_cpu_ids=1.
rcu: RCU calculated value of scheduler-enlistment delay is 25 jiffies.
rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=1
NR_IRQS: 64, nr_irqs: 64, preallocated irqs: 0
Root IRQ handler: gic_handle_irq
GICv2m: range[mem 0x08020000-0x08020fff], SPI[80:143]
rcu: srcu_init: Setting srcu_struct sizes based on contention.
arch_timer: cp15 timer(s) running at 62.50MHz (virt).
clocksource: arch_sys_counter: mask: 0x1ffffffffffffff max_cycles: 0x1cd42e208c, max_idle_ns: 881590405314 ns
sched_clock: 57 bits at 63MHz, resolution 16ns, wraps every 4398046511096ns
Console: colour dummy device 80x25
Calibrating delay loop (skipped), value calculated using timer frequency.. 125.00 BogoMIPS (lpj=250000)
pid_max: default: 32768 minimum: 301
Mount-cache hash table entries: 512 (order: 0, 4096 bytes, linear)
Mountpoint-cache hash table entries: 512 (order: 0, 4096 bytes, linear)
cacheinfo: Unable to detect cache hierarchy for CPU 0
rcu: Hierarchical SRCU implementation.
rcu:    Max phase no-delay instances is 1000.
EFI services will not be available.
smp: Bringing up secondary CPUs ...
smp: Brought up 1 node, 1 CPU
SMP: Total of 1 processors activated.
CPU features: detected: 32-bit EL0 Support
CPU features: detected: CRC32 instructions
CPU: All CPU(s) started at EL1
alternatives: applying system-wide alternatives
devtmpfs: initialized
clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns
futex hash table entries: 256 (order: 2, 16384 bytes, linear)
DMI not present or invalid.
NET: Registered PF_NETLINK/PF_ROUTE protocol family
DMA: preallocated 128 KiB GFP_KERNEL pool for atomic allocations
DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations
DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations
thermal_sys: Registered thermal governor 'step_wise'
cpuidle: using governor menu
hw-breakpoint: found 6 breakpoint and 4 watchpoint registers.
ASID allocator initialised with 65536 entries
Serial: AMBA PL011 UART driver
9000000.pl011: ttyAMA0 at MMIO 0x9000000 (irq = 13, base_baud = 0) is a PL011 rev1
printk: console [ttyAMA0] enabled
ACPI: Interpreter disabled.
iommu: Default domain type: Translated 
iommu: DMA domain TLB invalidation policy: strict mode 
SCSI subsystem initialized
libata version 3.00 loaded.
pps_core: LinuxPPS API ver. 1 registered
pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
PTP clock support registered
vgaarb: loaded
clocksource: Switched to clocksource arch_sys_counter
pnp: PnP ACPI: disabled
NET: Registered PF_INET protocol family
IP idents hash table entries: 2048 (order: 2, 16384 bytes, linear)
tcp_listen_portaddr_hash hash table entries: 256 (order: 0, 4096 bytes, linear)
Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, linear)
TCP established hash table entries: 1024 (order: 1, 8192 bytes, linear)
TCP bind hash table entries: 1024 (order: 3, 32768 bytes, linear)
TCP: Hash tables configured (established 1024 bind 1024)
UDP hash table entries: 256 (order: 1, 8192 bytes, linear)
UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)
NET: Registered PF_UNIX/PF_LOCAL protocol family
PCI: CLS 0 bytes, default 64
hw perfevents: enabled with armv8_pmuv3 PMU driver, 7 counters available
workingset: timestamp_bits=46 max_order=15 bucket_order=0
fuse: init (API version 7.37)
Block layer SCSI generic (bsg) driver version 0.4 loaded (major 249)
io scheduler mq-deadline registered
io scheduler kyber registered
pci-host-generic 4010000000.pcie: host bridge /pcie@10000000 ranges:
pci-host-generic 4010000000.pcie:       IO 0x003eff0000..0x003effffff -> 0x0000000000
pci-host-generic 4010000000.pcie:      MEM 0x0010000000..0x003efeffff -> 0x0010000000
pci-host-generic 4010000000.pcie:      MEM 0x8000000000..0xffffffffff -> 0x8000000000
pci-host-generic 4010000000.pcie: Memory resource size exceeds max for 32 bits
pci-host-generic 4010000000.pcie: ECAM at [mem 0x4010000000-0x401fffffff] for [bus 00-ff]
pci-host-generic 4010000000.pcie: PCI host bridge to bus 0000:00
pci_bus 0000:00: root bus resource [bus 00-ff]
pci_bus 0000:00: root bus resource [io  0x0000-0xffff]
pci_bus 0000:00: root bus resource [mem 0x10000000-0x3efeffff]
pci_bus 0000:00: root bus resource [mem 0x8000000000-0xffffffffff]
pci 0000:00:00.0: [1b36:0008] type 00 class 0x060000
pci 0000:00:01.0: [1af4:1005] type 00 class 0x00ff00
pci 0000:00:01.0: reg 0x10: [io  0x0000-0x001f]
pci 0000:00:01.0: reg 0x14: [mem 0x00000000-0x00000fff]
pci 0000:00:01.0: reg 0x20: [mem 0x00000000-0x00003fff 64bit pref]
pci 0000:00:01.0: BAR 4: assigned [mem 0x8000000000-0x8000003fff 64bit pref]
pci 0000:00:01.0: BAR 1: assigned [mem 0x10000000-0x10000fff]
pci 0000:00:01.0: BAR 0: assigned [io  0x1000-0x101f]
virtio-pci 0000:00:01.0: enabling device (0000 -> 0003)
cacheinfo: Unable to detect cache hierarchy for CPU 0
virtio_blk virtio0: 1/0/0 default/read/poll queues
virtio_blk virtio0: [vda] 122880 512-byte logical blocks (62.9 MB/60.0 MiB)
rtc-pl031 9010000.pl031: registered as rtc0
rtc-pl031 9010000.pl031: setting system clock to 2025-10-12T20:18:54 UTC (1760300334)
NET: Registered PF_INET6 protocol family
Segment Routing with IPv6
In-situ OAM (IOAM) with IPv6
sit: IPv6, IPv4 and MPLS over IPv4 tunneling driver
NET: Registered PF_PACKET protocol family
NET: Registered PF_KEY protocol family
NET: Registered PF_VSOCK protocol family
registered taskstats version 1
EXT4-fs (vda): INFO: recovery required on readonly filesystem
EXT4-fs (vda): write access will be enabled during recovery
EXT4-fs (vda): orphan cleanup on readonly fs
EXT4-fs (vda): recovery complete
EXT4-fs (vda): mounted filesystem with ordered data mode. Quota mode: disabled.
VFS: Mounted root (ext4 filesystem) readonly on device 254:0.
devtmpfs: mounted
Freeing unused kernel memory: 1280K
Run /sbin/init as init process
  with arguments:
    /sbin/init
  with environment:
    HOME=/
    TERM=linux
EXT4-fs (vda): re-mounted. Quota mode: disabled.
scull: loading out-of-tree module taints kernel.
scullsingle registered at f800008
sculluid registered at f800009
scullwuid registered at f80000a
scullpriv registered at f80000b
Hello, world from VrushabhGadaCU!