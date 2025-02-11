/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) 2025 Texas Instruments Incorporated - http://www.ti.com/
 *
 * Configuration for K3 based AM625 EVM
 *
 * Authors:
 *  Paresh Bhagat <p-bhagat@ti.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/types.h>
#include <jailhouse/cell-config.h>

struct {
	struct jailhouse_system header;
	__u64 cpus[1];
	struct jailhouse_memory mem_regions[39];
	struct jailhouse_irqchip irqchips[5];
	struct jailhouse_pci_device pci_devices[2];
} __attribute__((packed)) config = {
	.header = {
		.signature = JAILHOUSE_SYSTEM_SIGNATURE,
		.revision = JAILHOUSE_CONFIG_REVISION,
		.architecture = JAILHOUSE_ARM64,
		.flags = JAILHOUSE_SYS_VIRTUAL_DEBUG_CONSOLE,
		.hypervisor_memory = {
			.phys_start = 0xc0200000,
			.size = 0x400000,
		},
		.debug_console = {
			.address = 0x02800000,
			.size = 0x1000,
			.type = JAILHOUSE_CON_TYPE_8250,
			.flags = JAILHOUSE_CON_ACCESS_MMIO |
				 JAILHOUSE_CON_REGDIST_4,
		},
		.platform_info = {
			.pci_mmconfig_base = 0x76000000,
			.pci_mmconfig_end_bus = 0,
			.pci_is_virtual = 1,
			.pci_domain = -1,
			.arm = {
				.gic_version = 3,
				.gicd_base = 0x01800000,
				.gicr_base = 0x01840000,
				.maintenance_irq = 25,
			},
		},
		.root_cell = {
			.name = "k3-am62l3-evm",

			.cpu_set_size = sizeof(config.cpus),
			.num_memory_regions = ARRAY_SIZE(config.mem_regions),
			.num_irqchips = ARRAY_SIZE(config.irqchips),
			.num_pci_devices = ARRAY_SIZE(config.pci_devices),
			.vpci_irq_base = 180 - 32,
		},
	},

	.cpus = {
		0x3,
	},

	.mem_regions = {
		/* IVSHMEM shared memory regions for 00:00.0 (demo) */
		{
			.phys_start = 0xc0000000,
			.virt_start = 0xc0000000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ,
		},
		{
			.phys_start = 0xc0010000,
			.virt_start = 0xc0010000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE,
		},
		/* Peer 0 */ {
			.phys_start = 0xc0020000,
			.virt_start = 0xc0020000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE,
		},
		/* Peer 1 */ {
			.phys_start = 0xc0030000,
			.virt_start = 0xc0030000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ,
		},
		/* Peer 2 */ {
			.phys_start = 0xc0040000,
			.virt_start = 0xc0040000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ,
		},
		/* IVSHMEM shared memory region for 00:01.0 */
		JAILHOUSE_SHMEM_NET_REGIONS(0xc0100000, 0),
		{
			.phys_start = 0x01810000,
			.virt_start = 0x01810000,
			.size = 0x00070000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		{
			.phys_start = 0x018a0000,
			.virt_start = 0x018a0000,
			.size = 0x00060000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* RAM */ {
			.phys_start = 0x80000000,
			.virt_start = 0x80000000,
			.size = 0x40000000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_EXECUTE,
		},
		/* RAM. Reserved for inmates */ {
			.phys_start = 0xc0600000,
			.virt_start = 0xc0600000,
			.size = 0x3fa00000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_EXECUTE,
		},
		/* ctrl mmr */ {
			.phys_start = 0x09000000,
			.virt_start = 0x09000000,
			.size = 0x00400000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* GPIO0 */ {
			.phys_start = 0x00600000,
			.virt_start = 0x00600000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* TimeSync Router */ {
			.phys_start = 0x00a40000,
			.virt_start = 0x00a40000,
			.size = 0x00000800,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* Wake Up Domain VTM0 */ {
			.phys_start = 0x00b00000,
			.virt_start = 0x00b00000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* DSS */ {
			.phys_start = 0x30200000,
			.virt_start = 0x30200000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		{
			.phys_start = 0x30201000,
			.virt_start = 0x30201000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		{
			.phys_start = 0x30202000,
			.virt_start = 0x30202000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		{
			.phys_start = 0x30207000,
			.virt_start = 0x30207000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		{
			.phys_start = 0x3020a000,
			.virt_start = 0x3020a000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* First peripheral window, 1 of 2 */ {
			.phys_start = 0x01000000,
			.virt_start = 0x01000000,
			.size = 0x00800000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* First peripheral window, 2 of 2 */ {
			.phys_start = 0x01900000,
			.virt_start = 0x01900000,
			.size = 0x01229000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* Second peripheral window */ {
			.phys_start = 0x0e000000,
			.virt_start = 0x0e000000,
			.size = 0x01d20000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* Third peripheral window */ {
			.phys_start = 0x20000000,
			.virt_start = 0x20000000,
			.size = 0x0a008000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* OCSRAM */ {
			.phys_start = 0x70800000,
			.virt_start = 0x70800000,
			.size = 0x00010000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* DMSS */ {
			.phys_start = 0x47000000,
			.virt_start = 0x47000000,
			.size = 0x02000000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* USB0 */ {
			.phys_start = 0x31000000,
			.virt_start = 0x31000000,
			.size = 0x00050000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* USB1 */ {
			.phys_start = 0x31100000,
			.virt_start = 0x31100000,
			.size = 0x00050000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* GPMC0 */ {
			.phys_start = 0x3b000000,
			.virt_start = 0x3b000000,
			.size = 0x00000400,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* GPMC0 data */ {
			.phys_start = 0x50000000,
			.virt_start = 0x50000000,
			.size = 0x08000000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* CPSW */ {
			.phys_start = 0x08000000,
			.virt_start = 0x08000000,
			.size = 0x00200000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* First Wake Up Domain */ {
			.phys_start = 0x04080000,
			.virt_start = 0x04080000,
			.size = 0x00008000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* Second Wake Up Domain */ {
			.phys_start = 0x04201000,
			.virt_start = 0x04201000,
			.size = 0x00008000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* Third Wake Up Domain */ {
			.phys_start = 0x2b000000,
			.virt_start = 0x2b000000,
			.size = 0x00600000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* fourth Wake Up Domain */ {
			.phys_start = 0x40800000,
			.virt_start = 0x40800000,
			.size = 0x00014000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* fifth Wake Up Domain */ {
			.phys_start = 0x43000000,
			.virt_start = 0x43000000,
			.size = 0x00080000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* sixth Wakeup Domain */ {
			.phys_start = 0x707f0000,
			.virt_start = 0x707f0000,
			.size = 0x00010000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
	},

	.irqchips = {
		{
			.address = 0x01800000,
			.pin_base = 32,
			.pin_bitmap = {
				0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
			},
		},
		{
			.address = 0x01800000,
			.pin_base = 160,
			.pin_bitmap = {
				0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
			},
		},
		{
			.address = 0x01800000,
			.pin_base = 288,
			.pin_bitmap = {
				0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
			},
		},
		{
			.address = 0x01800000,
			.pin_base = 416,
			.pin_bitmap = {
				0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
			},
		},
		{
			.address = 0x01800000,
			.pin_base = 544,
			.pin_bitmap = {
				0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
			},
		},
	},

	.pci_devices = {
		/* 0001:00:00.0 */ {
			.type = JAILHOUSE_PCI_TYPE_IVSHMEM,
			.domain = 1,
			.bdf = 0 << 3,
			.bar_mask = JAILHOUSE_IVSHMEM_BAR_MASK_INTX,
			.shmem_regions_start = 0,
			.shmem_dev_id = 0,
			.shmem_peers = 3,
			.shmem_protocol = JAILHOUSE_SHMEM_PROTO_UNDEFINED,
		},
		/* 0001:00:01.0 */ {
			.type = JAILHOUSE_PCI_TYPE_IVSHMEM,
			.domain = 1,
			.bdf = 1 << 3,
			.bar_mask = JAILHOUSE_IVSHMEM_BAR_MASK_INTX,
			.shmem_regions_start = 5,
			.shmem_dev_id = 0,
			.shmem_peers = 2,
			.shmem_protocol = JAILHOUSE_SHMEM_PROTO_VETH,
		},
	},
};
