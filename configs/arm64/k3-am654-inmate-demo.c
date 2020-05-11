/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Configuration for demo inmate on K3 based platforms.
 * 1CPU, 64K RAM, 1 serial port(MCU UART 0).
 *
 * Copyright (c) 2019 Texas Instruments Incorporated - http://www.ti.com/
 *
 * Authors:
 *  Nikhil Devshatwar <nikhil.nd@ti.com>
 *  Lokesh Vutla <lokeshvutla@ti.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/types.h>
#include <jailhouse/cell-config.h>

struct {
	struct jailhouse_cell_desc cell;
	__u64 cpus[1];
	struct jailhouse_memory mem_regions[8];
	struct jailhouse_irqchip irqchips[1];
	struct jailhouse_pci_device pci_devices[1];
} __attribute__((packed)) config = {
	.cell = {
		.signature = JAILHOUSE_CELL_DESC_SIGNATURE,
		.revision = JAILHOUSE_CONFIG_REVISION,
		.name = "inmate-demo",
		.flags = JAILHOUSE_CELL_PASSIVE_COMMREG,

		.cpu_set_size = sizeof(config.cpus),
		.num_memory_regions = ARRAY_SIZE(config.mem_regions),
		.num_irqchips = 1,
		.num_pci_devices = 1,
		.vpci_irq_base = 189 - 32,

		.console = {
			.address = 0x40a00000,
			.divider = 0x35,
			.type = JAILHOUSE_CON_TYPE_8250,
			.flags = JAILHOUSE_CON_ACCESS_MMIO |
				 JAILHOUSE_CON_REGDIST_4,
		},
	},

	.cpus = {
		0x4,
	},

	.mem_regions = {
		/* IVSHMEM shared memory regions for 00:00.0 (demo) */
		{
			.phys_start = 0x8dfb00000,
			.virt_start = 0x8dfb00000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_ROOTSHARED,
		},
		{
			.phys_start = 0x8dfb10000,
			.virt_start = 0x8dfb10000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_ROOTSHARED |
				 JAILHOUSE_MEM_WRITE ,
		},
		{
			.phys_start = 0x8dfb20000,
			.virt_start = 0x8dfb20000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_ROOTSHARED,
		},
		{
			.phys_start = 0x8dfb30000,
			.virt_start = 0x8dfb30000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_ROOTSHARED |
				 JAILHOUSE_MEM_WRITE ,
		},
		{
			.phys_start = 0x8dfb40000,
			.virt_start = 0x8dfb40000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_ROOTSHARED,
		},
		/* MCU UART0 */ {
			.phys_start = 0x40a00000,
			.virt_start = 0x40a00000,
			.size = 0x10000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_IO,
		},
		/* RAM */ {
			.phys_start = 0x8e0000000,
			.virt_start = 0,
			.size = 0x00010000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_EXECUTE | JAILHOUSE_MEM_LOADABLE,
		},
		/* communication region */ {
			.virt_start = 0x80000000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_COMM_REGION,
		},
	},

	.irqchips = {
		{
			.address = 0x01800000,
			.pin_base = 160,
			.pin_bitmap = {
				1 << (189 - 160), 0x0, 0x00, 0,
			},
		},
	},

	.pci_devices = {
		/* 00:00.0 */ {
			.type = JAILHOUSE_PCI_TYPE_IVSHMEM,
			.bdf = 0 << 3,
			.bar_mask = JAILHOUSE_IVSHMEM_BAR_MASK_INTX,
			.shmem_regions_start = 0,
			.shmem_dev_id = 1,
			.shmem_peers = 3,
			.shmem_protocol = JAILHOUSE_SHMEM_PROTO_UNDEFINED,
		},
	},
};
