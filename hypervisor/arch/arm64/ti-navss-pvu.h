/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) 2018 Texas Instruments Incorporated - http://www.ti.com/
 *
 * TI NAVSS PVU library
 *
 * Authors:
 *  Nikhil Devshatwar <nikhil.nd@ti.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef __TI_NAVSS_PVU_H__
#define __TI_NAVSS_PVU_H__

#include <jailhouse/utils.h>
#include <jailhouse/printk.h>
#include <jailhouse/entry.h>

/* Field definitions for the PVU entry */
#define PVU_ENTRY_INVALID		(0 << 30)
#define PVU_ENTRY_VALID			(2 << 30)

#define LPAE_PAGE_SZ_4K			0
#define LPAE_PAGE_SZ_16K		1
#define LPAE_PAGE_SZ_64K		2
#define LPAE_PAGE_SZ_2M			3
#define LPAE_PAGE_SZ_32M		4
#define LPAE_PAGE_SZ_512M		5
#define LPAE_PAGE_SZ_1G			6
#define LPAE_PAGE_SZ_16G		7

#define LPAE_PAGE_PERM_UR		(1 << 15)
#define LPAE_PAGE_PERM_UW		(1 << 14)
#define LPAE_PAGE_PERM_UX		(1 << 13)
#define LPAE_PAGE_PERM_SR		(1 << 12)
#define LPAE_PAGE_PERM_SW		(1 << 11)
#define LPAE_PAGE_PERM_SX		(1 << 10)

#define LPAE_PAGE_MEM_DEVICE		(0 << 8)
#define LPAE_PAGE_MEM_WRITEBACK		(1 << 8)
#define LPAE_PAGE_MEM_WRITETHROUGH	(2 << 8)

#define LPAE_PAGE_PREFETCH		(1 << 6)
#define LPAE_PAGE_INNER_SHARABLE	(1 << 5)
#define LPAE_PAGE_OUTER_SHARABLE	(1 << 4)

#define LPAE_PAGE_IS_NOALLOC		(0 << 2)
#define LPAE_PAGE_IS_WR_ALLOC		(1 << 2)
#define LPAE_PAGE_IS_RD_ALLOC		(2 << 2)
#define LPAE_PAGE_IS_RDWR_ALLOC		(3 << 2)

#define LPAE_PAGE_OS_NOALLOC		(0 << 0)
#define LPAE_PAGE_OS_WR_ALLOC		(1 << 0)
#define LPAE_PAGE_OS_RD_ALLOC		(2 << 0)
#define LPAE_PAGE_OS_RDWR_ALLOC		(3 << 0)

#define PVU_NUM_TLBS			64
#define PVU_NUM_ENTRIES			8

struct pvu_tlb_entry {
	u64		virt_addr;
	u64		phys_addr;
	u64		size;
	u64		flags;
};

struct pvu_dev {
	u32		*cfg_base;
	u32		*tlb_base;

	u32		num_tlbs;
	u32		num_entries;
	u16		max_virtid;

	u16		tlb_data[PVU_NUM_TLBS];
};

struct pvu_exception {
	u32		source;
};

u32 pvu_init_device(struct pvu_dev *dev, u16 max_virtid);

void pvu_tlb_enable(struct pvu_dev *dev, u16 tlbnum);
void pvu_tlb_disable(struct pvu_dev *dev, u16 tlbnum);

u32 pvu_tlb_is_enabled(struct pvu_dev *dev, u16 tlbnum);
int pvu_tlb_chain(struct pvu_dev *dev, u16 tlbnum, u16 tlb_next);
u32 pvu_tlb_next(struct pvu_dev *dev, u16 tlbnum);

u32 pvu_tlb_alloc(struct pvu_dev *dev, u16 virtid);
void pvu_tlb_flush(struct pvu_dev *dev, u16 tlbnum);

void pvu_entry_enable(struct pvu_dev *dev, u16 tlbnum, u8 index);
void pvu_entry_disable(struct pvu_dev *dev, u16 tlbnum, u8 index);
int pvu_entry_write(struct pvu_dev *dev, u16 tlbnum, u8 index,
	struct pvu_tlb_entry *ent);

void pvu_exception_get(struct pvu_dev *dev, struct pvu_exception *ex);
void pvu_exception_clear(struct pvu_dev *dev);

int pvu_entrylist_create(u64 ipa, u64 pa, u64 map_size,
	u64 flags, struct pvu_tlb_entry *entlist, u32 num_entries);
void pvu_entrylist_sort(struct pvu_tlb_entry *entlist, u32 num_entries);

#endif /* __TI_NAVSS_PVU_H__ */
