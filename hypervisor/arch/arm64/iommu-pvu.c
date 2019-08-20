/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) 2018 Texas Instruments Incorporated - http://www.ti.com/
 *
 * IOMMU driver for TI NAVSS PVU hardware
 *
 * Uses the ti-navss-pvu library to implement the iommu functionality
 * Unlike SMMU, PVU hosts the translation tables in the TLB MMRs
 * There will be multiple translation entries chained and spread across
 * multiple TLBs. For optimal usage, the entries should be sorted and
 * programmed in the decreasing order of size.
 *
 * Therefore, iommu_map_memory only creates data structures, actual register
 * programming is deffered till the iommu_config_commit callback
 *
 * PVU is mostly used in a one-time config manner. So no support for
 * iommu_unmap_memory
 *
 * Authors:
 *  Nikhil Devshatwar <nikhil.nd@ti.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/entry.h>
#include <jailhouse/paging.h>
#include <jailhouse/cell.h>
#include <jailhouse/control.h>
#include <jailhouse/unit.h>
#include <asm/iommu.h>
#include "ti-navss-pvu.h"

#define MAX_VIRTID		  7
#define MAX_PVU_ENTRIES		(PAGE_SIZE / sizeof (struct pvu_tlb_entry))

static struct pvu_dev pvu_units[JAILHOUSE_MAX_IOMMU_UNITS];
static unsigned int pvu_count;

/*
 * Setup TLB entries for the given virtid in all of PVU instances
 * Chain the TLB to next available if running out of entries in a TLB
 * Enables all the TLBs written to
 */
static int pvu_iommu_cfg_entries(struct cell *cell, u8 virtid)
{
	u32 inst;
	int i, ret, tlb_next, tlbnum, idx, num_ent;
	struct pvu_tlb_entry *ent, *cell_entries;
	struct pvu_dev *dev;

	cell_entries = cell->arch.iommu_pvu.entries;
	num_ent = cell->arch.iommu_pvu.ent_count;
	if (num_ent == 0 || cell_entries == NULL)
		return 0;

	for (inst = 0; inst < pvu_count; inst++) {
		dev = &pvu_units[inst];
		if (pvu_tlb_is_enabled(dev, virtid))
			continue;

		tlbnum = virtid;
		for (i = 0; i < num_ent; i++) {

			ent = &cell_entries[i];
			idx = i % dev->num_entries;

			if (idx == 0 && i >= dev->num_entries) {

				tlb_next = pvu_tlb_alloc(dev, virtid);
				if (tlb_next < 0)
					return -ENOMEM;
				pvu_tlb_chain(dev, tlbnum, tlb_next);
				pvu_tlb_enable(dev, tlbnum);
				tlbnum = tlb_next;
			}

			ret = pvu_entry_write(dev, tlbnum, idx, ent);
			if (ret)
				return ret;
		}
		pvu_tlb_enable(dev, tlbnum);
	}
	return 0;
}

/*
 * Add to the data structures to map a memory region
 * Actual TLB and entry programming is deferred till config_commit call
 * Keep a count of total entries populated till now
 */
int pvu_iommu_map_memory(struct cell *cell,
		const struct jailhouse_memory *mem)
{
	struct pvu_tlb_entry *ent;
	u32 flags = 0;
	int size, ret;

	if (pvu_count == 0)
		return 0;

	if ((mem->flags & JAILHOUSE_MEM_DMA) == 0)
		return 0;

	if (cell->arch.iommu_pvu.ent_count == MAX_PVU_ENTRIES)
		return -ENOMEM;

	if (mem->flags & JAILHOUSE_MEM_READ)
		flags |= (LPAE_PAGE_PERM_UR | LPAE_PAGE_PERM_SR);
	if (mem->flags & JAILHOUSE_MEM_WRITE)
		flags |= (LPAE_PAGE_PERM_UW | LPAE_PAGE_PERM_SW);
	if (mem->flags & JAILHOUSE_MEM_EXECUTE)
		flags |= (LPAE_PAGE_PERM_UX | LPAE_PAGE_PERM_SX);

	flags |= (LPAE_PAGE_MEM_WRITETHROUGH | LPAE_PAGE_OUTER_SHARABLE |
		LPAE_PAGE_IS_NOALLOC | LPAE_PAGE_OS_NOALLOC);

	ent = &cell->arch.iommu_pvu.entries[cell->arch.iommu_pvu.ent_count];
	size = MAX_PVU_ENTRIES - cell->arch.iommu_pvu.ent_count;

	ret = pvu_entrylist_create(mem->virt_start, mem->phys_start, mem->size,
			flags, ent, size);
	if (ret < 0)
		return ret;

	cell->arch.iommu_pvu.ent_count += ret;
	return 0;
}

int pvu_iommu_unmap_memory(struct cell *cell,
		const struct jailhouse_memory *mem)
{
	/*
	 * dummy unmap for now
	 * PVU is to be used to map everything at once
	 */
	return 0;
}

/*
 * Actual TLB entry programming is done at this point
 * Sort all the PVU entries in the decreasing order of size
 * This is useful to get the least average translation latency
 * All instances are configured with same entries
 */
int pvu_iommu_config_commit(struct cell *cell)
{
	int ret, i, virtid;

	if (pvu_count == 0)
		return 0;

	if (!cell) {
		return 0;
	}

	pvu_entrylist_sort(cell->arch.iommu_pvu.entries, cell->arch.iommu_pvu.ent_count);

	for_each_stream_id(virtid, cell->config, i) {
		if (virtid > MAX_VIRTID)
			continue;

		ret = pvu_iommu_cfg_entries(cell, virtid);
		if (ret)
			return ret;
	}

	cell->arch.iommu_pvu.ent_count = 0;
	return ret;
}

static int pvu_iommu_cell_init(struct cell *cell)
{
	struct pvu_dev *dev;
	int i, virtid;

	if (pvu_count == 0)
		return 0;

	cell->arch.iommu_pvu.ent_count = 0;
	cell->arch.iommu_pvu.entries = page_alloc(&mem_pool, 1);
	if (!cell->arch.iommu_pvu.entries)
		return -ENOMEM;

	dev = &pvu_units[0];
	for_each_stream_id(virtid, cell->config, i) {
		if (virtid > MAX_VIRTID)
			continue;

		if (pvu_tlb_is_enabled(dev, virtid)) {
			printk("PVU: WARN: virtid %d already enabled\n", virtid);
			/* TODO: VirtID modulation */
		}
	}
	return 0;
}

static int pvu_iommu_flush_context(u16 virtid)
{
	struct pvu_dev *dev;
	int i, tlbnum, next;

	for (i = 0; i < pvu_count; i++) {

		dev = &pvu_units[i];
		tlbnum = virtid;

		while (tlbnum) {

			next = pvu_tlb_next(dev, tlbnum);
			pvu_tlb_flush(dev, tlbnum);
			tlbnum = next;
		}
	}
	return 0;
}

static void pvu_iommu_cell_exit(struct cell *cell)
{
	int i, virtid;

	if (pvu_count == 0)
		return;

	for_each_stream_id(virtid, cell->config, i) {
		if (virtid > MAX_VIRTID)
			continue;

		pvu_iommu_flush_context(virtid);
	}

	cell->arch.iommu_pvu.ent_count = 0;
	page_free(&mem_pool, cell->arch.iommu_pvu.entries, 1);
	cell->arch.iommu_pvu.entries = NULL;
}

static int pvu_iommu_init(void)
{
	struct jailhouse_iommu *iommu;
	struct pvu_dev *dev;
	int i, ret;

	for (i = 0; i < JAILHOUSE_MAX_IOMMU_UNITS; i++) {

		iommu = &system_config->platform_info.arm.iommu_units[i];
		if (iommu->type != JAILHOUSE_IOMMU_PVU)
			continue;

		dev = &pvu_units[pvu_count];
		dev->cfg_base = paging_map_device(iommu->pvu.cfg_base,
					iommu->pvu.cfg_size);
		dev->tlb_base = paging_map_device(iommu->pvu.tlb_base,
					iommu->pvu.tlb_size);

		ret = pvu_init_device(dev, MAX_VIRTID);
		if (ret)
			return ret;

		pvu_count++;
	}

	return pvu_iommu_cell_init(&root_cell);
}

DEFINE_UNIT_SHUTDOWN_STUB(pvu_iommu);
DEFINE_UNIT_MMIO_COUNT_REGIONS_STUB(pvu_iommu);
DEFINE_UNIT(pvu_iommu, "PVU IOMMU");
