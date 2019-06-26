/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) 2018 Texas Instruments Incorporated - http://www.ti.com/
 *
 * TI NAVSS PVU library
 *
 * Hypervisor agnostic library for configuring PVU as IOMMU
 * Provides primitive functions for configuring PVU TLB entries
 * Supports enable/disable of each entry/TLB individually
 * Support chaining of TLB entries to accommodate higher number of entries
 * Utility functions for splitting a memory region into valid entries
 * and storting based on the page size.
 *
 * Authors:
 *  Nikhil Devshatwar <nikhil.nd@ti.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include "ti-navss-pvu.h"
#include "ti-navss-pvu-priv.h"
#include <jailhouse/mmio.h>

static const u64 PVU_PAGE_SIZE_BYTES[] = {
	[LPAE_PAGE_SZ_4K]		=   4 * 1024,
	[LPAE_PAGE_SZ_16K]		=  16 * 1024,
	[LPAE_PAGE_SZ_64K]		=  64 * 1024,
	[LPAE_PAGE_SZ_2M]		=   2 * 1024 * 1024,
	[LPAE_PAGE_SZ_32M]		=  32 * 1024 * 1024,
	[LPAE_PAGE_SZ_512M]		= 512 * 1024 * 1024,
	[LPAE_PAGE_SZ_1G]		=   1 * 1024 * 1024 * 1024,
	[LPAE_PAGE_SZ_16G]		=  16ULL * 1024 * 1024 * 1024,
};

static inline u32 is_aligned(u64 addr, u64 size)
{
	return (addr % size) == 0;
}

u32 pvu_init_device(struct pvu_dev *dev, u16 max_virtid)
{
	struct pvu_hw_cfg *cfg;
	int i;

	cfg = (struct pvu_hw_cfg *)dev->cfg_base;
	/* TODO Add pid check here */

	dev->num_tlbs = mmio_read32_field(&cfg->config,
			PVU_CONFIG_NTLB_MASK);
	dev->num_entries = mmio_read32_field(&cfg->config,
			PVU_CONFIG_NENT_MASK);

	if (max_virtid >= dev->num_tlbs) {
		printk("ERROR: Max virtid(%d) should be less than num_tlbs(%d)\n",
			max_virtid, dev->num_tlbs);
		return -EINVAL;
	}

	dev->max_virtid = max_virtid;
	mmio_write32(&cfg->virtid_map1, 0);
	mmio_write32_field(&cfg->virtid_map2, PVU_MAX_VIRTID_MASK, max_virtid);

	for (i = 0; i < dev->num_tlbs; i++) {

		pvu_tlb_disable(dev, i);
		if (i < dev->max_virtid)
			dev->tlb_data[i] = 0x0 | i << dev->num_entries;
		else
			dev->tlb_data[i] = 0x0;
	}

	/* Enable all types of exceptions */
	mmio_write32(&cfg->exception_logging_disable, 0x0);
	mmio_write32(&cfg->exception_logging_control, 0x0);
	mmio_write32_field(&cfg->enable, PVU_enable_MASK, PVU_enable_EN);
	return 0;
}

void pvu_tlb_enable(struct pvu_dev *dev, u16 tlbnum)
{
	struct pvu_hw_tlb *tlb;

	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;
	/* Also enable fault logging for this TLB */
	mmio_write32_field(&tlb->chain, PVU_TLB_LOG_DIS_MASK, 0);
	mmio_write32_field(&tlb->chain, PVU_TLB_EN_MASK, 1);
}

void pvu_tlb_disable(struct pvu_dev *dev, u16 tlbnum)
{
	struct pvu_hw_tlb *tlb;

	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;
	/* Also disable fault logging for this TLB */
	mmio_write32_field(&tlb->chain, PVU_TLB_EN_MASK, 0);
	mmio_write32_field(&tlb->chain, PVU_TLB_LOG_DIS_MASK, 1);
}

u32 pvu_tlb_is_enabled(struct pvu_dev *dev, u16 tlbnum)
{
	struct pvu_hw_tlb *tlb;

	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;
	if (mmio_read32_field(&tlb->chain, PVU_TLB_EN_MASK))
		return 1;
	else
		return 0;
}

int pvu_tlb_chain(struct pvu_dev *dev, u16 tlbnum, u16 tlb_next)
{
	struct pvu_hw_tlb *tlb;

	if (tlb_next <= tlbnum || tlb_next <= dev->max_virtid)
		return -EINVAL;

	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;
	mmio_write32_field(&tlb->chain, PVU_TLB_CHAIN_MASK, tlb_next);
	return 0;
}

u32 pvu_tlb_next(struct pvu_dev *dev, u16 tlbnum)
{
	struct pvu_hw_tlb *tlb;

	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;
	return mmio_read32_field(&tlb->chain, PVU_TLB_CHAIN_MASK);
}

u32 pvu_tlb_alloc(struct pvu_dev *dev, u16 virtid)
{
	int i;

	for (i = dev->max_virtid + 1; i < dev->num_tlbs; i++) {
		if (dev->tlb_data[i] == 0) {
			dev->tlb_data[i] = virtid << dev->num_entries;
			return i;
		}
	}
	return 0;
}

void pvu_tlb_flush(struct pvu_dev *dev, u16 tlbnum)
{
	struct pvu_hw_tlb_entry *entry;
	struct pvu_hw_tlb *tlb;
	u32 i;

	pvu_tlb_disable(dev, tlbnum);
	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;

	for (i = 0; i < dev->num_entries; i++) {

		entry = &tlb->entry[i];
		mmio_write32(&entry->reg0, 0x0);
		mmio_write32(&entry->reg1, 0x0);
		mmio_write32(&entry->reg2, 0x0);
		mmio_write32(&entry->reg4, 0x0);
		mmio_write32(&entry->reg5, 0x0);
		mmio_write32(&entry->reg6, 0x0);
	}

	mmio_write32(&tlb->chain, 0x0);
	pvu_tlb_disable(dev, tlbnum);

	if (i < dev->max_virtid)
		dev->tlb_data[tlbnum] = 0x0 | i << dev->num_entries;
	else
		dev->tlb_data[tlbnum] = 0x0;

}

void pvu_entry_enable(struct pvu_dev *dev, u16 tlbnum, u8 index)
{
	struct pvu_hw_tlb_entry *entry;
	struct pvu_hw_tlb *tlb;

	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;
	entry = &tlb->entry[index];

	mmio_write32_field(&entry->reg2, PVU_TLB_ENTRY_MODE_MASK,
		PVU_TLB_ENTRY_VALID);

	dev->tlb_data[tlbnum] |= (1 << index);
}

void pvu_entry_disable(struct pvu_dev *dev, u16 tlbnum, u8 index)
{
	struct pvu_hw_tlb_entry *entry;
	struct pvu_hw_tlb *tlb;

	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;
	entry = &tlb->entry[index];

	mmio_write32_field(&entry->reg2, PVU_TLB_ENTRY_MODE_MASK,
		PVU_TLB_ENTRY_INVALID);

	dev->tlb_data[tlbnum] &= ~(1 << index);
}

/*
 * Primitive method to program the TLB entry with some error checks
 * Size should be one of the supported size from PVU_PAGE_SIZE_BYTES array
 * Both virtual address and physical address should be aligned to size
 * Enables the entry after writing
 **/
int pvu_entry_write(struct pvu_dev *dev, u16 tlbnum, u8 index,
	struct pvu_tlb_entry *ent)
{
	/* TODO check if size is supported enum and addr is aligned*/
	struct pvu_hw_tlb_entry *entry;
	struct pvu_hw_tlb *tlb;
	u8 pgsz;

	tlb = (struct pvu_hw_tlb *)dev->tlb_base + tlbnum;
	entry = &tlb->entry[index];

	for (pgsz = 0; pgsz < ARRAY_SIZE(PVU_PAGE_SIZE_BYTES); pgsz++) {
		if (ent->size == PVU_PAGE_SIZE_BYTES[pgsz])
			break;
	}

	if (pgsz >= ARRAY_SIZE(PVU_PAGE_SIZE_BYTES)) {
		printk("ERROR: %s: Unsupported page size %llx\n",
			__func__, ent->size);
		return -EINVAL;
	}

	if (!is_aligned(ent->virt_addr, ent->size) ||
	    !is_aligned(ent->phys_addr, ent->size)) {
		printk("ERROR: %s: Address %llx => %llx  not aligned with size %llx\n",
			__func__, ent->virt_addr, ent->phys_addr, ent->size);
		return -EINVAL;
	}

	mmio_write32(&entry->reg0, ent->virt_addr & 0xffffffff);
	mmio_write32_field(&entry->reg1, 0xffff, (ent->virt_addr >> 32));
	mmio_write32(&entry->reg2, 0x0);

	mmio_write32(&entry->reg4, ent->phys_addr & 0xffffffff);
	mmio_write32_field(&entry->reg5, 0xffff, (ent->phys_addr >> 32));
	mmio_write32(&entry->reg6, 0x0);

	mmio_write32_field(&entry->reg2, PVU_TLB_ENTRY_PGSIZE_MASK, pgsz);
	mmio_write32_field(&entry->reg2, PVU_TLB_ENTRY_FLAG_MASK, ent->flags);

	/* Do we need "DSB NSH" here to make sure all writes are finised? */
	pvu_entry_enable(dev, tlbnum, index);
	return 0;
}

void pvu_exception_get(struct pvu_dev *dev, struct pvu_exception *ex)
{
	/* TODO */
}

void pvu_exception_clear(struct pvu_dev *dev)
{
	/* TODO */
}

/* Given a memory region, cut it into multiple chunks such that
 * each region is of a PVU supported page size and the region start
 * address is aligned to the page size
 * Returns number of entries populated
 */
int pvu_entrylist_create(u64 ipa, u64 pa, u64 map_size,
	u64 flags, struct pvu_tlb_entry *entlist, u32 num_entries)
{
	u8 num_sizes = ARRAY_SIZE(PVU_PAGE_SIZE_BYTES);
	u64 page_size, vaddr, paddr;
	s64 size, i, aligned, count;

	vaddr = ipa;
	paddr = pa;
	size = map_size;
	count  = 0;

	while (size) {

		if (count == num_entries) {
			printk("ERROR: Need more TLB entries for mapping %llx => %llx with size %llx\n",
				ipa, pa, map_size);
			return -EINVAL;
		}

		aligned = 0;

		/* Try size from largest to smallest for mapping */
		for (i = num_sizes - 1; i >= 0; i--) {

			page_size = PVU_PAGE_SIZE_BYTES[i];

			if (is_aligned(vaddr, page_size) &&
			    is_aligned(paddr, page_size) &&
			    size >= page_size) {

				entlist[count].virt_addr = vaddr;
				entlist[count].phys_addr = paddr;
				entlist[count].size = page_size;
				entlist[count].flags = flags;

				count++;
				vaddr += page_size;
				paddr += page_size;
				size -= page_size;
				aligned = 1;
				break;
			}
		}

		if (!aligned) {
			printk("ERROR: Addresses %llx %llx aren't aligned to any of the allowed page sizes\n",
				vaddr, paddr);
			return -EINVAL;
		}
	}
	return count;
}

/* Sort the list of entries in decreasing order of page size */
void pvu_entrylist_sort(struct pvu_tlb_entry *entlist, u32 num_entries)
{
	int i, j;
	struct pvu_tlb_entry temp;

	for (i = 0; i < num_entries; i++) {
		for (j = i; j < num_entries; j++) {
			if (entlist[i].size < entlist[j].size) {
				temp = entlist[i];
				entlist[i] = entlist[j];
				entlist[j] = temp;
			}
		}
	}
}
