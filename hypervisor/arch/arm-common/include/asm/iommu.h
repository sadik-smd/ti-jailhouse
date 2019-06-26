/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) 2018 Texas Instruments Incorporated - http://www.ti.com
 *
 * Authors:
 *  Nikhil Devshatwar <nikhil.nd@ti.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef _JAILHOUSE_ASM_IOMMU_H
#define _JAILHOUSE_ASM_IOMMU_H

#include <jailhouse/types.h>
#include <jailhouse/utils.h>
#include <jailhouse/config.h>
#include <jailhouse/cell-config.h>


int pvu_iommu_map_memory(struct cell *cell,
		const struct jailhouse_memory *mem);
int pvu_iommu_unmap_memory(struct cell *cell,
		const struct jailhouse_memory *mem);
int pvu_iommu_config_commit(struct cell *cell);

int iommu_map_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem);
int iommu_unmap_memory_region(struct cell *cell,
			      const struct jailhouse_memory *mem);
int iommu_config_commit(struct cell *cell);
#endif
