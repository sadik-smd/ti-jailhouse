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

#include <jailhouse/control.h>
#include <jailhouse/config.h>
#include <asm/iommu.h>

int iommu_map_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	return 0;
}

int iommu_unmap_memory_region(struct cell *cell,
			      const struct jailhouse_memory *mem)
{
	return 0;
}

int iommu_config_commit(struct cell *cell)
{
	return 0;
}
