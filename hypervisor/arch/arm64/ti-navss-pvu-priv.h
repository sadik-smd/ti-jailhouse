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

#ifndef __TI_NAVSS_PVU_PRIV_H__
#define __TI_NAVSS_PVU_PRIV_H__

#define PVU_CONFIG_NTLB_MASK		(0xff)
#define PVU_CONFIG_NENT_MASK		(0xf << 16)

#define PVU_MAX_VIRTID_MASK		(0xfff)

#define PVU_enable_EN			(0x1)
#define PVU_enable_DIS			(0x0)
#define PVU_enable_MASK			(0x1)

struct pvu_hw_cfg {
	u32		pid;
	u32		config;
	u8		resv_16[8];
	u32		enable;
	u32		virtid_map1;
	u32		virtid_map2;
	u8		resv_48[20];
	u32		exception_logging_disable;
	u8		resv_260[208];
	u32		destination_id;
	u8		resv_288[24];
	u32		exception_logging_control;
	u32		exception_logging_header0;
	u32		exception_logging_header1;
	u32		exception_logging_data0;
	u32		exception_logging_data1;
	u32		exception_logging_data2;
	u32		exception_logging_data3;
	u8		resv_320[4];
	u32		exception_pend_set;
	u32		exception_pend_clear;
	u32		exception_ENABLE_set;
	u32		exception_ENABLE_clear;
	u32		eoi_reg;
};

#define PVU_TLB_ENTRY_VALID		(2)
#define PVU_TLB_ENTRY_INVALID		(0)
#define PVU_TLB_ENTRY_MODE_MASK		(0x3 << 30)
#define PVU_TLB_ENTRY_FLAG_MASK		(0xff7f)
#define PVU_TLB_ENTRY_PGSIZE_MASK	(0xf << 16)

struct pvu_hw_tlb_entry {
	u32		reg0;
	u32		reg1;
	u32		reg2;
	u32		reg3;
	u32		reg4;
	u32		reg5;
	u32		reg6;
	u32		reg7;
};

#define PVU_TLB_EN_MASK			(1 << 31)
#define PVU_TLB_LOG_DIS_MASK		(1 << 30)
#define PVU_TLB_FAULT_MASK		(1 << 29)
#define PVU_TLB_CHAIN_MASK		(0xfff)

struct pvu_hw_tlb {
	u32			chain;
	u8			resv_32[28];
	struct pvu_hw_tlb_entry	entry[8];
	u8			resv_4096[3808];
};

#endif /* __TI_NAVSS_PVU_PRIV_H__ */
