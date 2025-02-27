/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2013-2014, Linaro Ltd.
 *	Author: Al Stone <al.stone@linaro.org>
 *	Author: Graeme Gregory <graeme.gregory@linaro.org>
 *	Author: Hanjun Guo <hanjun.guo@linaro.org>
 *
 *  Copyright (C) 2021-2023, Ventana Micro Systems Inc.
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 */

#ifndef _ASM_ACPI_H
#define _ASM_ACPI_H

/* Basic configuration for ACPI */
#ifdef CONFIG_ACPI

typedef u64 phys_cpuid_t;
#define PHYS_CPUID_INVALID INVALID_HARTID

/* ACPI table mapping after acpi_permanent_mmap is set */
void __iomem *acpi_os_ioremap(acpi_physical_address phys, acpi_size size);
#define acpi_os_ioremap acpi_os_ioremap

#define acpi_strict 1	/* No out-of-spec workarounds on RISC-V */
extern int acpi_disabled;
extern int acpi_noirq;
extern int acpi_pci_disabled;

#ifdef	CONFIG_ACPI_APEI
/*
 * acpi_disable_cmcff is used in drivers/acpi/apei/hest.c for disabling
 * IA-32 Architecture Corrected Machine Check (CMC) Firmware-First mode
 * with a kernel command line parameter "acpi=nocmcoff". But we don't
 * have this IA-32 specific feature on ARM64, this definition is only
 * for compatibility.
 */
#define acpi_disable_cmcff 1
static inline pgprot_t arch_apei_get_mem_attribute(phys_addr_t addr)
{
	/*
	 * Until we have a way to look for EFI memory attributes.
	 */
	return PAGE_KERNEL;
}
#else /* CONFIG_ACPI_APEI */
#define acpi_disable_cmcff 0
#endif /* !CONFIG_ACPI_APEI */

static inline void disable_acpi(void)
{
	acpi_disabled = 1;
	acpi_pci_disabled = 1;
	acpi_noirq = 1;
}

static inline void enable_acpi(void)
{
	acpi_disabled = 0;
	acpi_pci_disabled = 0;
	acpi_noirq = 0;
}

/*
 * The ACPI processor driver for ACPI core code needs this macro
 * to find out whether this cpu was already mapped (mapping from CPU hardware
 * ID to CPU logical ID) or not.
 */
#define cpu_physical_id(cpu) cpuid_to_hartid_map(cpu)

/*
 * Since MADT must provide at least one RINTC structure, the
 * CPU will be always available in MADT on RISC-V.
 */
static inline bool acpi_has_cpu_in_madt(void)
{
	return true;
}

static inline void arch_fix_phys_package_id(int num, u32 slot) { }

void acpi_init_rintc_map(void);
struct acpi_madt_rintc *acpi_cpu_get_madt_rintc(int cpu);
static inline u32 get_acpi_id_for_cpu(int cpu)
{
	return acpi_cpu_get_madt_rintc(cpu)->uid;
}

int acpi_get_riscv_isa(struct acpi_table_header *table,
		       unsigned int cpu, const char **isa);

void acpi_get_cbo_block_size(struct acpi_table_header *table, u32 *cbom_size,
			     u32 *cboz_size, u32 *cbop_size);
#else
static inline void acpi_init_rintc_map(void) { }
static inline struct acpi_madt_rintc *acpi_cpu_get_madt_rintc(int cpu)
{
	return NULL;
}

static inline int acpi_get_riscv_isa(struct acpi_table_header *table,
				     unsigned int cpu, const char **isa)
{
	return -EINVAL;
}

static inline void acpi_get_cbo_block_size(struct acpi_table_header *table,
					   u32 *cbom_size, u32 *cboz_size,
					   u32 *cbop_size) { }

#endif /* CONFIG_ACPI */

#ifdef CONFIG_ACPI_NUMA
int acpi_numa_get_nid(unsigned int cpu);
void acpi_map_cpus_to_nodes(void);
#else
static inline int acpi_numa_get_nid(unsigned int cpu) { return NUMA_NO_NODE; }
static inline void acpi_map_cpus_to_nodes(void) { }
#endif /* CONFIG_ACPI_NUMA */

#endif /*_ASM_ACPI_H*/
