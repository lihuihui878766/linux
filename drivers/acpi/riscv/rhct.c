// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#define pr_fmt(fmt)	"ACPI: RHCT: " fmt

#include <linux/acpi.h>

/* Root pointer to the mapped RHCT table */
static struct acpi_table_header *rhct_table;

int acpi_get_riscv_isa(unsigned int cpu, char *isa)
{
	struct acpi_rhct_node *node, *ref_node, *end;
	struct acpi_table_rhct *rhct;
	struct acpi_rhct_isa_string *isa_node;
	u32 acpi_cpu_id = get_acpi_id_for_cpu(cpu);
	acpi_status status;
	int i, j;

	if (acpi_disabled) {
		pr_info("acpi_get_riscv_isa: acpi is disabled\n");
		return -1;
	}

	status = acpi_get_table(ACPI_SIG_RHCT, 0, &rhct_table);
	if (ACPI_FAILURE(status)) {
		pr_warn_once("No RHCT table found, CPU capabilities may be inaccurate\n");
		return -1;
	}

	rhct = (struct acpi_table_rhct *)rhct_table;

	node = ACPI_ADD_PTR(struct acpi_rhct_node, rhct, rhct->node_offset);
	end = ACPI_ADD_PTR(struct acpi_rhct_node, rhct, rhct->header.length);

	for (i = 0; i < rhct->node_count; i++) {
		if (node >= end)
			break;
		switch (node->type) {
			struct acpi_rhct_hart_info *hart_info;

		case ACPI_RHCT_NODE_HART_INFO:
			hart_info = (struct acpi_rhct_hart_info *)node->node_data;
			if (acpi_cpu_id != hart_info->acpi_proc_id)
				break;
			for (j = 0; j < hart_info->num_offsets; j++) {
				ref_node = ACPI_ADD_PTR(struct acpi_rhct_node, rhct, hart_info->node_offset[j]);
				if (ref_node->type == ACPI_RHCT_NODE_ISA_STRING) {
					isa_node = (struct acpi_rhct_isa_string *)ref_node->node_data;
					strncpy(isa, isa_node->isa, isa_node->isa_length);
					acpi_put_table(rhct_table);
					return 0;
				}
			}
			break;
		}
		node = ACPI_ADD_PTR(struct acpi_rhct_node, node, node->length);
	}

	acpi_put_table(rhct_table);
	return -1;
}
