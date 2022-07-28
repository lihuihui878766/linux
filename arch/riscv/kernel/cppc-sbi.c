#ifdef CONFIG_ACPI_CPPC_LIB
#include <asm/sbi.h>
#include <acpi/cppc_acpi.h>

struct sbi_cppc_data {
	u64 reg;
	u64 val;
	struct sbiret ret;
};

static void sbi_cpc_read(void *read_data)
{
	struct sbi_cppc_data *data = (struct sbi_cppc_data *) read_data;

	data->ret = sbi_ecall(SBI_EXT_PSM, SBI_PSM_CPC_READ_FFH,
			data->reg, 0,
			0, 0, 0, 0);
}

static void sbi_cpc_write(void *write_data)
{
	struct sbi_cppc_data *data = (struct sbi_cppc_data *) write_data;

	data->ret = sbi_ecall(SBI_EXT_PSM, SBI_PSM_CPC_WRITE_FFH,
			data->reg, data->val, 0, 0, 0, 0);

}

/*
 * Refer to drivers/acpi/cppc_acpi.c for the description of the functions
 * below.
 */
bool cpc_ffh_supported(void)
{
	return true;
}

int cpc_read_ffh(int cpu, struct cpc_reg *reg, u64 *val)
{
	struct sbi_cppc_data data;

	if (WARN_ON_ONCE(irqs_disabled()))
		return -EPERM;

	data.reg = reg->address;

	smp_call_function_single(cpu, sbi_cpc_read, &data, 1);

	*val = data.ret.value;

	return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
}

int cpc_write_ffh(int cpu, struct cpc_reg *reg, u64 val)
{
	struct sbi_cppc_data data;

	if (WARN_ON_ONCE(irqs_disabled()))
		return -EPERM;

	data.reg = reg->address;
	data.val = val;

	smp_call_function_single(cpu, sbi_cpc_write, &data, 1);

	return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
}
#endif /* CONFIG_ACPI_CPPC_LIB */
