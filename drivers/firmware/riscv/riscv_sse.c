// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Rivos Inc.
 */

#define pr_fmt(fmt) "sse: " fmt

#include <linux/cpu.h>
#include <acpi/ghes.h>
#include <linux/acpi.h>
#include <linux/cpuhotplug.h>
#include <linux/hardirq.h>
#include <linux/list.h>
#include <linux/percpu-defs.h>
#include <linux/reboot.h>
#include <linux/riscv_sse.h>
#include <linux/slab.h>

#include <asm/sbi.h>
#include <asm/sse.h>

struct sse_event {
	struct list_head list;
	u32 evt;
	u32 priority;
	sse_event_handler *handler;
	void *handler_arg;
	bool is_enabled;
	/* Only valid for global events */
	unsigned int cpu;

	union {
		struct sse_registered_event *global;
		struct sse_registered_event __percpu *local;
	};
};

static int sse_hp_state;
static bool sse_available;
static DEFINE_SPINLOCK(events_list_lock);
static LIST_HEAD(events);
static DEFINE_MUTEX(sse_mutex);

void sse_handle_event(struct sse_registered_event *reg_evt, struct pt_regs *regs)
{
	int ret;
	struct sse_event *evt = reg_evt->evt;

	ret = evt->handler(evt->evt, evt->handler_arg, regs);
	if (ret)
		pr_warn("event %x handler failed with error %d\n", reg_evt->evt_id, ret);
}

static bool sse_event_is_global(u32 evt)
{
	return !!(evt & SBI_SSE_EVENT_GLOBAL);
}

static
struct sse_event *sse_event_get(u32 evt)
{
	struct sse_event *sse_evt = NULL, *tmp;

	spin_lock(&events_list_lock);
	list_for_each_entry(tmp, &events, list) {
		if (tmp->evt == evt) {
			sse_evt = tmp;
			break;
		}
	}
	spin_unlock(&events_list_lock);

	return sse_evt;
}

static phys_addr_t sse_event_get_phys(struct sse_registered_event *reg_evt, void *addr)
{
	phys_addr_t phys;

	if (sse_event_is_global(reg_evt->evt_id))
		phys = virt_to_phys(addr);
	else
		phys = per_cpu_ptr_to_phys(addr);

	return phys;
}

static int sse_sbi_event_func(struct sse_event *event, unsigned long func)
{
	struct sbiret ret;
	u32 evt = event->evt;

	ret = sbi_ecall(SBI_EXT_SSE, func, evt, 0, 0, 0, 0, 0);
	if (ret.error)
		pr_err("Failed to execute func %lx, event %x, error %ld\n", func,
		       evt, ret.error);

	return sbi_err_map_linux_errno(ret.error);
}

static int sse_sbi_disable_event(struct sse_event *event)
{
	return sse_sbi_event_func(event, SBI_SSE_EVENT_DISABLE);
}

static int sse_sbi_enable_event(struct sse_event *event)
{
	return sse_sbi_event_func(event, SBI_SSE_EVENT_ENABLE);
}

static int sse_event_attr_get_no_lock(struct sse_registered_event *reg_evt,
				      unsigned long attr_id, unsigned long *val)
{
	struct sbiret sret;
	u32 evt = reg_evt->evt_id;
	unsigned long phys;

	phys = sse_event_get_phys(reg_evt, &reg_evt->attr_buf);

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_READ, evt,
				     attr_id, 1, phys, 0, 0);
	if (sret.error) {
		pr_err("Failed to get event %x attr %lx, error %ld\n", evt,
		       attr_id, sret.error);
		return sbi_err_map_linux_errno(sret.error);
	}

	*val = reg_evt->attr_buf;

	return 0;
}

static int sse_event_attr_set_nolock(struct sse_registered_event *reg_evt,
				     unsigned long attr_id, unsigned long val)
{
	struct sbiret sret;
	u32 evt = reg_evt->evt_id;
	unsigned long phys;

	reg_evt->attr_buf = val;
	phys = sse_event_get_phys(reg_evt, &reg_evt->attr_buf);

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_ATTR_WRITE, evt,
				     attr_id, 1, phys, 0, 0);
	if (sret.error && sret.error != SBI_ERR_INVALID_STATE) {
		pr_err("Failed to set event %x attr %lx, error %ld\n", evt,
			attr_id, sret.error);
		return sbi_err_map_linux_errno(sret.error);
	}

	return 0;
}

static int sse_event_set_target_cpu_nolock(struct sse_event *event,
					   unsigned int cpu)
{
	unsigned int hart_id = cpuid_to_hartid_map(cpu);
	struct sse_registered_event *reg_evt = event->global;
	u32 evt = event->evt;
	bool was_enabled;
	int ret;

	if (!sse_event_is_global(evt))
		return -EINVAL;

	was_enabled = event->is_enabled;
	if (was_enabled)
		sse_sbi_disable_event(event);
	do {
		ret = sse_event_attr_set_nolock(reg_evt,
						SBI_SSE_ATTR_PREFERRED_HART,
						hart_id);
	} while (ret == -EINVAL);

	if (ret == 0)
		event->cpu = cpu;

	if (was_enabled)
		sse_sbi_enable_event(event);

	return 0;
}

int sse_event_set_target_cpu(struct sse_event *event, unsigned int cpu)
{
	int ret;

	mutex_lock(&sse_mutex);
	cpus_read_lock();

	if (!cpu_online(cpu))
		return -EINVAL;

	ret = sse_event_set_target_cpu_nolock(event, cpu);

	cpus_read_unlock();
	mutex_unlock(&sse_mutex);

	return ret;
}

static int sse_event_init_registered(unsigned int cpu,
				     struct sse_registered_event *reg_evt,
				     struct sse_event *event)
{
	reg_evt->evt_id = event->evt;
	reg_evt->evt = event;
	reg_evt->interrupted_state_phys =
			sse_event_get_phys(reg_evt, &reg_evt->interrupted);

	sse_init_event(cpu, reg_evt);

	return 0;
}

static void sse_event_free_registered(struct sse_registered_event *reg_evt)
{
	sse_free_event(reg_evt);
}

static int sse_event_alloc_global(struct sse_event *event)
{
	int err;
	struct sse_registered_event *reg_evt;

	reg_evt = kzalloc(sizeof(*reg_evt), GFP_KERNEL);
	if (!reg_evt)
		return -ENOMEM;

	event->global = reg_evt;
	err = sse_event_init_registered(smp_processor_id(), reg_evt,
					event);
	if (err)
		kfree(reg_evt);

	return err;
}

static int sse_event_alloc_local(struct sse_event *event)
{
	int err;
	unsigned int cpu, err_cpu;
	struct sse_registered_event *reg_evt;
	struct sse_registered_event __percpu *reg_evts;

	reg_evts = alloc_percpu(struct sse_registered_event);
	if (!reg_evts)
		return -ENOMEM;

	event->local = reg_evts;

	for_each_possible_cpu(cpu) {
		reg_evt = per_cpu_ptr(reg_evts, cpu);
		err = sse_event_init_registered(cpu, reg_evt, event);
		if (err) {
			err_cpu = cpu;
			goto err_free_per_cpu;
		}
	}

	return 0;

err_free_per_cpu:
	for_each_possible_cpu(cpu) {
		if (cpu == err_cpu)
			break;
		reg_evt = per_cpu_ptr(reg_evts, cpu);
		sse_event_free_registered(reg_evt);
	}

	free_percpu(reg_evts);

	return err;
}

static struct sse_event *sse_event_alloc(u32 evt,
					 u32 priority,
					 sse_event_handler *handler, void *arg)
{
	int err;
	struct sse_event *event;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return ERR_PTR(-ENOMEM);

	event->evt = evt;
	event->priority = priority;
	event->handler_arg = arg;
	event->handler = handler;

	if (sse_event_is_global(evt)) {
		err = sse_event_alloc_global(event);
		if (err)
			goto err_alloc_reg_evt;
	} else {
		err = sse_event_alloc_local(event);
		if (err)
			goto err_alloc_reg_evt;
	}

	return event;

err_alloc_reg_evt:
	kfree(event);

	return ERR_PTR(err);
}

static int sse_sbi_register_event(struct sse_event *event,
				  struct sse_registered_event *reg_evt)
{
	int ret;
	struct sbiret sret;
	u32 evt = event->evt;

	ret = sse_event_attr_set_nolock(reg_evt, SBI_SSE_ATTR_PRIO,
					     event->priority);
	if (ret)
		return ret;

	sret = sbi_ecall(SBI_EXT_SSE, SBI_SSE_EVENT_REGISTER, evt,
			 reg_evt->entry.pc, reg_evt->entry.arg, 0, 0, 0);
	if (sret.error)
		pr_err("Failed to register event %d, error %ld\n", evt,
		       sret.error);

	return sbi_err_map_linux_errno(sret.error);
}

static int sse_event_register_local(struct sse_event *event)
{
	int ret;
	struct sse_registered_event *reg_evt = per_cpu_ptr(event->local,
							   smp_processor_id());

	ret = sse_sbi_register_event(event, reg_evt);
	if (ret)
		pr_err("Failed to register event %x: err %d\n", event->evt,
		       ret);

	return ret;
}


static int sse_sbi_unregister_event(struct sse_event *event)
{
	return sse_sbi_event_func(event, SBI_SSE_EVENT_UNREGISTER);
}

struct sse_per_cpu_evt {
	struct sse_event *event;
	unsigned long func;
	int error;
};

static void sse_event_per_cpu_func(void *info)
{
	int ret;
	struct sse_per_cpu_evt *cpu_evt = info;

	if (cpu_evt->func == SBI_SSE_EVENT_REGISTER)
		ret = sse_event_register_local(cpu_evt->event);
	else
		ret = sse_sbi_event_func(cpu_evt->event, cpu_evt->func);

	if (ret)
		WRITE_ONCE(cpu_evt->error, 1);
}

static void sse_event_free(struct sse_event *event)
{
	unsigned int cpu;
	struct sse_registered_event *reg_evt;

	if (sse_event_is_global(event->evt)) {
		sse_event_free_registered(event->global);
		kfree(event->global);
	} else {
		for_each_possible_cpu(cpu) {
			reg_evt = per_cpu_ptr(event->local, cpu);
			sse_event_free_registered(reg_evt);
		}
		free_percpu(event->local);
	}

	kfree(event);
}

int sse_event_enable(struct sse_event *event)
{
	int ret = 0;
	struct sse_per_cpu_evt cpu_evt;

	mutex_lock(&sse_mutex);

	cpus_read_lock();
	if (sse_event_is_global(event->evt)) {
		ret = sse_sbi_enable_event(event);
		if (ret)
			goto out;

	} else {
		cpu_evt.event = event;
		cpu_evt.error = 0;
		cpu_evt.func = SBI_SSE_EVENT_ENABLE;
		on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
		if (READ_ONCE(cpu_evt.error)) {
			cpu_evt.func = SBI_SSE_EVENT_DISABLE;
			on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
			goto out;
		}
	}
	event->is_enabled = true;
out:
	cpus_read_unlock();
	mutex_unlock(&sse_mutex);

	return ret;
}


static void sse_event_disable_nolock(struct sse_event *event)
{
	struct sse_per_cpu_evt cpu_evt;

	if (sse_event_is_global(event->evt)) {
		sse_sbi_disable_event(event);
	} else {
		cpu_evt.event = event;
		cpu_evt.func = SBI_SSE_EVENT_DISABLE;
		on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
	}
}

void sse_event_disable(struct sse_event *event)
{
	mutex_lock(&sse_mutex);

	cpus_read_lock();
	sse_event_disable_nolock(event);
	event->is_enabled = false;
	cpus_read_unlock();

	mutex_unlock(&sse_mutex);
}

struct sse_event *sse_event_register(u32 evt, u32 priority,
				     sse_event_handler *handler, void *arg)
{
	struct sse_per_cpu_evt cpu_evt;
	struct sse_event *event;
	int ret = 0;

	if (!sse_available)
		return ERR_PTR(-EOPNOTSUPP);

	mutex_lock(&sse_mutex);
	if (sse_event_get(evt)) {
		pr_err("Event %x already registered\n", evt);
		ret = -EEXIST;
		goto out_unlock;
	}

	event = sse_event_alloc(evt, priority, handler, arg);
	if (IS_ERR(event)) {
		ret = PTR_ERR(event);
		goto out_unlock;
	}

	cpus_read_lock();
	if (sse_event_is_global(evt)) {
		unsigned long preferred_hart;

		ret = sse_event_attr_get_no_lock(event->global, SBI_SSE_ATTR_PREFERRED_HART,
					         &preferred_hart);
		if (ret)
			goto err_event_free;
		event->cpu = riscv_hartid_to_cpuid(preferred_hart);

		ret = sse_sbi_register_event(event, event->global);
		if (ret)
			goto err_event_free;

	} else {
		cpu_evt.event = event;
		cpu_evt.error = 0;
		cpu_evt.func = SBI_SSE_EVENT_REGISTER;
		on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
		if (READ_ONCE(cpu_evt.error)) {
			cpu_evt.func = SBI_SSE_EVENT_UNREGISTER;
			on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
			goto err_event_free;
		}
	}
	cpus_read_unlock();

	spin_lock(&events_list_lock);
	list_add(&event->list, &events);
	spin_unlock(&events_list_lock);

	mutex_unlock(&sse_mutex);

	return event;

err_event_free:
	cpus_read_unlock();
	sse_event_free(event);
out_unlock:
	mutex_unlock(&sse_mutex);

	return ERR_PTR(ret);
}

static void sse_event_unregister_nolock(struct sse_event *event)
{
	struct sse_per_cpu_evt cpu_evt;

	if (sse_event_is_global(event->evt)) {
		sse_sbi_unregister_event(event);
	} else {
		cpu_evt.event = event;
		cpu_evt.func = SBI_SSE_EVENT_UNREGISTER;
		on_each_cpu(sse_event_per_cpu_func, &cpu_evt, 1);
	}
}

void sse_event_unregister(struct sse_event *event)
{
	mutex_lock(&sse_mutex);

	cpus_read_lock();
	sse_event_unregister_nolock(event);
	cpus_read_unlock();

	spin_lock(&events_list_lock);
	list_del(&event->list);
	spin_unlock(&events_list_lock);

	sse_event_free(event);

	mutex_unlock(&sse_mutex);
}

static int sse_cpu_online(unsigned int cpu)
{
	struct sse_event *sse_evt;

	spin_lock(&events_list_lock);
	list_for_each_entry(sse_evt, &events, list) {
		if (sse_event_is_global(sse_evt->evt))
			continue;

		sse_event_register_local(sse_evt);
		if (sse_evt->is_enabled)
			sse_sbi_enable_event(sse_evt);
	}

	spin_unlock(&events_list_lock);

	return 0;
}

static int sse_cpu_teardown(unsigned int cpu)
{
	unsigned int next_cpu;
	struct sse_event *sse_evt;

	spin_lock(&events_list_lock);
	list_for_each_entry(sse_evt, &events, list) {
		if (!sse_event_is_global(sse_evt->evt)) {

			if (sse_evt->is_enabled)
				sse_sbi_disable_event(sse_evt);

			sse_sbi_unregister_event(sse_evt);
			continue;
		}

		if (sse_evt->cpu != smp_processor_id())
			continue;

		/* Update destination hart for global event */
		next_cpu = cpumask_any_but(cpu_online_mask, cpu);
		sse_event_set_target_cpu_nolock(sse_evt, next_cpu);
	}
	spin_unlock(&events_list_lock);

	return 0;
}

static void sse_reset(void)
{
	struct sse_event *event = NULL;

	list_for_each_entry(event, &events, list) {
		sse_event_disable_nolock(event);
		sse_event_unregister_nolock(event);
	}
}

/*
 * Mask all CPUs and unregister all events on panic, reboot or kexec.
 */
static int sse_reboot_notifier(struct notifier_block *nb, unsigned long action,
				void *data)
{
	cpuhp_remove_state(sse_hp_state);

	sse_reset();

	return NOTIFY_OK;
}

static struct notifier_block sse_reboot_nb = {
	.notifier_call = sse_reboot_notifier,
};

static int __init sse_init(void)
{
	int cpu, ret;

	if (sbi_probe_extension(SBI_EXT_SSE) <= 0) {
		pr_err("Missing SBI SSE extension\n");
		return -EOPNOTSUPP;
	}
	pr_info("SBI SSE extension detected\n");

	for_each_possible_cpu(cpu)
		INIT_LIST_HEAD(&events);

	ret = register_reboot_notifier(&sse_reboot_nb);
	if (ret) {
		pr_warn("Failed to register reboot notifier...\n");
		return ret;
	}

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "riscv/sse:online",
					sse_cpu_online, sse_cpu_teardown);
	if (ret < 0)
		goto remove_reboot;

	sse_hp_state = ret;
	sse_available = true;

	return 0;

remove_reboot:
	unregister_reboot_notifier(&sse_reboot_nb);

	return ret;

}
core_initcall(sse_init);

#define SSE_GHES_LIST_OF_CALLBACKS

struct sse_ghes_callback {
#ifdef SSE_GHES_LIST_OF_CALLBACKS
	struct list_head head;
#endif
	struct ghes *ghes;
	sse_event_handler *callback;
};

struct sse_ghes_event_data {
	struct list_head head;
	u32 event_num;
#ifdef SSE_GHES_LIST_OF_CALLBACKS
	struct list_head callback_list;
#else
	struct sse_ghes_callback *global_cb;
	struct sse_ghes_callback __percpu *local_cb;
#endif
	struct sse_event *event;
};

static DEFINE_SPINLOCK(sse_ghes_event_list_lock);
static LIST_HEAD(sse_ghes_event_list);

static int sse_ghes_handler(u32 event_num, void *arg, struct pt_regs *regs)
{
	struct sse_ghes_event_data *ev_data = arg;
	struct sse_ghes_callback *cb = NULL;
	int err = 0;

#ifdef SSE_GHES_LIST_OF_CALLBACKS
	list_for_each_entry(cb, &ev_data->callback_list, head) {
		if (cb && cb->ghes && cb->callback) {
			err = cb->callback(ev_data->event_num, cb->ghes, regs);
			break;
		}
	}
#else
	if (ev_data->event_num & SBI_SSE_EVENT_GLOBAL)
		cb = ev_data->global_cb;
	else
		cb = this_cpu_ptr(ev_data->local_cb);
	if (cb && cb->ghes && cb->callback)
		err = cb->callback(ev_data->event_num, cb->ghes, regs);
#endif

	if (err) {
		pr_err("%s: cpu%d: event 0x%x callback failed (error %d)\n",
			__func__, smp_processor_id(), event_num, err);
	}

	return err;
}

int sse_register_ghes(struct ghes *ghes, sse_event_handler *lo_cb,
		      sse_event_handler *hi_cb)
{
	struct sse_ghes_event_data *ev_data, *evd;
	struct sse_ghes_callback *cb;
	u32 ev_num;
	int err;

	if (!sse_available)
		return -EOPNOTSUPP;
	if (!ghes || !lo_cb || !hi_cb)
		return -EINVAL;

	ev_num = ghes->generic->notify.vector;

	ev_data = NULL;
	spin_lock(&sse_ghes_event_list_lock);
	list_for_each_entry(evd, &sse_ghes_event_list, head) {
		if (evd->event_num == ev_num) {
			ev_data = evd;
			break;
		}
	}
	spin_unlock(&sse_ghes_event_list_lock);

	if (!ev_data) {
		ev_data = kzalloc(sizeof(*ev_data), GFP_KERNEL);
		if (!ev_data)
			return -ENOMEM;

		INIT_LIST_HEAD(&ev_data->head);
		ev_data->event_num = ev_num;

#ifdef SSE_GHES_LIST_OF_CALLBACKS
		INIT_LIST_HEAD(&ev_data->callback_list);
#else
		if (ev_num & SBI_SSE_EVENT_GLOBAL) {
			ev_data->global_cb = kzalloc(sizeof(*cb), GFP_KERNEL);
			if (!ev_data->global_cb) {
				kfree(ev_data);
				return -ENOMEM;
			}
		} else {
			ev_data->local_cb = alloc_percpu(typeof(*cb));
			if (!ev_data->local_cb) {
				kfree(ev_data);
				return -ENOMEM;
			}
		}
#endif

		ev_data->event = sse_event_register(ev_num, ev_num,
						    sse_ghes_handler, ev_data);
		if (!ev_data->event) {
			pr_err("%s: Couldn't register event 0x%x\n", __func__, ev_num);
#ifndef SSE_GHES_LIST_OF_CALLBACKS
			if (ev_num & SBI_SSE_EVENT_GLOBAL)
				kfree(ev_data->global_cb);
			else
				free_percpu(ev_data->local_cb);
#endif
			kfree(ev_data);
			return -ENOMEM;
		}

		err = sse_event_enable(ev_data->event);
		if (err) {
			pr_err("%s: Couldn't enable event 0x%x\n", __func__, ev_num);
			sse_event_unregister(ev_data->event);
#ifndef SSE_GHES_LIST_OF_CALLBACKS
			if (ev_num & SBI_SSE_EVENT_GLOBAL)
				kfree(ev_data->global_cb);
			else
				free_percpu(ev_data->local_cb);
#endif
			kfree(ev_data);
			return err;
		}

		spin_lock(&sse_ghes_event_list_lock);
		list_add_tail(&ev_data->head, &sse_ghes_event_list);
		spin_unlock(&sse_ghes_event_list_lock);
	}

#ifdef SSE_GHES_LIST_OF_CALLBACKS
	list_for_each_entry(cb, &ev_data->callback_list, head) {
		if (cb->ghes == ghes)
			return -EALREADY;
	}

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;
	INIT_LIST_HEAD(&cb->head);
	cb->ghes = ghes;
	cb->callback = lo_cb;
	list_add_tail(&cb->head, &ev_data->callback_list);
#else
	/* TODO: Find target CPU for given GHES instance with local event */
	if (ev_data->event_num & SBI_SSE_EVENT_GLOBAL)
		cb = ev_data->global_cb;
	else
		cb = per_cpu_ptr(ev_data->local_cb, smp_processor_id());
	if (cb->ghes)
		return -EALREADY;

	cb->ghes = ghes;
	cb->callback = lo_cb;
#endif

	return 0;
}

int sse_unregister_ghes(struct ghes *ghes)
{
	struct sse_ghes_event_data *ev_data, *tmp;
	struct sse_ghes_callback *cb;
	int free_ev_data = 0;
#ifndef SSE_GHES_LIST_OF_CALLBACKS
	int cpu;
#endif

	if (!ghes)
		return -EINVAL;

	spin_lock(&sse_ghes_event_list_lock);

	list_for_each_entry_safe(ev_data, tmp, &sse_ghes_event_list, head) {
#ifdef SSE_GHES_LIST_OF_CALLBACKS
		list_for_each_entry(cb, &ev_data->callback_list, head) {
			if (cb->ghes != ghes)
				continue;

			list_del(&cb->head);
			kfree(cb);
			break;
		}

		if (list_empty(&ev_data->callback_list))
			free_ev_data = 1;
#else
		if (ev_data->event_num & SBI_SSE_EVENT_GLOBAL) {
			free_ev_data = 1;
		} else {
			for_each_cpu(cpu, cpu_present_mask) {
				cb = per_cpu_ptr(ev_data->local_cb, cpu);
				if (cb->ghes != ghes)
					continue;

				cb->ghes = NULL;
				cb->callback = NULL;
			}

			free_ev_data = 1;
			for_each_cpu(cpu, cpu_present_mask) {
				cb = per_cpu_ptr(ev_data->local_cb, cpu);
				if (cb->ghes) {
					free_ev_data = 0;
					break;
				}
			}
		}
#endif

		if (free_ev_data) {
			spin_unlock(&sse_ghes_event_list_lock);

			sse_event_disable(ev_data->event);
			sse_event_unregister(ev_data->event);
			ev_data->event = NULL;

			spin_lock(&sse_ghes_event_list_lock);

#ifndef SSE_GHES_LIST_OF_CALLBACKS
			if (ev_data->event_num & SBI_SSE_EVENT_GLOBAL)
				kfree(ev_data->global_cb);
			else
				free_percpu(ev_data->local_cb);
#endif

			list_del(&ev_data->head);
			kfree(ev_data);
		}
	}

	spin_unlock(&sse_ghes_event_list_lock);

	return 0;
}
