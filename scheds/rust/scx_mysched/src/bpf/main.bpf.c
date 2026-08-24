/* SPDX-License-Identifier: GPL-2.0 */

#ifdef LSP

#ifndef __bpf__
#define __bpf__
#endif

#include "../../../../include/scx/common.bpf.h"

#else

#include <scx/common.bpf.h>

#endif

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0

s32 BPF_STRUCT_OPS(mysched_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32  cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	bpf_printk("1 SELECT pid=%d prev=%d cpu=%d", p->pid, prev_cpu, cpu);

	return cpu;
}

void BPF_STRUCT_OPS(mysched_enqueue, struct task_struct *p, u64 enq_flags)
{
	bpf_printk("2 ENQUEUE pid=%d", p->pid);

	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(mysched_dispatch, s32 cpu, struct task_struct *prev)
{
	bpf_printk("3 DISPATCH cpu=%d", cpu);

	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mysched_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(mysched_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

void BPF_STRUCT_OPS(mysched_running, struct task_struct *p)
{
	bpf_printk("4 RUNNING pid=%d cpu=%d", p->pid,
		   bpf_get_smp_processor_id());
}

SCX_OPS_DEFINE(mysched_ops, .select_cpu = (void *)mysched_select_cpu,
	       .enqueue	 = (void *)mysched_enqueue,
	       .running	 = (void *)mysched_running,
	       .dispatch = (void *)mysched_dispatch,
	       .init = (void *)mysched_init, .exit = (void *)mysched_exit,
	       .name = "mysched");