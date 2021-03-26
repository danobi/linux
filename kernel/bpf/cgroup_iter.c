// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2020 Facebook */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/cgroup-defs.h>
#include <linux/init.h>
#include <linux/seq_file.h>

struct bpf_iter_seq_cgroup_info {
	struct cgroup *root;
	struct cgroup *cgrp;
};

static void *cgroup_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_cgroup_info *info = seq->private;

	if (*pos == 0) {
		BUG_ON(!!info->cgrp);
		info->cgrp = NULL;
		++*pos;
	}

	return info->cgrp;
}

static void *cgroup_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_cgroup_info *info = seq->private;
	struct cgroup_subsys_state *css;

	++*pos;
	cgroup_put(info->cgrp);

	rcu_read_lock();
	css = css_next_descendant_pre(&info->cgrp->self, &info->root->self);
	rcu_read_unlock();

	if (!css)
		return NULL;

	info->cgrp = css->cgroup;
	cgroup_get(info->cgrp);

	return info->cgrp;
}

struct bpf_iter__cgroup {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct cgroup *, cgrp);
	__bpf_md_ptr(char *, name);
};

DEFINE_BPF_ITER_FUNC(cgroup, struct bpf_iter_meta *meta, struct cgroup *cgrp,
		     char *name)

static int __cgroup_seq_show(struct seq_file *seq, struct cgroup *cgrp,
			     bool in_stop)
{
	struct bpf_iter_meta meta;
	struct bpf_iter__cgroup ctx;
	struct bpf_prog *prog;
	char name[256] = {};

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, in_stop);
	if (!prog)
		return 0;

	cgroup_name(cgrp, name, sizeof(name));
	meta.seq = seq;
	ctx.meta = &meta;
	ctx.cgrp = cgrp;
	ctx.name = name;

	return bpf_iter_run_prog(prog, &ctx);
}

static int cgroup_seq_show(struct seq_file *seq, void *v)
{
	return __cgroup_seq_show(seq, v, false);
}

static void cgroup_seq_stop(struct seq_file *seq, void *v)
{
	if (v)
		cgroup_put((struct cgroup *)v);
	else
		__cgroup_seq_show(seq, v, true);
}

static int init_seq_cgroup(void *priv_data, struct bpf_iter_aux_info *aux)
{
	struct bpf_iter_seq_cgroup_info *info = priv_data;

	info->root = &cgrp_dfl_root.cgrp;
	cgroup_get(info->root);

	return 0;
}

static void fini_seq_cgroup(void *priv_data)
{
	struct bpf_iter_seq_cgroup_info *info = priv_data;
	cgroup_put(info->root);
}

static const struct seq_operations cgroup_seq_ops = {
	.start	= cgroup_seq_start,
	.next	= cgroup_seq_next,
	.stop	= cgroup_seq_stop,
	.show	= cgroup_seq_show,
};

static const struct bpf_iter_seq_info cgroup_seq_info = {
	.seq_ops		= &cgroup_seq_ops,
	.init_seq_private	= init_seq_cgroup,
	.fini_seq_private	= fini_seq_cgroup,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_cgroup_info),
};

static struct bpf_iter_reg cgroup_reg_info = {
	.target			= "cgroup",
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__cgroup, cgrp),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &cgroup_seq_info,
};

BTF_ID_LIST(btf_cgroup_id)
BTF_ID(struct, cgroup)

static int __init bpf_cgroup_iter_init(void)
{
	cgroup_reg_info.ctx_arg_info[0].btf_id = *btf_cgroup_id;
	return bpf_iter_reg_target(&cgroup_reg_info);
}

late_initcall(bpf_cgroup_iter_init);
