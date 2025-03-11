// SPDX-License-Identifier: GPL-2.0

/* For EXPORT_SYMBOL_GPL() */
#include <linux/export.h>

/* Copy-paste of includes from verifier.c from here... */
#include <uapi/linux/btf.h>
#include <linux/bpf-cgroup.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <net/netlink.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/stringify.h>
#include <linux/bsearch.h>
#include <linux/sort.h>
#include <linux/perf_event.h>
#include <linux/ctype.h>
#include <linux/error-injection.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>
#include <linux/poison.h>
#include <linux/module.h>
#include <linux/cpumask.h>
#include <linux/bpf_mem_alloc.h>
#include <net/xdp.h>
#include <linux/trace_events.h>
#include <linux/kallsyms.h>
#include "disasm.h"
/* ... until here */

EXPORT_SYMBOL_GPL(arch_bpf_timed_may_goto);
EXPORT_SYMBOL_GPL(bpf_alu_string);
EXPORT_SYMBOL_GPL(bpf_arch_uaddress_limit);
EXPORT_SYMBOL_GPL(bpf_arena_get_user_vm_start);
EXPORT_SYMBOL_GPL(bpf_bprintf_prepare);
EXPORT_SYMBOL_GPL(bpf_cgroup_storage_assign);
EXPORT_SYMBOL_GPL(bpf_check_uarg_tail_zero);
EXPORT_SYMBOL_GPL(bpf_core_apply);
EXPORT_SYMBOL_GPL(bpf_dev_bound_kfunc_check);
EXPORT_SYMBOL_GPL(bpf_dev_bound_kfunc_id);
EXPORT_SYMBOL_GPL(bpf_dev_bound_resolve_kfunc);
EXPORT_SYMBOL_GPL(bpf_dynptr_from_skb_rdonly);
EXPORT_SYMBOL_GPL(bpf_extension_verifier_ops);
EXPORT_SYMBOL_GPL(__bpf_free_used_btfs);
EXPORT_SYMBOL_GPL(__bpf_free_used_maps);
EXPORT_SYMBOL_GPL(bpf_get_raw_tracepoint);
EXPORT_SYMBOL_GPL(bpf_global_ma_set);
EXPORT_SYMBOL_GPL(bpf_helper_changes_pkt_data);
EXPORT_SYMBOL_GPL(bpf_int_jit_compile);
EXPORT_SYMBOL_GPL(bpf_iter_prog_supported);
EXPORT_SYMBOL_GPL(bpf_jit_add_poke_descriptor);
EXPORT_SYMBOL_GPL(bpf_jit_free);
EXPORT_SYMBOL_GPL(bpf_jit_inlines_helper_call);
EXPORT_SYMBOL_GPL(bpf_jit_needs_zext);
EXPORT_SYMBOL_GPL(bpf_jit_supports_arena);
EXPORT_SYMBOL_GPL(bpf_jit_supports_exceptions);
EXPORT_SYMBOL_GPL(bpf_jit_supports_far_kfunc_call);
EXPORT_SYMBOL_GPL(bpf_jit_supports_insn);
EXPORT_SYMBOL_GPL(bpf_jit_supports_kfunc_call);
EXPORT_SYMBOL_GPL(bpf_jit_supports_percpu_insn);
EXPORT_SYMBOL_GPL(bpf_jit_supports_private_stack);
EXPORT_SYMBOL_GPL(bpf_jit_supports_ptr_xchg);
EXPORT_SYMBOL_GPL(bpf_jit_supports_subprog_tailcalls);
EXPORT_SYMBOL_GPL(bpf_jit_supports_timed_may_goto);
EXPORT_SYMBOL_GPL(bpf_lsm_get_retval_range);
EXPORT_SYMBOL_GPL(bpf_lsm_has_d_inode_locked);
EXPORT_SYMBOL_GPL(bpf_lsm_is_sleepable_hook);
EXPORT_SYMBOL_GPL(bpf_lsm_verify_prog);
EXPORT_SYMBOL_GPL(bpf_map_fops);
EXPORT_SYMBOL_GPL(bpf_map_offload_ops);
EXPORT_SYMBOL_GPL(bpf_map_write_active);
EXPORT_SYMBOL_GPL(bpf_mem_alloc_percpu_init);
EXPORT_SYMBOL_GPL(bpf_mem_alloc_percpu_unit_init);
EXPORT_SYMBOL_GPL(bpf_offload_prog_map_match);
EXPORT_SYMBOL_GPL(bpf_opcode_in_insntable);
EXPORT_SYMBOL_GPL(bpf_patch_insn_single);
EXPORT_SYMBOL_GPL(bpf_prog_alloc_jited_linfo);
EXPORT_SYMBOL_GPL(bpf_prog_alloc_no_stats);
EXPORT_SYMBOL_GPL(bpf_prog_calc_tag);
EXPORT_SYMBOL_GPL(bpf_prog_dev_bound_match);
EXPORT_SYMBOL_GPL(bpf_prog_has_trampoline);
EXPORT_SYMBOL_GPL(bpf_prog_jit_attempt_done);
EXPORT_SYMBOL_GPL(bpf_prog_kallsyms_add);
EXPORT_SYMBOL_GPL(bpf_prog_offload_finalize);
EXPORT_SYMBOL_GPL(bpf_prog_offload_remove_insns);
EXPORT_SYMBOL_GPL(bpf_prog_offload_replace_insn);
EXPORT_SYMBOL_GPL(bpf_prog_offload_verifier_prep);
EXPORT_SYMBOL_GPL(bpf_prog_offload_verify_insn);
EXPORT_SYMBOL_GPL(bpf_put_raw_tracepoint);
EXPORT_SYMBOL_GPL(bpf_remove_dentry_xattr_locked);
EXPORT_SYMBOL_GPL(bpf_remove_insns);
EXPORT_SYMBOL_GPL(bpf_set_dentry_xattr_locked);
EXPORT_SYMBOL_GPL(bpf_sock_common_is_valid_access);
EXPORT_SYMBOL_GPL(bpf_sock_convert_ctx_access);
EXPORT_SYMBOL_GPL(bpf_sock_is_valid_access);
EXPORT_SYMBOL_GPL(bpf_struct_ops_find);
EXPORT_SYMBOL_GPL(bpf_struct_ops_supported);
EXPORT_SYMBOL_GPL(bpf_struct_ops_verifier_ops);
EXPORT_SYMBOL_GPL(bpf_syscall_verifier_ops);
EXPORT_SYMBOL_GPL(bpf_tcp_sock_convert_ctx_access);
EXPORT_SYMBOL_GPL(bpf_tcp_sock_is_valid_access);
EXPORT_SYMBOL_GPL(bpf_token_capable);
EXPORT_SYMBOL_GPL(bpf_trampoline_get);
EXPORT_SYMBOL_GPL(bpf_user_rnd_init_once);
EXPORT_SYMBOL_GPL(bpf_verifier_vlog);
EXPORT_SYMBOL_GPL(bpf_vlog_finalize);
EXPORT_SYMBOL_GPL(bpf_vlog_init);
EXPORT_SYMBOL_GPL(bpf_vlog_reset);
EXPORT_SYMBOL_GPL(bpf_xdp_sock_convert_ctx_access);
EXPORT_SYMBOL_GPL(bpf_xdp_sock_is_valid_access);
EXPORT_SYMBOL_GPL(btf_bpf_map_id);
EXPORT_SYMBOL_GPL(btf_check_iter_arg);
EXPORT_SYMBOL_GPL(btf_check_type_match);
EXPORT_SYMBOL_GPL(btf_distill_func_proto);
EXPORT_SYMBOL_GPL(btf_find_by_name_kind);
EXPORT_SYMBOL_GPL(btf_find_decl_tag_value);
EXPORT_SYMBOL_GPL(btf_find_struct_meta);
EXPORT_SYMBOL_GPL(btf_fops);
EXPORT_SYMBOL_GPL(btf_get);
EXPORT_SYMBOL_GPL(btf_get_by_fd);
EXPORT_SYMBOL_GPL(btf_get_name);
EXPORT_SYMBOL_GPL(btf_is_kernel);
EXPORT_SYMBOL_GPL(btf_is_module);
EXPORT_SYMBOL_GPL(btf_is_prog_ctx_type);
EXPORT_SYMBOL_GPL(btf_is_projection_of);
EXPORT_SYMBOL_GPL(btf_kfunc_id_set_contains);
EXPORT_SYMBOL_GPL(btf_kfunc_is_modify_return);
EXPORT_SYMBOL_GPL(btf_name_by_offset);
EXPORT_SYMBOL_GPL(btf_nested_type_is_trusted);
EXPORT_SYMBOL_GPL(btf_nr_types);
EXPORT_SYMBOL_GPL(btf_obj_id);
EXPORT_SYMBOL_GPL(btf_param_match_suffix);
EXPORT_SYMBOL_GPL(btf_parse_vmlinux);
EXPORT_SYMBOL_GPL(btf_prepare_func_args);
EXPORT_SYMBOL_GPL(btf_put);
EXPORT_SYMBOL_GPL(btf_record_find);
EXPORT_SYMBOL_GPL(btf_resolve_size);
EXPORT_SYMBOL_GPL(btf_sock_ids);
EXPORT_SYMBOL_GPL(btf_struct_access);
EXPORT_SYMBOL_GPL(btf_struct_ids_match);
EXPORT_SYMBOL_GPL(btf_tracing_ids);
EXPORT_SYMBOL_GPL(btf_try_get_module);
EXPORT_SYMBOL_GPL(btf_type_ids_nocast_alias);
EXPORT_SYMBOL_GPL(btf_type_is_void);
EXPORT_SYMBOL_GPL(btf_type_resolve_func_ptr);
EXPORT_SYMBOL_GPL(btf_type_resolve_ptr);
EXPORT_SYMBOL_GPL(btf_types_are_same);
EXPORT_SYMBOL_GPL(btf_type_skip_modifiers);
EXPORT_SYMBOL_GPL(btf_type_str);
EXPORT_SYMBOL_GPL(cg_dev_verifier_ops);
EXPORT_SYMBOL_GPL(cg_skb_verifier_ops);
EXPORT_SYMBOL_GPL(cg_sock_addr_verifier_ops);
EXPORT_SYMBOL_GPL(cg_sockopt_verifier_ops);
EXPORT_SYMBOL_GPL(cg_sock_verifier_ops);
EXPORT_SYMBOL_GPL(cg_sysctl_verifier_ops);
EXPORT_SYMBOL_GPL(dynptr_type_str);
EXPORT_SYMBOL_GPL(find_kallsyms_symbol_value);
EXPORT_SYMBOL_GPL(flow_dissector_verifier_ops);
EXPORT_SYMBOL_GPL(func_id_name);
EXPORT_SYMBOL_GPL(get_callchain_buffers);
EXPORT_SYMBOL_GPL(get_kern_ctx_btf_id);
EXPORT_SYMBOL_GPL(iter_state_str);
EXPORT_SYMBOL_GPL(iter_type_str);
EXPORT_SYMBOL_GPL(kallsyms_lookup);
EXPORT_SYMBOL_GPL(kallsyms_lookup_name);
EXPORT_SYMBOL_GPL(kprobe_verifier_ops);
EXPORT_SYMBOL_GPL(lirc_mode2_verifier_ops);
EXPORT_SYMBOL_GPL(lsm_verifier_ops);
EXPORT_SYMBOL_GPL(lwt_in_verifier_ops);
EXPORT_SYMBOL_GPL(lwt_out_verifier_ops);
EXPORT_SYMBOL_GPL(lwt_seg6local_verifier_ops);
EXPORT_SYMBOL_GPL(lwt_xmit_verifier_ops);
EXPORT_SYMBOL_GPL(netfilter_verifier_ops);
EXPORT_SYMBOL_GPL(perf_event_verifier_ops);
EXPORT_SYMBOL_GPL(print_bpf_insn);
EXPORT_SYMBOL_GPL(print_insn_state);
EXPORT_SYMBOL_GPL(print_verifier_state);
EXPORT_SYMBOL_GPL(raw_tracepoint_verifier_ops);
EXPORT_SYMBOL_GPL(raw_tracepoint_writable_verifier_ops);
EXPORT_SYMBOL_GPL(reg_type_str);
EXPORT_SYMBOL_GPL(__SCK__cond_resched);
EXPORT_SYMBOL_GPL(__SCK__perf_snapshot_branch_stack);
EXPORT_SYMBOL_GPL(sk_filter_verifier_ops);
EXPORT_SYMBOL_GPL(sk_lookup_verifier_ops);
EXPORT_SYMBOL_GPL(sk_msg_verifier_ops);
EXPORT_SYMBOL_GPL(sk_reuseport_verifier_ops);
EXPORT_SYMBOL_GPL(sk_skb_verifier_ops);
EXPORT_SYMBOL_GPL(sock_ops_verifier_ops);
EXPORT_SYMBOL_GPL(sysctl_perf_event_max_stack);
EXPORT_SYMBOL_GPL(tc_cls_act_verifier_ops);
EXPORT_SYMBOL_GPL(tnum_add);
EXPORT_SYMBOL_GPL(tnum_and);
EXPORT_SYMBOL_GPL(tnum_arshift);
EXPORT_SYMBOL_GPL(tnum_cast);
EXPORT_SYMBOL_GPL(tnum_clear_subreg);
EXPORT_SYMBOL_GPL(tnum_const);
EXPORT_SYMBOL_GPL(tnum_const_subreg);
EXPORT_SYMBOL_GPL(tnum_in);
EXPORT_SYMBOL_GPL(tnum_intersect);
EXPORT_SYMBOL_GPL(tnum_is_aligned);
EXPORT_SYMBOL_GPL(tnum_lshift);
EXPORT_SYMBOL_GPL(tnum_mul);
EXPORT_SYMBOL_GPL(tnum_or);
EXPORT_SYMBOL_GPL(tnum_range);
EXPORT_SYMBOL_GPL(tnum_rshift);
EXPORT_SYMBOL_GPL(tnum_sub);
EXPORT_SYMBOL_GPL(tnum_subreg);
EXPORT_SYMBOL_GPL(tnum_unknown);
EXPORT_SYMBOL_GPL(tnum_with_subreg);
EXPORT_SYMBOL_GPL(tnum_xor);
EXPORT_SYMBOL_GPL(tracepoint_verifier_ops);
EXPORT_SYMBOL_GPL(tracing_verifier_ops);
EXPORT_SYMBOL_GPL(verbose_linfo);
EXPORT_SYMBOL_GPL(within_error_injection_list);
EXPORT_SYMBOL_GPL(xdp_verifier_ops);