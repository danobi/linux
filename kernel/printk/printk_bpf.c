#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/printk.h>

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_kprintk(const char *fmt, arg1)
{
}
