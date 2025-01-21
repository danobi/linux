#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 11

struct test_val {
	unsigned int index;
	int foo[MAX_ENTRIES];
};


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct test_val);
} map_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct test_val);
} map_array_pcpu SEC(".maps");


SEC("socket")
unsigned int arr(void)
{
	/* Need 8-byte alignment for spill tracking */
	__u32 __attribute__((aligned(8))) key = 1;
	struct test_val *val;

	val = bpf_map_lookup_elem(&map_array, &key);
	val->index = offsetof(struct test_val, foo);

	return val->index;
}

SEC("socket")
unsigned int pcpuarr(void)
{
	__u32 __attribute__((aligned(8))) key = 1;
	struct test_val *val;

	val = bpf_map_lookup_elem(&map_array_pcpu, &key);
	val->index = offsetof(struct test_val, foo);

	return val->index;
}
