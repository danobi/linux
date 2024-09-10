// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <unistd.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct sample {
	long value;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} ringbuf SEC(".maps");

long value = 0;
int round_tripped = 0;

SEC("raw_tracepoint")
int test_ringbuf_bpf_to_bpf_produce(void *ctx)
{
	struct sample *sample;

	sample = bpf_ringbuf_reserve(&ringbuf, sizeof(*sample), 0);
	if (!sample)
		return 0;
	sample->value = value;

	bpf_ringbuf_submit(sample, 0);
	return 0;
}

static long consume_cb(struct bpf_dynptr *dynptr, void *context)
{
	struct sample *sample = NULL;

	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample)
		return 0;

	if (sample->value == value)
		round_tripped++;

	return 0;
}

SEC("raw_tracepoint")
int test_ringbuf_bpf_to_bpf_consume(void *ctx)
{
	bpf_user_ringbuf_drain(&ringbuf, consume_cb, NULL, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
