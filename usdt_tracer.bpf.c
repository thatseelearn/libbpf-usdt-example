// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * usdt_tracer.bpf.c - USDT 프로브에 attach하는 BPF 프로그램
 *
 * libbpf의 USDT 지원을 사용하여 target_app의 프로브를 추적합니다.
 * 프로브가 발동되면 이벤트 정보를 ring buffer를 통해 사용자 공간으로 전달합니다.
 */

#include "vmlinux.h"           /* BTF에서 생성된 커널 타입 정의 */
#include <bpf/bpf_helpers.h>   /* BPF 헬퍼 함수 */
#include <bpf/bpf_tracing.h>   /* 트레이싱 관련 매크로 */
#include <bpf/usdt.bpf.h>      /* USDT 지원 매크로 */
#include "usdt_tracer.h"

/* Ring buffer 맵 - 사용자 공간으로 이벤트를 전달하는 채널 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB */
} events SEC(".maps");

/*
 * SEC("usdt") 매크로 설명:
 *
 * SEC("usdt/./target_app:my_app:request_start")
 *       ^^^^                                    - 프로그램 타입: USDT
 *            ^^^^^^^^^^^^^^                     - 바이너리 경로
 *                           ^^^^^^              - provider 이름
 *                                  ^^^^^^^^^^^^^- 프로브 이름
 *
 * bpf_usdt_arg(ctx, N, &val) 로 프로브 인자에 접근합니다.
 * N은 0부터 시작하는 인자 인덱스입니다.
 */

/* 프로브: 요청 시작 */
SEC("usdt")
int BPF_USDT(handle_request_start, long request_id, const char *endpoint)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->request_id = request_id;
    e->latency_ms = -1;  /* 시작 이벤트이므로 지연 없음 */

    /* 사용자 공간 문자열을 BPF 메모리로 안전하게 복사 */
    bpf_probe_read_user_str(e->message, sizeof(e->message), endpoint);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 프로브: 요청 완료 */
SEC("usdt")
int BPF_USDT(handle_request_end, long request_id, int latency_ms)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->request_id = request_id;
    e->latency_ms = latency_ms;

    __builtin_memcpy(e->message, "completed", 10);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 프로브: 앱 준비 완료 */
SEC("usdt")
int BPF_USDT(handle_app_ready)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->request_id = 0;
    e->latency_ms = 0;

    __builtin_memcpy(e->message, "app_ready", 10);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
