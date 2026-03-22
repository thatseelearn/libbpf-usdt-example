/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __USDT_TRACER_H
#define __USDT_TRACER_H

#define MAX_MSG_LEN 128

/* BPF 프로그램 → 사용자 공간으로 전달되는 이벤트 구조체 */
struct event {
    __u32 pid;
    __u64 timestamp_ns;
    __s64 request_id;
    __s32 latency_ms;
    char  message[MAX_MSG_LEN];
};

#endif /* __USDT_TRACER_H */
