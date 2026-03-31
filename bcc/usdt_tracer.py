#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
"""
bcc/usdt_tracer.py - BCC 기반 USDT 트레이서

usdt_tracer (libbpf 버전)와 동일한 출력 형식으로 target_app의 USDT 프로브를 추적합니다.

사용법:
    sudo python3 bcc/usdt_tracer.py -p $(pidof target_app)

의존성:
    sudo apt install python3-bpfcc   # 또는 bpfcc-tools
"""

import argparse
import ctypes
import os
import signal
import sys
from datetime import datetime

from bcc import BPF, USDT

# ─── BPF 프로그램 ────────────────────────────────────────────────────────────
#
# BCC는 런타임에 이 C 코드를 clang으로 컴파일합니다.
# libbpf 버전과의 주요 차이점:
#   - vmlinux.h / 스켈레톤 불필요
#   - BPF_PERF_OUTPUT (perf buffer) 사용  ← BCC의 전통적인 방식
#   - bpf_usdt_readarg() 로 USDT 인자 접근
#
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

#define MAX_MSG_LEN 128

/* 사용자 공간으로 전달할 이벤트 구조체 */
struct event {
    u32  pid;
    u64  timestamp_ns;
    s64  request_id;
    s32  latency_ms;   /* -1 이면 START 이벤트 */
    char message[MAX_MSG_LEN];
};

/* Perf buffer: 커널 → 사용자 공간 이벤트 채널 */
BPF_PERF_OUTPUT(events);

/* 프로브: 요청 시작 */
int handle_request_start(struct pt_regs *ctx)
{
    struct event e = {};

    e.pid        = bpf_get_current_pid_tgid() >> 32;
    e.timestamp_ns = bpf_ktime_get_ns();
    e.latency_ms = -1;  /* START 이벤트 표시 */

    bpf_usdt_readarg(1, ctx, &e.request_id);

    /* 문자열 인자: 포인터를 먼저 읽고, 그 주소에서 문자열 복사 */
    u64 endpoint_ptr = 0;
    bpf_usdt_readarg(2, ctx, &endpoint_ptr);
    bpf_probe_read_user_str(e.message, sizeof(e.message), (void *)endpoint_ptr);

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* 프로브: 요청 완료 */
int handle_request_end(struct pt_regs *ctx)
{
    struct event e = {};

    e.pid          = bpf_get_current_pid_tgid() >> 32;
    e.timestamp_ns = bpf_ktime_get_ns();

    bpf_usdt_readarg(1, ctx, &e.request_id);
    bpf_usdt_readarg(2, ctx, &e.latency_ms);

    __builtin_memcpy(e.message, "completed", 10);

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* 프로브: 앱 준비 완료 */
int handle_app_ready(struct pt_regs *ctx)
{
    struct event e = {};

    e.pid          = bpf_get_current_pid_tgid() >> 32;
    e.timestamp_ns = bpf_ktime_get_ns();
    e.request_id   = 0;
    e.latency_ms   = 0;

    __builtin_memcpy(e.message, "app_ready", 10);

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

# ─── 이벤트 구조체 (ctypes) ──────────────────────────────────────────────────

class Event(ctypes.Structure):
    _fields_ = [
        ("pid",          ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("request_id",   ctypes.c_int64),
        ("latency_ms",   ctypes.c_int32),
        ("message",      ctypes.c_char * 128),
    ]

# ─── 이벤트 출력 ─────────────────────────────────────────────────────────────

def handle_event(cpu, data, size):
    e = ctypes.cast(data, ctypes.POINTER(Event)).contents
    now = datetime.now()
    ts = now.strftime("%H:%M:%S") + f".{now.microsecond // 1000:03d}"

    if e.latency_ms < 0:
        # START 이벤트
        endpoint = e.message.decode("utf-8", errors="replace")
        print(f"{ts} [PID {e.pid:5d}] START  request #{e.request_id:<6d} → {endpoint}")
    elif e.request_id > 0:
        # END 이벤트
        speed = "FAST" if e.latency_ms < 100 else "NORMAL" if e.latency_ms < 200 else "SLOW"
        print(f"{ts} [PID {e.pid:5d}] END    request #{e.request_id:<6d}   {e.latency_ms:4d} ms  [{speed}]")
    else:
        # 기타 이벤트 (app_ready 등)
        msg = e.message.decode("utf-8", errors="replace")
        print(f"{ts} [PID {e.pid:5d}] EVENT  {msg}")

# ─── 메인 ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="BCC 기반 USDT 트레이서 (usdt_tracer libbpf 버전과 동일한 출력)")
    parser.add_argument("-p", "--pid", type=int, required=True,
                        help="추적할 대상 프로세스의 PID")
    args = parser.parse_args()

    # /proc/PID/exe 로 바이너리 경로 확인
    binary_path = os.path.realpath(f"/proc/{args.pid}/exe")
    if not os.path.exists(binary_path):
        print(f"Error: PID {args.pid}의 바이너리를 찾을 수 없습니다.", file=sys.stderr)
        sys.exit(1)

    # USDT 컨텍스트 생성 및 프로브 활성화
    usdt = USDT(pid=args.pid)
    usdt.enable_probe(probe="request_start", fn_name="handle_request_start")
    usdt.enable_probe(probe="request_end",   fn_name="handle_request_end")
    usdt.enable_probe(probe="app_ready",     fn_name="handle_app_ready")

    # BPF 프로그램 컴파일 및 로드
    b = BPF(text=BPF_PROGRAM, usdt_contexts=[usdt])

    # Perf buffer 콜백 등록
    b["events"].open_perf_buffer(handle_event)

    print("=== USDT Tracer (BCC) ===")
    print(f"Attached to PID {args.pid} ({binary_path})")
    print("Tracing probes: my_app:{request_start, request_end, app_ready}")
    print("Ctrl+C to stop\n")

    def on_sigint(sig, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    while True:
        b.perf_buffer_poll()


if __name__ == "__main__":
    main()
