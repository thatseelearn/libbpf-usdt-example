// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * usdt_tracer.c - BPF 프로그램 로더 및 이벤트 출력기
 *
 * 이 프로그램은:
 * 1. BPF 스켈레톤을 통해 BPF 프로그램을 커널에 로드
 * 2. 대상 프로세스의 USDT 프로브에 attach
 * 3. Ring buffer에서 이벤트를 읽어 화면에 출력
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "usdt_tracer.h"
#include "usdt_tracer.skel.h"  /* bpftool에 의해 자동 생성되는 스켈레톤 */

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

/* libbpf 디버그 출력 콜백 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;  /* 디버그 메시지 생략 */
    return vfprintf(stderr, format, args);
}

/* Ring buffer 이벤트 핸들러 - BPF에서 보낸 이벤트를 처리 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct timespec ts;
    struct tm *tm_info;
    char time_buf[32];

    clock_gettime(CLOCK_REALTIME, &ts);
    tm_info = localtime(&ts.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);

    if (e->latency_ms < 0) {
        /* 요청 시작 이벤트 */
        printf("%s.%03ld [PID %5u] START  request #%-6lld → %s\n",
               time_buf, ts.tv_nsec / 1000000,
               e->pid, (long long)e->request_id, e->message);
    } else if (e->request_id > 0) {
        /* 요청 완료 이벤트 */
        const char *speed = e->latency_ms < 100 ? "FAST" :
                           e->latency_ms < 200 ? "NORMAL" : "SLOW";
        printf("%s.%03ld [PID %5u] END    request #%-6lld   %4d ms  [%s]\n",
               time_buf, ts.tv_nsec / 1000000,
               e->pid, (long long)e->request_id, e->latency_ms, speed);
    } else {
        /* 기타 이벤트 (app_ready 등) */
        printf("%s.%03ld [PID %5u] EVENT  %s\n",
               time_buf, ts.tv_nsec / 1000000,
               e->pid, e->message);
    }

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -p <PID> [-b <binary_path>]\n"
        "\n"
        "  -p PID           대상 프로세스의 PID\n"
        "  -b binary_path   대상 바이너리 경로 (기본: /proc/PID/exe)\n"
        "\n"
        "예시:\n"
        "  # 터미널 1: ./target_app\n"
        "  # 터미널 2: sudo ./usdt_tracer -p $(pidof target_app)\n",
        prog);
}

int main(int argc, char **argv)
{
    struct usdt_tracer_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int pid = -1;
    char binary_path[256] = {0};
    int opt;
    int err = 0;

    /* 인자 파싱 */
    while ((opt = getopt(argc, argv, "p:b:h")) != -1) {
        switch (opt) {
        case 'p':
            pid = atoi(optarg);
            break;
        case 'b':
            strncpy(binary_path, optarg, sizeof(binary_path) - 1);
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (pid <= 0) {
        fprintf(stderr, "Error: PID를 지정하세요 (-p)\n\n");
        usage(argv[0]);
        return 1;
    }

    /* 바이너리 경로가 지정되지 않으면 /proc/PID/exe 사용 */
    if (binary_path[0] == '\0') {
        snprintf(binary_path, sizeof(binary_path), "/proc/%d/exe", pid);
    }

    /* 시그널 핸들러 등록 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* libbpf 로그 콜백 설정 */
    libbpf_set_print(libbpf_print_fn);

    /* 1단계: BPF 스켈레톤 열기 */
    skel = usdt_tracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* 2단계: BPF 프로그램을 커널에 로드 */
    err = usdt_tracer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /*
     * 3단계: USDT 프로브에 attach
     *
     * bpf_program__attach_usdt() 파라미터:
     *   - prog:        BPF 프로그램
     *   - pid:         대상 프로세스 PID (-1이면 전체)
     *   - binary_path: USDT 프로브가 있는 ELF 바이너리 경로
     *   - usdt_provider: provider 이름 (DTRACE_PROBE의 첫 번째 인자)
     *   - usdt_name:   프로브 이름 (DTRACE_PROBE의 두 번째 인자)
     *   - opts:        추가 옵션 (NULL이면 기본값)
     */
    skel->links.handle_request_start =
        bpf_program__attach_usdt(skel->progs.handle_request_start,
                                 pid, binary_path,
                                 "my_app", "request_start", NULL);
    if (!skel->links.handle_request_start) {
        err = errno;
        fprintf(stderr, "Failed to attach request_start probe: %s\n",
                strerror(err));
        goto cleanup;
    }

    skel->links.handle_request_end =
        bpf_program__attach_usdt(skel->progs.handle_request_end,
                                 pid, binary_path,
                                 "my_app", "request_end", NULL);
    if (!skel->links.handle_request_end) {
        err = errno;
        fprintf(stderr, "Failed to attach request_end probe: %s\n",
                strerror(err));
        goto cleanup;
    }

    skel->links.handle_app_ready =
        bpf_program__attach_usdt(skel->progs.handle_app_ready,
                                 pid, binary_path,
                                 "my_app", "app_ready", NULL);
    if (!skel->links.handle_app_ready) {
        err = errno;
        fprintf(stderr, "Failed to attach app_ready probe: %s\n",
                strerror(err));
        goto cleanup;
    }

    printf("=== USDT Tracer ===\n");
    printf("Attached to PID %d (%s)\n", pid, binary_path);
    printf("Tracing probes: my_app:{request_start, request_end, app_ready}\n");
    printf("Ctrl+C to stop\n\n");

    /* 4단계: Ring buffer 생성 및 이벤트 폴링 */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
                          NULL, NULL);
    if (!rb) {
        err = errno;
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(err));
        goto cleanup;
    }

    /* 이벤트 루프 */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout_ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    usdt_tracer_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
