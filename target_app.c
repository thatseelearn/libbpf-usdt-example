/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * target_app.c - USDT 프로브가 삽입된 샘플 애플리케이션
 *
 * 이 프로그램은 가상의 웹 서버를 시뮬레이션합니다.
 * 요청을 처리할 때마다 USDT 프로브를 통해 이벤트를 발생시킵니다.
 *
 * 컴파일 시 systemtap-sdt-dev 패키지의 <sys/sdt.h>를 사용합니다.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/sdt.h>  /* USDT 프로브 매크로 */

/*
 * DTRACE_PROBE 매크로 설명:
 *
 * DTRACE_PROBE(provider, name)              - 인자 없는 프로브
 * DTRACE_PROBE1(provider, name, arg1)       - 인자 1개
 * DTRACE_PROBE2(provider, name, arg1, arg2) - 인자 2개
 * ...
 *
 * provider: 프로브 그룹 이름 (여기서는 "my_app")
 * name:     개별 프로브 이름
 * argN:     프로브에 전달할 데이터
 */

static long request_counter = 0;

/* 요청 처리를 시뮬레이션하는 함수 */
static void handle_request(long request_id, const char *endpoint)
{
    /* 프로브 1: 요청 시작 */
    DTRACE_PROBE2(my_app, request_start, request_id, endpoint);

    /* 50~300ms 사이의 랜덤 지연으로 처리 시간 시뮬레이션 */
    int latency_ms = 50 + rand() % 251;
    usleep(latency_ms * 1000);

    /* 프로브 2: 요청 완료 (request_id와 지연시간 전달) */
    DTRACE_PROBE2(my_app, request_end, request_id, latency_ms);

    printf("[app] request #%ld to %s completed in %d ms\n",
           request_id, endpoint, latency_ms);
}

int main(void)
{
    const char *endpoints[] = {
        "/api/users",
        "/api/orders",
        "/api/products",
        "/api/health",
    };
    int num_endpoints = sizeof(endpoints) / sizeof(endpoints[0]);

    srand(time(NULL));

    printf("=== USDT Demo Target Application ===\n");
    printf("PID: %d\n", getpid());
    printf("프로브 확인: bpftrace -l 'usdt:./target_app:*'\n");
    printf("Ctrl+C로 종료\n\n");

    /* 프로브 3: 앱 시작 알림 */
    DTRACE_PROBE(my_app, app_ready);

    while (1) {
        request_counter++;
        const char *ep = endpoints[rand() % num_endpoints];
        handle_request(request_counter, ep);
        /* 요청 사이 0.5~1.5초 대기 */
        usleep((500 + rand() % 1000) * 1000);
    }

    return 0;
}
