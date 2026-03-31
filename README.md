# eBPF USDT Tracing Demo (libbpf)

USDT(User Statically-Defined Tracing) 프로브를 libbpf으로 추적하는 교육용 데모입니다.

## 개념 소개

### eBPF란?

eBPF(extended Berkeley Packet Filter)는 리눅스 커널 내부에서 **샌드박스된 프로그램**을 실행할 수 있는 기술입니다. 커널을 수정하거나 모듈을 빌드하지 않고도 네트워크, 보안, 성능 모니터링 등의 기능을 구현할 수 있습니다.

```
┌─────────────────────────────────────────────────┐
│                 사용자 공간                        │
│  ┌──────────┐          ┌──────────────────────┐  │
│  │target_app│          │   usdt_tracer(로더)    │  │
│  │ (USDT    │          │  - BPF 프로그램 로드    │  │
│  │  프로브)  │          │  - ring buffer 읽기    │  │
│  └────┬─────┘          └──────────┬───────────┘  │
│       │                           │               │
├───────┼───────────────────────────┼───────────────┤
│       │         커널 공간          │               │
│       ▼                           │               │
│  ┌─────────┐    이벤트     ┌──────┴──────┐       │
│  │  USDT   │──────────────▶│ BPF 프로그램 │       │
│  │ uprobe  │               │ (커널에서    │       │
│  │ 트리거   │               │  실행됨)     │       │
│  └─────────┘               └──────┬──────┘       │
│                                    │               │
│                             ┌──────▼──────┐       │
│                             │ Ring Buffer │       │
│                             └─────────────┘       │
└─────────────────────────────────────────────────────┘
```

### USDT란?

USDT(User Statically-Defined Tracing)는 **사용자 공간 애플리케이션에 삽입하는 정적 트레이싱 포인트**입니다.

DTrace에서 유래한 개념으로, 개발자가 코드의 의미 있는 지점에 프로브(probe)를 미리 삽입해 두면, 트레이서가 런타임에 해당 지점을 관찰할 수 있습니다.

**핵심 특징:**
- **정적**: 컴파일 타임에 바이너리에 삽입됨 (동적 계측과 대비)
- **저비용**: 트레이싱하지 않을 때는 NOP 명령어로 대체되어 오버헤드가 거의 없음
- **안정적 인터페이스**: 내부 구현이 바뀌어도 프로브 이름/인자를 유지하면 트레이서 호환성 보장
- **프로덕션 사용 가능**: MySQL, PostgreSQL, Node.js, Python, JVM 등 많은 프로젝트가 USDT 사용

### libbpf란?

libbpf는 BPF 프로그램을 로드하고 관리하기 위한 **C 라이브러리**입니다.

BCC(BPF Compiler Collection)와 달리, libbpf는 CO-RE(Compile Once, Run Everywhere) 접근 방식을 사용합니다:

| 항목 | BCC | libbpf (CO-RE) |
|------|-----|----------------|
| 컴파일 시점 | 런타임 (대상 머신에서) | 빌드 타임 (개발 머신에서) |
| 의존성 | LLVM/Clang 런타임 필요 | 커널 BTF만 필요 |
| 메모리 | 높음 (~100MB+) | 낮음 |
| 시작 속도 | 느림 (컴파일 필요) | 빠름 |
| 배포 | 소스 코드 배포 | 바이너리 배포 가능 |

## 프로젝트 구조

```
libbpf-usdt-example/
├── target_app.c          # USDT 프로브가 삽입된 샘플 애플리케이션
├── usdt_tracer.bpf.c     # BPF 프로그램 (커널에서 실행)
├── usdt_tracer.c          # 사용자 공간 로더 (BPF 프로그램 관리)
├── usdt_tracer.h          # 공유 데이터 구조체 정의
├── trace_usdt.bt          # bpftrace 스크립트 (빠른 테스트용)
├── bcc/
│   └── usdt_tracer.py    # BCC 기반 트레이서 (Python)
├── Makefile               # 빌드 시스템
└── README.md              # 이 파일
```

## 빌드 파이프라인

빌드는 다음 단계로 진행됩니다:

```
1. vmlinux.h 생성
   bpftool btf dump → vmlinux.h
   (커널 BTF에서 모든 커널 타입 정의를 C 헤더로 추출)

2. BPF 프로그램 컴파일
   clang -target bpf → usdt_tracer.bpf.o
   (BPF 바이트코드로 컴파일)

3. 스켈레톤 생성
   bpftool gen skeleton → usdt_tracer.skel.h
   (BPF 프로그램을 로드/attach하는 C 코드 자동 생성)

4. 사용자 프로그램 빌드
   gcc → target_app      (프로브가 포함된 대상 앱)
   gcc → usdt_tracer      (BPF 로더)
```

## 환경 설정 (Ubuntu 24.04+)

### 필수 패키지 설치

```bash
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-$(uname -r) \
    systemtap-sdt-dev \
    pkg-config \
    gcc \
    make
```

각 패키지의 역할:

| 패키지 | 용도 |
|--------|------|
| `clang`, `llvm` | BPF 프로그램을 BPF 바이트코드로 컴파일 |
| `libbpf-dev` | libbpf 헤더 및 라이브러리 |
| `linux-tools-*` | `bpftool` 제공 (BTF 덤프, 스켈레톤 생성) |
| `systemtap-sdt-dev` | `<sys/sdt.h>` 헤더 (DTRACE_PROBE 매크로) |
| `pkg-config` | libbpf 컴파일/링크 플래그 자동 탐색 |

### BTF 지원 확인

```bash
# 커널에 BTF가 활성화되어 있는지 확인
ls /sys/kernel/btf/vmlinux
# 파일이 존재하면 BTF 지원됨 (Ubuntu 24.04는 기본 활성화)
```

## 빌드

```bash
make
```

## 실행 방법

**터미널 1** — 대상 애플리케이션 실행:

```bash
./target_app
```

출력 예시:
```
=== USDT Demo Target Application ===
PID: 12345
프로브 확인: bpftrace -l 'usdt:./target_app:*'
Ctrl+C로 종료

[app] request #1 to /api/users completed in 187 ms
[app] request #2 to /api/orders completed in 93 ms
...
```

**터미널 2** — USDT 트레이서 실행 (root 필요):

```bash
sudo ./usdt_tracer -p $(pidof target_app)
```

출력 예시:
```
=== USDT Tracer ===
Attached to PID 12345 (/proc/12345/exe)
Tracing probes: my_app:{request_start, request_end, app_ready}
Ctrl+C to stop

14:23:01.123 [PID 12345] START  request #3      → /api/products
14:23:01.280 [PID 12345] END    request #3        157 ms  [NORMAL]
14:23:02.541 [PID 12345] START  request #4      → /api/health
14:23:02.612 [PID 12345] END    request #4         71 ms  [FAST]
14:23:03.987 [PID 12345] START  request #5      → /api/orders
14:23:04.253 [PID 12345] END    request #5        266 ms  [SLOW]
```

## USDT 프로브 확인하기

빌드된 바이너리에 포함된 USDT 프로브를 확인하는 방법:

```bash
# readelf로 .note.stapsdt 섹션 확인
readelf -n ./target_app | grep -A4 stapsdt

# bpftrace로 프로브 목록 확인 (더 읽기 쉬움)
sudo bpftrace -l 'usdt:./target_app:*'
```

예상 출력:
```
usdt:./target_app:my_app:request_start
usdt:./target_app:my_app:request_end
usdt:./target_app:my_app:app_ready
```

## 코드 상세 설명

### 1. USDT 프로브 정의 (`target_app.c`)

```c
#include <sys/sdt.h>

// 인자 없는 프로브
DTRACE_PROBE(my_app, app_ready);

// 인자 2개 프로브
DTRACE_PROBE2(my_app, request_start, request_id, endpoint);
DTRACE_PROBE2(my_app, request_end, request_id, latency_ms);
```

`DTRACE_PROBE` 매크로는 컴파일 시 NOP 명령어와 ELF 노트 섹션을 생성합니다. 트레이서가 attach하면 NOP이 breakpoint/uprobe로 교체되어 BPF 프로그램이 실행됩니다.

### 2. BPF 프로그램 (`usdt_tracer.bpf.c`)

```c
SEC("usdt")
int BPF_USDT(handle_request_start, long request_id, const char *endpoint)
{
    // ring buffer에 이벤트 기록
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    e->request_id = request_id;
    bpf_probe_read_user_str(e->message, sizeof(e->message), endpoint);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

**핵심 포인트:**
- `BPF_USDT()` 매크로가 USDT 인자 접근 코드를 자동 생성
- `bpf_probe_read_user_str()`로 사용자 공간 문자열을 안전하게 읽음
- Ring buffer를 통해 커널 → 사용자 공간으로 이벤트 전달

### 3. 사용자 공간 로더 (`usdt_tracer.c`)

```c
// 스켈레톤 기반 BPF 프로그램 관리
skel = usdt_tracer_bpf__open();     // 1. 열기
usdt_tracer_bpf__load(skel);        // 2. 커널에 로드

// USDT 프로브에 attach
bpf_program__attach_usdt(prog, pid, binary_path,
                         "my_app", "request_start", NULL);

// Ring buffer에서 이벤트 폴링
rb = ring_buffer__new(fd, handle_event, NULL, NULL);
while (!exiting)
    ring_buffer__poll(rb, 100);
```

### 4. 데이터 흐름 요약

```
target_app                    커널                      usdt_tracer
───────────                   ────                      ───────────
DTRACE_PROBE2(               uprobe 트리거
  my_app,            ──────▶  BPF 프로그램 실행
  request_start,              ring buffer에
  id, endpoint)               이벤트 기록     ──────▶  handle_event()
                                                       화면에 출력
```

## BCC를 이용한 트레이서

[`bcc/usdt_tracer.py`](bcc/usdt_tracer.py)는 libbpf 버전(`usdt_tracer`)과 동일한 동작을 BCC(Python)로 구현한 트레이서입니다.

### libbpf vs BCC 비교

| 항목 | libbpf (CO-RE) | BCC |
|------|----------------|-----|
| 언어 | C | Python + C (인라인) |
| 컴파일 | 빌드 타임 | 런타임 (실행 시 clang 호출) |
| 커널 이벤트 전달 | Ring buffer | Perf buffer |
| USDT 인자 접근 | `BPF_USDT()` 매크로 | `bpf_usdt_readarg()` |
| 의존성 | libbpf, bpftool | python3-bpfcc, clang |
| 배포 | 바이너리 배포 가능 | Python + LLVM 런타임 필요 |

### 의존성 설치

```bash
sudo apt install python3-bpfcc
```

### 실행

```bash
# 터미널 1
./target_app

# 터미널 2
sudo python3 bcc/usdt_tracer.py -p $(pidof target_app)
```

출력은 `usdt_tracer`와 동일합니다:
```
=== USDT Tracer (BCC) ===
Attached to PID 12345 (/usr/bin/target_app)
Tracing probes: my_app:{request_start, request_end, app_ready}
Ctrl+C to stop

14:23:01.123 [PID 12345] START  request #3      → /api/products
14:23:01.280 [PID 12345] END    request #3        157 ms  [NORMAL]
```

## bpftrace를 이용한 빠른 테스트

libbpf 트레이서를 빌드하기 전에, bpftrace로 프로브가 동작하는지 빠르게 확인할 수 있습니다.

스크립트는 [`trace_usdt.bt`](trace_usdt.bt)에 있으며, `usdt_tracer`와 동일한 형식으로 출력합니다:

```bash
sudo bpftrace trace_usdt.bt
```

## 트러블슈팅

| 증상 | 원인 및 해결 |
|------|-------------|
| `vmlinux.h` 생성 실패 | `ls /sys/kernel/btf/vmlinux` 확인. 없으면 `CONFIG_DEBUG_INFO_BTF=y` 커널 필요 |
| `sys/sdt.h` 없음 | `sudo apt install systemtap-sdt-dev` |
| `libbpf.h` 없음 | `sudo apt install libbpf-dev` |
| `bpftool` 없음 | `sudo apt install linux-tools-$(uname -r)` |
| 프로브 attach 실패 | PID가 맞는지, 바이너리 경로가 맞는지 확인 |
| `Operation not permitted` | `sudo`로 실행 또는 `CAP_BPF` + `CAP_PERFMON` capability 부여 |

## 참고 자료

- [libbpf 공식 저장소](https://github.com/libbpf/libbpf)
- [libbpf-bootstrap (예제 모음)](https://github.com/libbpf/libbpf-bootstrap)
- [BPF CO-RE 설명](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [USDT in libbpf](https://nakryiko.com/posts/usdt-notes/)
- [Linux 커널 BPF 문서](https://docs.kernel.org/bpf/)

## 라이선스

이 프로젝트의 소스 코드는 GPL-2.0 OR BSD-3-Clause 듀얼 라이선스로 제공됩니다.
