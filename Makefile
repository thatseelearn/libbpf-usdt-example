# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#
# USDT + libbpf 데모 빌드 시스템
#

CLANG      ?= clang
CC         ?= gcc
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# libbpf, bpf 헤더 경로
LIBBPF_CFLAGS  := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

CFLAGS   := -Wall -g -O2 $(LIBBPF_CFLAGS)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu

OUTPUT_DIR := .output
VMLINUX_H  := vmlinux.h

.PHONY: all clean

all: $(OUTPUT_DIR) target_app usdt_tracer

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

# ──────────────────────────────────────────
# 1. vmlinux.h 생성 (BTF에서 커널 타입 추출)
# ──────────────────────────────────────────
$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ──────────────────────────────────────────
# 2. BPF 프로그램 컴파일 (.bpf.c → .bpf.o)
# ──────────────────────────────────────────
$(OUTPUT_DIR)/usdt_tracer.bpf.o: usdt_tracer.bpf.c usdt_tracer.h $(VMLINUX_H) | $(OUTPUT_DIR)
	$(CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

# ──────────────────────────────────────────
# 3. BPF 스켈레톤 생성 (.bpf.o → .skel.h)
# ──────────────────────────────────────────
$(OUTPUT_DIR)/usdt_tracer.skel.h: $(OUTPUT_DIR)/usdt_tracer.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 스켈레톤을 소스 디렉토리에도 복사 (include 편의)
usdt_tracer.skel.h: $(OUTPUT_DIR)/usdt_tracer.skel.h
	cp $< $@

# ──────────────────────────────────────────
# 4. 대상 애플리케이션 빌드 (USDT 프로브 포함)
# ──────────────────────────────────────────
target_app: target_app.c
	$(CC) $(CFLAGS) -o $@ $<

# ──────────────────────────────────────────
# 5. 트레이서(로더) 빌드
# ──────────────────────────────────────────
usdt_tracer: usdt_tracer.c usdt_tracer.skel.h usdt_tracer.h
	$(CC) $(CFLAGS) -I. -o $@ $< $(LIBBPF_LDFLAGS)

clean:
	rm -rf $(OUTPUT_DIR) target_app usdt_tracer vmlinux.h usdt_tracer.skel.h
