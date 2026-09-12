#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apply_fixes.py —— 在 threshold_mldsa_2party 项目根目录运行，一次性完成以下修改：

  1. 一次配置、一次编译、多次运行：
     - 构建时把协议源码分别以 ML-DSA-44/65/87 编译，部分链接并本地化内部符号后，
       与运行时分发器链接成**一个** src/sign/node；运行时用 --mldsa-mode 选择参数集。
     - DFSS 适配器 ABI 改为与参数集无关（掩码数组按最大参数集定长，ABI v4），只构建一份。
     - `make` 一条命令完成构建；旧的 `make dfss-sign MLDSA_MODE=xx` 仍可用（MLDSA_MODE 被忽略）。
  2. EzPC 路径问题：
     - 原 Makefile 只读 config/toolchain.local.conf（该文件不存在），而你把 ezpc_root 写在了
       config/sign/common.local.conf ——那是协议配置，每次运行都会被脚本重写，构建也不读它。
     - 现在路径统一放在 config/toolchain.local.conf；本脚本会把 common.*.conf 里的 ezpc_root
       迁移过去；构建时还会自动探测 ../third_party/EzPC 等常见位置并写回。
     - 协议配置解析器遇到 ezpc_root 改为忽略，而不是报“未知字段”。
     - 清理压缩包里自带的、来自另一目录的过期 build/dfss（CMake 缓存路径不符会导致配置失败）。
  3. MP-SPDZ：项目代码与构建脚本已无任何引用。本脚本会列出机器上残留的 MP-SPDZ 目录；
     加 --purge-spdz 才会真正删除。

用法（在项目根目录）：
  python3 apply_fixes.py                 # 修改代码与文档（修改前自动备份到 .patch_backup/<时间戳>/）
  python3 apply_fixes.py --build         # 修改后立即 make 并运行三种参数集的自检
  python3 apply_fixes.py --purge-spdz    # 同时删除检测到的 MP-SPDZ 目录
  python3 apply_fixes.py --dry-run       # 只显示将要做什么
脚本可重复运行（已应用的修改会被跳过）。
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# 整文件替换（新建或重写）
# ---------------------------------------------------------------------------
FILES: dict[str, str] = {}
FILES['Makefile'] = r'''SHELL := /bin/bash
PYTHON ?= python3

# 一次配置、一次编译：
#   make                 构建 DFSS 适配器 + 单一 src/sign/node（同时包含 ML-DSA-44/65/87）
#   make selftest        协议自检（进程内 DFSS 替身，不需要 EzPC），三种参数集都跑
#   make check           只检查依赖
#   make EZPC_ROOT=/path 首次指定 EzPC 路径（会写入 config/toolchain.local.conf，之后不必再传）
# 参数集在运行时选择：scripts/run_local_simulation.sh --mldsa-mode 44|65|87
#
# EzPC 路径解析顺序（scripts/toolchain_config.py）：
#   make/环境变量 EZPC_ROOT → config/toolchain.local.conf → 旧配置中的 ezpc_root= → 自动探测
#   （<项目>/third_party/EzPC、<项目>/../third_party/EzPC、<项目>/../EzPC、~/EzPC）

DFSS_BUILD := build/dfss
SIGN_BUILD := $(CURDIR)/build/sign
EZPC_ARG := $(if $(strip $(EZPC_ROOT)),--ezpc-root "$(EZPC_ROOT)",)

.PHONY: all build check dfss-configure dfss-build node selftest-build selftest \
        clean distclean dfss-sign dfss-sign-all dfss-sign-one help

all: build

build: node
	@echo "[build] 完成：src/sign/node 同时支持 ML-DSA-$$(./src/sign/node modes | sed 's/ /\/ML-DSA-/g')，运行时用 --mldsa-mode 选择"

help:
	@sed -n '4,13p' Makefile

check:
	@$(PYTHON) scripts/check_dfss_environment.py $(EZPC_ARG)

# 只在缓存缺失或过期（项目目录被移动 / 拷贝自其他机器 / EzPC 路径变化）时重新配置。
dfss-configure: check
	@set -e; \
	root="$$($(PYTHON) scripts/toolchain_config.py --get)"; \
	cache="$(DFSS_BUILD)/CMakeCache.txt"; \
	if [ -f "$$cache" ]; then \
	  home="$$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$$cache")"; \
	  cached="$$(sed -n 's/^EZPC_ROOT:PATH=//p' "$$cache")"; \
	  if [ "$$(realpath -m "$$home")" != "$$(realpath -m src/dcf)" ] || \
	     [ "$$(realpath -m "$$cached")" != "$$(realpath -m "$$root")" ]; then \
	    echo "[build] 清理过期的 $(DFSS_BUILD)（缓存来自其他目录，或 EzPC 路径已改变）"; \
	    rm -rf "$(DFSS_BUILD)"; \
	  fi; \
	fi; \
	if [ ! -f "$$cache" ]; then \
	  cmake -S src/dcf -B $(DFSS_BUILD) -DEZPC_ROOT="$$root" \
	    -DDEALERLESS_BUILD_TESTS=OFF -DDEALERLESS_BUILD_SIGN_ADAPTER=ON \
	    -DCMAKE_BUILD_TYPE=Release -DDEALERLESS_ENABLE_OPENMP=ON \
	    -DSIGN_INCLUDE_DIR="$(CURDIR)/include"; \
	fi

dfss-build: dfss-configure
	cmake --build $(DFSS_BUILD) --target dfss_sign_adapter --parallel

# 真实后端：链接 C++ DFSS 适配器（与参数集无关，只构建一份）；缺失时直接失败，不会静默降级。
node: dfss-build
	$(MAKE) -C src/sign all DFSS_BACKEND=1 TARGET=node \
		DFSS_BUILD_DIR="$(CURDIR)/$(DFSS_BUILD)" BUILD_DIR="$(SIGN_BUILD)"

# 协议逻辑自检：链接 weak stub，产物 node-selftest，不需要 EzPC，也不覆盖 node。
selftest-build:
	$(MAKE) -C src/sign all DFSS_BACKEND=0 TARGET=node-selftest BUILD_DIR="$(SIGN_BUILD)"

selftest: selftest-build
	./src/sign/node-selftest selftest --all-modes
	./src/sign/node-selftest selftest --all-modes --batch 4 --pool 8 --pool-mode refill
	./src/sign/node-selftest selftest --all-modes --fault-inject

# 兼容旧命令：MLDSA_MODE 已不再需要，一次构建包含全部参数集。
dfss-sign dfss-sign-all dfss-sign-one:
	@$(if $(MLDSA_MODE),echo "[build] 提示：MLDSA_MODE=$(MLDSA_MODE) 已不再需要，node 同时包含 44/65/87，运行时选择";,true)
	@$(MAKE) --no-print-directory build

clean:
	$(MAKE) -C src/sign clean BUILD_DIR="$(SIGN_BUILD)"

distclean: clean
	rm -rf build/dfss build/dfss-44 build/dfss-65 build/dfss-87 build/sign
'''

FILES['src/sign/Makefile'] = r'''# 签名协议构建：一次构建同时编译 ML-DSA-44/65/87 三套实现，链接成一个二进制。
#
#   每个参数集：src/*.c 以 -DMLDSA_MODE=<m> 编译 → ld -r 部分链接 →
#               objcopy 只保留 node_main_<m> 为全局符号（其余本地化，三套互不冲突）
#   最终：dispatch/node_dispatch.c + mode44.o + mode65.o + mode87.o → $(TARGET)
#
# DFSS_BACKEND=1：链接真实 libdfss_sign_adapter（排除 weak stub，缺失即链接失败，不会静默降级）
# DFSS_BACKEND=0：链接 weak stub，只能跑 selftest（进程内替身）
CC := gcc
CXX := g++
LD ?= ld
OBJCOPY ?= objcopy

MODES := 44 65 87
BUILD_DIR ?= ../../build/sign
DFSS_BACKEND ?= 0
DFSS_BUILD_DIR ?= ../../build/dfss

ifeq ($(DFSS_BACKEND),0)
TARGET ?= node-selftest
else
TARGET ?= node
endif

BASE_CFLAGS := -Wall -Wextra -O2 -pthread -I../../include -MMD -MP
LDLIBS := -pthread

CORE_SRC := $(filter-out src/dcf_dealerless_backend.c,$(wildcard src/*.c))
STUB_SRC := src/dcf_dealerless_backend.c
DISPATCH_SRC := dispatch/node_dispatch.c

MODE_OBJS := $(foreach m,$(MODES),$(BUILD_DIR)/mode$(m).o)
DISPATCH_OBJ := $(BUILD_DIR)/dispatch/node_dispatch.o
STUB_OBJ := $(BUILD_DIR)/stub/dcf_dealerless_backend.o

ifeq ($(DFSS_BACKEND),0)
LINKER := $(CC)
EXTRA_OBJS := $(STUB_OBJ)
LDFLAGS :=
else
LINKER := $(CXX)
EXTRA_OBJS :=
LDFLAGS := -L$(abspath $(DFSS_BUILD_DIR)) -Wl,-rpath,$(abspath $(DFSS_BUILD_DIR))
LDLIBS += -ldfss_sign_adapter
endif

all: $(TARGET)

$(TARGET): $(DISPATCH_OBJ) $(MODE_OBJS) $(EXTRA_OBJS)
	$(LINKER) -pthread $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(DISPATCH_OBJ): $(DISPATCH_SRC)
	@mkdir -p $(@D)
	$(CC) $(BASE_CFLAGS) -c $< -o $@

# weak stub 与参数集无关（ABI 结构体按最大参数集定长），只编译一份。
$(STUB_OBJ): $(STUB_SRC)
	@mkdir -p $(@D)
	$(CC) $(BASE_CFLAGS) -c $< -o $@

define MODE_RULES
OBJ_$(1) := $$(patsubst src/%.c,$$(BUILD_DIR)/m$(1)/%.o,$$(CORE_SRC))

$$(BUILD_DIR)/m$(1)/%.o: src/%.c
	@mkdir -p $$(@D)
	$$(CC) $$(BASE_CFLAGS) -DMLDSA_MODE=$(1) -c $$< -o $$@

$$(BUILD_DIR)/mode$(1).o: $$(OBJ_$(1))
	$$(LD) -r -o $$@.tmp $$^
	$$(OBJCOPY) --redefine-sym node_mode_main=node_main_$(1) $$@.tmp
	$$(OBJCOPY) --keep-global-symbol=node_main_$(1) $$@.tmp $$@
	@rm -f $$@.tmp

-include $$(OBJ_$(1):.o=.d)
endef
$(foreach m,$(MODES),$(eval $(call MODE_RULES,$(m))))

-include $(DISPATCH_OBJ:.o=.d) $(STUB_OBJ:.o=.d)

clean:
	rm -rf $(BUILD_DIR)
	rm -f node node-selftest node-44 node-65 node-87 src/*.o src/*.d

.PHONY: all clean
'''

FILES['src/sign/dispatch/node_dispatch.c'] = r'''/*
 * node_dispatch.c —— 单一可执行文件的运行时 ML-DSA 参数集分发器。
 *
 * 协议实现（src/sign/src 目录下的 C 源码）大量使用编译期常量（K、L、数组长度），因此构建时把同一份
 * 源码分别以 MLDSA_MODE=44/65/87 各编译一遍，再各自部分链接成一个只导出
 * node_main_<mode> 的目标文件（其余符号全部本地化，三套实现互不冲突），最后与本文件
 * 链接成**一个** node 二进制。运行时根据参数选择其中一套：
 *
 *   node <config.conf> ...                  读取配置（含 include=）里的 mldsa_mode
 *   node --mldsa-mode 65 <config.conf> ...  显式指定；与配置不一致会被拒绝
 *   node selftest [--mldsa-mode N | --all-modes] [...]
 *   node verify <pk.bin> <sig.bin> <msg.txt> 按公钥长度自动识别参数集
 *   node modes                              列出本二进制支持的参数集
 *
 * 一次配置、一次编译，之后每次运行都可以换参数集，不需要重新编译。
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int node_main_44(int argc, char **argv);
int node_main_65(int argc, char **argv);
int node_main_87(int argc, char **argv);

typedef struct {
    int mode;
    long pk_bytes;
    int (*entry)(int, char **);
} ModeEntry;

static const ModeEntry MODES[] = {
    { 44, 1312, node_main_44 },
    { 65, 1952, node_main_65 },
    { 87, 2592, node_main_87 },
};
#define MODE_COUNT ((int)(sizeof(MODES) / sizeof(MODES[0])))

static const ModeEntry *find_mode(int mode) {
    for (int i = 0; i < MODE_COUNT; i++)
        if (MODES[i].mode == mode) return &MODES[i];
    return NULL;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "用法（同一个二进制支持 ML-DSA-44/65/87，运行时选择）:\n"
            "  %s [--mldsa-mode 44|65|87] <config.conf> [--message <text>] [--out-dir <dir>]\n"
            "  %s selftest [--mldsa-mode 44|65|87 | --all-modes] [--batch K] [--pool L]\n"
            "             [--pool-mode fixed|refill] [--fault-inject]\n"
            "  %s verify [--mldsa-mode 44|65|87] <public_key.bin> <signature.bin> <message.txt>\n"
            "  %s modes\n"
            "未指定 --mldsa-mode 时：签名运行读配置里的 mldsa_mode，verify 按公钥长度识别，\n"
            "selftest 默认 44。\n",
            prog, prog, prog, prog);
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = '\0';
    return s;
}

/* 与 config.c 相同的语义：顺序解析，include= 相对所在文件目录，后出现的值覆盖先出现的。 */
static int scan_mode(const char *path, int depth, int *mode) {
    if (depth > 4) return -1;
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[1024];
    int rc = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *s = trim(line);
        char *eq = strchr(s, '=');
        if (!*s || !eq) continue;
        *eq = '\0';
        char *key = trim(s), *val = trim(eq + 1);
        if (strcmp(key, "include") == 0) {
            char inc[PATH_MAX];
            const char *slash = strrchr(path, '/');
            if (val[0] == '/' || !slash) snprintf(inc, sizeof(inc), "%s", val);
            else snprintf(inc, sizeof(inc), "%.*s/%s", (int)(slash - path), path, val);
            if (scan_mode(inc, depth + 1, mode) != 0) { rc = -1; break; }
        } else if (strcmp(key, "mldsa_mode") == 0) {
            *mode = atoi(val);
        }
    }
    fclose(fp);
    return rc;
}

static int parse_mode_value(const char *s) {
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!s[0] || !end || *end) return -1;
    return find_mode((int)v) ? (int)v : -1;
}

/* 从 argv 中剥离 --mldsa-mode N / --mldsa-mode=N / --all-modes，其余参数原样保留。 */
static int strip_args(int argc, char **argv, char **out, int *out_argc, int *mode, int *all_modes) {
    int n = 0;
    for (int i = 0; i < argc; i++) {
        if (i > 0 && strcmp(argv[i], "--mldsa-mode") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--mldsa-mode 需要参数 44|65|87\n"); return -1; }
            *mode = parse_mode_value(argv[++i]);
            if (*mode < 0) { fprintf(stderr, "不支持的 --mldsa-mode: %s（可选 44/65/87）\n", argv[i]); return -1; }
        } else if (i > 0 && strncmp(argv[i], "--mldsa-mode=", 13) == 0) {
            *mode = parse_mode_value(argv[i] + 13);
            if (*mode < 0) { fprintf(stderr, "不支持的 %s（可选 44/65/87）\n", argv[i]); return -1; }
        } else if (i > 0 && strcmp(argv[i], "--all-modes") == 0) {
            *all_modes = 1;
        } else {
            out[n++] = argv[i];
        }
    }
    out[n] = NULL;
    *out_argc = n;
    return 0;
}

int main(int argc, char **argv) {
    char **av = calloc((size_t)argc + 1, sizeof(char *));
    if (!av) return 1;
    int ac = 0, mode = -1, all_modes = 0;
    if (strip_args(argc, argv, av, &ac, &mode, &all_modes) != 0) { usage(argv[0]); return 2; }

    if (ac < 2 || strcmp(av[1], "-h") == 0 || strcmp(av[1], "--help") == 0) {
        usage(argv[0]);
        return ac < 2 ? 2 : 0;
    }

    if (strcmp(av[1], "modes") == 0) {
        for (int i = 0; i < MODE_COUNT; i++) printf("%d%s", MODES[i].mode, i + 1 < MODE_COUNT ? " " : "\n");
        return 0;
    }

    if (strcmp(av[1], "selftest") == 0) {
        if (all_modes) {
            int rc = 0;
            for (int i = 0; i < MODE_COUNT; i++) {
                printf("==================== selftest ML-DSA-%d ====================\n", MODES[i].mode);
                fflush(stdout);
                int r = MODES[i].entry(ac, av);
                printf("[dispatch] ML-DSA-%d selftest %s\n", MODES[i].mode, r == 0 ? "OK" : "FAIL");
                if (r != 0) rc = r;
            }
            return rc;
        }
        return find_mode(mode > 0 ? mode : 44)->entry(ac, av);
    }

    if (strcmp(av[1], "verify") == 0) {
        if (mode < 0) {
            struct stat st;
            if (ac < 3 || stat(av[2], &st) != 0) {
                fprintf(stderr, "无法读取公钥文件，无法自动识别参数集；可用 --mldsa-mode 显式指定\n");
                return 1;
            }
            for (int i = 0; i < MODE_COUNT; i++)
                if ((long)st.st_size == MODES[i].pk_bytes) mode = MODES[i].mode;
            if (mode < 0) {
                fprintf(stderr, "公钥长度 %ld 字节不对应任何 ML-DSA 参数集（1312/1952/2592）\n", (long)st.st_size);
                return 1;
            }
        }
        return find_mode(mode)->entry(ac, av);
    }

    /* 签名运行：配置里的 mldsa_mode 是权威值。 */
    int cfg_mode = 44;
    char abs[PATH_MAX];
    const char *conf = realpath(av[1], abs) ? abs : av[1];
    if (scan_mode(conf, 0, &cfg_mode) != 0) {
        fprintf(stderr, "[dispatch] 无法读取配置 %s\n", av[1]);
        return 1;
    }
    if (mode > 0 && mode != cfg_mode) {
        fprintf(stderr, "[dispatch] --mldsa-mode %d 与配置中的 mldsa_mode=%d 不一致\n", mode, cfg_mode);
        return 2;
    }
    const ModeEntry *m = find_mode(cfg_mode);
    if (!m) {
        fprintf(stderr, "[dispatch] 配置中的 mldsa_mode=%d 不受支持（可选 44/65/87）\n", cfg_mode);
        return 2;
    }
    return m->entry(ac, av);
}
'''

FILES['scripts/toolchain_config.py'] = r'''#!/usr/bin/env python3
"""本机 EzPC 路径的唯一来源：config/toolchain.local.conf（不参与共享协议配置）。

解析顺序：
  1. 显式参数（--set / --ezpc-root / make EZPC_ROOT=...）
  2. 环境变量 EZPC_ROOT
  3. config/toolchain.local.conf 中的 ezpc_root=
  4. 旧版本误写在 config/sign/common.*.conf 里的 ezpc_root=（自动迁移）
  5. 自动探测：<项目>/third_party/EzPC、<项目>/../third_party/EzPC、<项目>/../EzPC、~/EzPC
第 1、2、4、5 步找到的有效路径会写回 config/toolchain.local.conf，之后无需再指定。
相对路径一律以**项目根目录**为基准。
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "toolchain.local.conf"
LEGACY_FILES = (
    ROOT / "config" / "sign" / "common.local.conf",
    ROOT / "config" / "sign" / "common.physical.conf",
)
CANDIDATES = (
    ROOT / "third_party" / "EzPC",
    ROOT.parent / "third_party" / "EzPC",
    ROOT.parent / "EzPC",
    Path.home() / "EzPC",
)
KEY_RE = re.compile(r"(?m)^\s*ezpc_root\s*=\s*(.+?)\s*$")


class ToolchainError(RuntimeError):
    pass


def _note(msg: str) -> None:
    print(f"[toolchain] {msg}", file=sys.stderr)


def _read_key(path: Path) -> str | None:
    if not path.is_file():
        return None
    matches = KEY_RE.findall(path.read_text(encoding="utf-8"))
    return matches[-1].strip() if matches else None


def _resolve_path(value: str) -> Path:
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = ROOT / p
    return p.resolve()


def _problem(root: Path) -> str | None:
    if not (root / "FSS" / "src" / "CMakeLists.txt").is_file():
        return f"{root}（缺少 FSS/src/CMakeLists.txt）"
    if not (root / "SCI" / "src").is_dir():
        return f"{root}（缺少 SCI/src）"
    return None


def _validate(value: str) -> Path:
    root = _resolve_path(value)
    problem = _problem(root)
    if problem:
        raise ToolchainError(f"EzPC 路径无效：{problem}")
    return root


def _stored(root: Path) -> str:
    """尽量存成相对项目根目录的路径，便于项目整体迁移到其他物理机。"""
    try:
        rel = os.path.relpath(root, ROOT)
    except ValueError:
        return str(root)
    if rel.startswith("../.."):
        return str(root)
    return rel


def save(value: str | Path) -> Path:
    root = _validate(str(value))
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    stored = _stored(root)
    old = _read_key(CONFIG)
    if old is None or _resolve_path(old) != root:
        CONFIG.write_text(
            "# 本机 EzPC 依赖路径（相对路径以项目根目录为基准）；不属于共享协议拓扑，勿提交到仓库。\n"
            f"ezpc_root={stored}\n", encoding="utf-8")
        _note(f"已写入 {CONFIG.relative_to(ROOT)}: ezpc_root={stored}")
    return root


def resolve(requested: str | None = None) -> Path:
    if requested:
        return save(requested)
    env = os.environ.get("EZPC_ROOT", "").strip()
    if env:
        return save(env)

    tried: list[str] = []
    saved = _read_key(CONFIG)
    if saved:
        root = _resolve_path(saved)
        problem = _problem(root)
        if problem is None:
            return root
        tried.append(f"config/toolchain.local.conf -> {problem}")

    for legacy in LEGACY_FILES:
        value = _read_key(legacy)
        if value:
            root = _resolve_path(value)
            problem = _problem(root)
            if problem is None:
                _note(f"从旧配置 {legacy.relative_to(ROOT)} 迁移 ezpc_root")
                return save(root)
            tried.append(f"{legacy.relative_to(ROOT)} -> {problem}")

    for cand in CANDIDATES:
        root = cand.resolve()
        problem = _problem(root)
        if problem is None:
            _note(f"自动探测到 EzPC: {root}")
            return save(root)
        tried.append(f"自动探测 -> {problem}")

    detail = "\n    ".join(tried) if tried else "(无)"
    raise ToolchainError(
        "找不到可用的 EzPC。已尝试：\n    " + detail + "\n"
        "解决办法（任选其一，只需做一次）：\n"
        "    make EZPC_ROOT=/absolute/path/to/EzPC\n"
        "    python3 scripts/toolchain_config.py --set ../third_party/EzPC   # 相对项目根目录\n"
        "    bash scripts/build_dependencies.sh                              # 自动克隆并配置")


def main() -> int:
    parser = argparse.ArgumentParser(description="读取或写入本机 EzPC 路径")
    parser.add_argument("--set", dest="set_value")
    parser.add_argument("--get", action="store_true")
    args = parser.parse_args()
    try:
        value = save(args.set_value) if args.set_value else resolve()
    except ToolchainError as exc:
        print(f"[toolchain] {exc}", file=sys.stderr)
        return 2
    if args.get or args.set_value:
        print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

FILES['scripts/check_dfss_environment.py'] = r'''#!/usr/bin/env python3
"""构建前的快速失败检查：EzPC 路径（统一由 toolchain_config 解析）+ 必需命令。"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import toolchain_config  # noqa: E402

REQUIRED_COMMANDS = ("cmake", "gcc", "g++", "make", "ld", "objcopy", "python3")


def main() -> int:
    parser = argparse.ArgumentParser(description="检查真实 EzPC/DFSS 后端所需的本地依赖。")
    parser.add_argument("--ezpc-root", default="",
                        help="EzPC 根目录（绝对路径，或相对项目根目录）；只需首次指定。")
    args = parser.parse_args()

    errors: list[str] = []
    ezpc_root = None
    try:
        ezpc_root = toolchain_config.resolve(args.ezpc_root or None)
    except toolchain_config.ToolchainError as exc:
        errors.append(str(exc))

    for command in REQUIRED_COMMANDS:
        if shutil.which(command) is None:
            errors.append(f"找不到命令：{command}（Ubuntu: sudo apt-get install -y build-essential cmake）")

    if errors:
        print("[DFSS dependency check] FAIL", file=sys.stderr)
        for item in errors:
            print(f"  - {item}", file=sys.stderr)
        return 2

    print(f"[DFSS dependency check] PASS  EZPC_ROOT={ezpc_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

FILES['scripts/prepare_runtime_configs.py'] = r'''#!/usr/bin/env python3
"""生成运行时配置。

本工程是 2-of-2 对称两方结构：没有协调方，也没有独立的 FSS 比较服务器，
P_b 同时是签名方和比较方 C_b。因此拓扑里只有 party=0 / party=1 两行。

每次运行都会生成一个独立目录 runtime/generated-config/<profile>-2of2-m<mode>-<stamp>/：
  common.conf  本次运行的公共参数（含本次选择的 mldsa_mode）
  p0.conf / p1.conf  include common.conf 与本方私有身份

  local    ：生成 p0.conf 与 p1.conf；同时把本次公共参数写到 config/sign/common.local.conf 备查。
  physical ：只生成本机那一份（--node p0|p1），公共拓扑取自
             config/sign/common.physical.conf（须先填好两台机器的 IP）。

因为每次运行的公共参数都在自己的目录里，不同参数集的多次运行互不覆盖。
EzPC 路径属于本机工具链（config/toolchain.local.conf），不会写进协议配置。

打印到 stdout 的是生成目录（local）或本机配置文件路径（physical）。
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "sign"
NODES = CONFIG / "nodes"
LOCAL = CONFIG / "common.local.conf"
PHYSICAL = CONFIG / "common.physical.conf"
RUNTIME = ROOT / "runtime" / "generated-config"
TOOLCHAIN_KEYS = ("ezpc_root",)


def fail(msg: str) -> None:
    print(f"[config] {msg}", file=sys.stderr)
    raise SystemExit(2)


def local_common(mode: int, batch: int, pool: int, pool_mode: str,
                 open_check: str, timeout: int) -> str:
    return "\n".join([
        "# 本地单机拓扑 —— 由 scripts/prepare_runtime_configs.py 生成，勿手改。",
        "# P_b 既是签名方也是 DFSS 比较方 C_b；DFSS 栈会占用 base、base+3、base+50、base+100。",
        "# EzPC 路径请写在 config/toolchain.local.conf（本机工具链），不要写在这里。",
        f"mldsa_mode={mode}",
        "party=0,127.0.0.1,9001,10101",
        "party=1,127.0.0.1,9002,10301",
        f"dcf_batch_size={batch}",
        f"dcf_pregen_pool_size={pool}",
        f"dcf_pool_exhaustion_mode={pool_mode}",
        f"open_check_mode={open_check}",
        "worker_threads=0",
        f"timeout_seconds={timeout}",
        "",
    ])


def override(text: str, mode: int, batch: int, pool: int, pool_mode: str,
             open_check: str, timeout: int) -> str:
    wanted = {
        "mldsa_mode": str(mode),
        "dcf_batch_size": str(batch),
        "dcf_pregen_pool_size": str(pool),
        "dcf_pool_exhaustion_mode": pool_mode,
        "open_check_mode": open_check,
        "timeout_seconds": str(timeout),
    }
    seen, out = set(), []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in TOOLCHAIN_KEYS:
                continue  # 工具链字段不属于协议配置
            if key in wanted:
                seen.add(key)
                out.append(f"{key}={wanted[key]}")
                continue
        out.append(line)
    for key, value in wanted.items():
        if key not in seen:
            out.append(f"{key}={value}")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=("local", "physical"), required=True)
    ap.add_argument("--node", choices=("p0", "p1"), help="physical profile 必填")
    ap.add_argument("--mldsa-mode", type=int, choices=(44, 65, 87), default=44)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--pool-size", type=int, default=8)
    ap.add_argument("--pool-mode", choices=("fixed", "refill"), default="refill")
    ap.add_argument("--open-check", choices=("strict", "off"), default="strict")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    if not 1 <= args.batch_size <= 8:
        fail("--batch-size 必须在 1..8")
    if not args.batch_size <= args.pool_size <= 64:
        fail("--pool-size 必须在 batch_size..64")

    if args.profile == "local":
        common_text = local_common(args.mldsa_mode, args.batch_size, args.pool_size,
                                   args.pool_mode, args.open_check, args.timeout)
        LOCAL.write_text(common_text, encoding="utf-8")
        names = ["p0", "p1"]
    else:
        if not PHYSICAL.is_file():
            fail("缺少 config/sign/common.physical.conf")
        text = PHYSICAL.read_text(encoding="utf-8")
        if "REPLACE_WITH_" in text:
            fail("请先把 common.physical.conf 里的 REPLACE_WITH_*_IP 换成真实 IP")
        if len(re.findall(r"(?m)^\s*party=", text)) != 2:
            fail("common.physical.conf 必须恰好有两行 party=")
        if not args.node:
            fail("physical profile 需要 --node p0|p1")
        common_text = override(text, args.mldsa_mode, args.batch_size, args.pool_size,
                               args.pool_mode, args.open_check, args.timeout)
        names = [args.node]

    for name in names:
        if not (NODES / f"{name}.conf").is_file():
            fail(f"缺少私有身份文件 config/sign/nodes/{name}.conf")

    RUNTIME.mkdir(parents=True, exist_ok=True)
    dest = RUNTIME / f"{args.profile}-2of2-m{args.mldsa_mode}-{time.time_ns()}-{os.getpid()}"
    dest.mkdir()
    common = dest / "common.conf"
    common.write_text(common_text, encoding="utf-8")
    for name in names:
        (dest / f"{name}.conf").write_text(
            f"include={common.resolve()}\ninclude={(NODES / (name + '.conf')).resolve()}\n",
            encoding="utf-8")
    print((dest / f"{args.node}.conf").resolve() if args.profile == "physical" else dest.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

FILES['scripts/build_dependencies.sh'] = r'''#!/usr/bin/env bash
# 新物理机一次性准备：系统包 → EzPC（SCI+FSS 源码）→ 本项目（一次编译，含 ML-DSA-44/65/87）→ 自检。
# 之后每次运行只需 scripts/run_local_simulation.sh / run_physical_node.sh，用 --mldsa-mode 选参数集。
#
# 安全声明：EzPC/SCI 的 DFSS 路径是半诚实的，构建它不会带来恶意安全。
# 本项目不需要 MP-SPDZ。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EZPC_URL="${EZPC_URL:-https://github.com/mpc-msri/EzPC.git}"
EZPC_REF="${EZPC_REF:-master}"
DO_SYSTEM=1; DO_EZPC=1; DO_PROJECT=1

log() { printf '[deps] %s\n' "$*"; }
die() { printf '[deps][error] %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-system) DO_SYSTEM=0 ;;
    --skip-ezpc) DO_EZPC=0 ;;
    --skip-project) DO_PROJECT=0 ;;
    --ezpc-dir) EZPC_DIR="$2"; shift ;;
    --mldsa-mode) log "提示：--mldsa-mode 已不再需要（一次构建包含 44/65/87），忽略 $2"; shift ;;
    -h|--help)
      echo "用法: scripts/build_dependencies.sh [--skip-system] [--skip-ezpc] [--skip-project] [--ezpc-dir DIR]"
      exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
  shift
done

if [ "${DO_SYSTEM}" -eq 1 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then command -v sudo >/dev/null 2>&1 || die "需要 root 或 sudo，否则用 --skip-system"; SUDO=sudo; fi
    log "安装系统依赖…"
    ${SUDO} apt-get update -y
    ${SUDO} apt-get install -y build-essential binutils git cmake python3 \
      libssl-dev libgmp-dev libntl-dev libsodium-dev libeigen3-dev \
      libboost-dev libboost-thread-dev libboost-filesystem-dev \
      automake libtool yasm texinfo pkg-config
  else
    log "未检测到 apt-get，跳过；请自行安装 gcc/g++(>=9)、binutils、cmake(>=3.16)、openssl、gmp、ntl、sodium、eigen3、boost。"
  fi
fi

if [ "${DO_EZPC}" -eq 1 ]; then
  if [ -z "${EZPC_DIR:-}" ] && EXISTING="$(python3 "${ROOT}/scripts/toolchain_config.py" --get 2>/dev/null)"; then
    log "复用已配置/已探测到的 EzPC: ${EXISTING}"
  else
    EZPC_DIR="${EZPC_DIR:-${ROOT}/third_party/EzPC}"
    if [ ! -d "${EZPC_DIR}/.git" ]; then
      log "克隆 EzPC (${EZPC_REF}) → ${EZPC_DIR}"
      mkdir -p "$(dirname "${EZPC_DIR}")"
      git clone --depth 1 --branch "${EZPC_REF}" "${EZPC_URL}" "${EZPC_DIR}"
    else
      log "复用已存在的 EzPC: ${EZPC_DIR}"
    fi
    python3 "${ROOT}/scripts/toolchain_config.py" --set "${EZPC_DIR}" >/dev/null
  fi
fi

if [ "${DO_PROJECT}" -eq 1 ]; then
  log "构建本项目（真实 DFSS 后端，单一二进制含 ML-DSA-44/65/87）…"
  ( cd "${ROOT}" && make )
  log "运行协议自检（进程内 DFSS 替身，三种参数集）…"
  ( cd "${ROOT}" && ./src/sign/node selftest --all-modes && ./src/sign/node selftest --all-modes --fault-inject )
fi

log "完成。之后直接运行，例如： bash scripts/run_local_simulation.sh --mldsa-mode 65"
'''

FILES['scripts/run_local_simulation.sh'] = r'''#!/usr/bin/env bash
# 在一台机器上同时起 P0 与 P1 两个进程，跑一次完整的 2-of-2 门限签名。
# 两个进程运行的是同一个二进制；参数集（44/65/87）在运行时由 --mldsa-mode 选择，无需重新编译。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE="${ROOT}/src/sign/node"
MODE=44; BATCH=1; POOL=8; POOL_MODE=refill; OPEN_CHECK=strict
TIMEOUT=900; MESSAGE="threshold-mldsa-2of2-demo-message"

usage() {
  cat <<'USAGE'
用法: scripts/run_local_simulation.sh [选项]
  --mldsa-mode 44|65|87      参数集，运行时选择，默认 44
  --batch-size K             一批的候选数，1..8，默认 1
  --pool-size L              离线 DCF 池容量，默认 8
  --pool-mode fixed|refill   池耗尽时停止或续生成，默认 refill
  --open-check strict|off    打开一致性检查，默认 strict
  --timeout N                单次收发超时秒数，默认 900
  --message TEXT             待签消息
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mldsa-mode) MODE="$2"; shift 2 ;;
    --batch-size) BATCH="$2"; shift 2 ;;
    --pool-size) POOL="$2"; shift 2 ;;
    --pool-mode) POOL_MODE="$2"; shift 2 ;;
    --open-check) OPEN_CHECK="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --message) MESSAGE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数 $1" >&2; usage; exit 2 ;;
  esac
done

if [ ! -x "${NODE}" ]; then
  echo "找不到 ${NODE}。在项目根目录执行一次 make 即可（同时编译 ML-DSA-44/65/87）；" >&2
  echo "首次如需指定 EzPC：make EZPC_ROOT=/absolute/path/to/EzPC" >&2
  exit 1
fi
if ! "${NODE}" modes 2>/dev/null | tr ' ' '\n' | grep -qx "${MODE}"; then
  echo "当前 ${NODE} 不支持 ML-DSA-${MODE}（可能是旧版单模式二进制），请在项目根目录重新执行 make" >&2
  exit 1
fi

CFG_DIR="$(python3 "${ROOT}/scripts/prepare_runtime_configs.py" --profile local \
  --mldsa-mode "${MODE}" --batch-size "${BATCH}" --pool-size "${POOL}" \
  --pool-mode "${POOL_MODE}" --open-check "${OPEN_CHECK}" --timeout "${TIMEOUT}")"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${ROOT}/logs/local-m${MODE}-${STAMP}"
mkdir -p "${OUT}/p0" "${OUT}/p1"
echo "[run] ML-DSA-${MODE}"
echo "[run] 配置: ${CFG_DIR}"
echo "[run] 日志: ${OUT}"

# P1 先起（它会重试连接 P0），然后起 P0。两者地位对称，先后只影响 TCP 建连。
"${NODE}" "${CFG_DIR}/p1.conf" --message "${MESSAGE}" --out-dir "${OUT}/p1" > "${OUT}/p1.log" 2>&1 &
P1=$!
sleep 0.5
set +e
timeout "$((TIMEOUT + 60))" "${NODE}" "${CFG_DIR}/p0.conf" --message "${MESSAGE}" --out-dir "${OUT}/p0" > "${OUT}/p0.log" 2>&1
RC0=$?
wait ${P1}; RC1=$?
set -e

grep -E "verify_result=|terminal_reason=" "${OUT}/p0.log" | tail -1 || true
grep -E "verify_result=|terminal_reason=" "${OUT}/p1.log" | tail -1 || true
if [ ${RC0} -eq 0 ] && [ ${RC1} -eq 0 ]; then
  echo "[run] PASS  签名: ${OUT}/p0/signature.bin  公钥: ${OUT}/p0/public_key.bin"
  "${NODE}" verify "${OUT}/p0/public_key.bin" "${OUT}/p0/signature.bin" "${OUT}/p0/message.txt"
else
  echo "[run] FAIL  p0_rc=${RC0} p1_rc=${RC1}，详见日志" >&2
  tail -5 "${OUT}/p0.log" >&2 || true
  exit 1
fi
'''

FILES['scripts/run_physical_node.sh'] = r'''#!/usr/bin/env bash
# 在物理机上启动本方节点。两台机器各执行一次，--node 不同即可；--mldsa-mode 两边必须一致。
# 先在两台机器上填好 config/sign/common.physical.conf 里的两个 IP。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE="${ROOT}/src/sign/node"
SELF=""; MODE=44; BATCH=1; POOL=8; POOL_MODE=refill; OPEN_CHECK=strict
TIMEOUT=900; MESSAGE="threshold-mldsa-2of2-demo-message"

while [ $# -gt 0 ]; do
  case "$1" in
    --node) SELF="$2"; shift 2 ;;
    --mldsa-mode) MODE="$2"; shift 2 ;;
    --batch-size) BATCH="$2"; shift 2 ;;
    --pool-size) POOL="$2"; shift 2 ;;
    --pool-mode) POOL_MODE="$2"; shift 2 ;;
    --open-check) OPEN_CHECK="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --message) MESSAGE="$2"; shift 2 ;;
    *) echo "未知参数 $1" >&2; exit 2 ;;
  esac
done
[ "${SELF}" = "p0" ] || [ "${SELF}" = "p1" ] || { echo "需要 --node p0|p1" >&2; exit 2; }
if [ ! -x "${NODE}" ]; then
  echo "找不到 ${NODE}。在项目根目录执行一次 make 即可（同时编译 ML-DSA-44/65/87）" >&2
  exit 1
fi
if ! "${NODE}" modes 2>/dev/null | tr ' ' '\n' | grep -qx "${MODE}"; then
  echo "当前 ${NODE} 不支持 ML-DSA-${MODE}（可能是旧版单模式二进制），请重新执行 make" >&2
  exit 1
fi

CONF="$(python3 "${ROOT}/scripts/prepare_runtime_configs.py" --profile physical --node "${SELF}" \
  --mldsa-mode "${MODE}" --batch-size "${BATCH}" --pool-size "${POOL}" \
  --pool-mode "${POOL_MODE}" --open-check "${OPEN_CHECK}" --timeout "${TIMEOUT}")"

OUT="${ROOT}/logs/physical-m${MODE}-$(date +%Y%m%d-%H%M%S)-${SELF}"
mkdir -p "${OUT}"
echo "[run] ${SELF} ML-DSA-${MODE} 配置 ${CONF}，日志 ${OUT}"
# 两方都要在大致同一时间启动；P1 会在 timeout 内反复重试连接 P0。
"${NODE}" "${CONF}" --message "${MESSAGE}" --out-dir "${OUT}" 2>&1 | tee "${OUT}/console.log"
exit "${PIPESTATUS[0]}"
'''

FILES['config/toolchain.local.conf.example'] = r'''# 每台主机各自的工具链配置，复制为 config/toolchain.local.conf 后按需修改（该文件不提交、不共享）。
# 通常不需要手工创建：make / scripts/build_dependencies.sh 会自动探测并写入。
# 相对路径以**项目根目录**为基准，例如 EzPC 与项目同级放在 ../third_party/EzPC：
ezpc_root=../third_party/EzPC
# 也可以填绝对路径：
# ezpc_root=/home/admin/EzPC
#
# 注意：ezpc_root 只能写在这里。config/sign/common.*.conf 是两方共享的协议配置，不放本机路径。
'''

FILES['.gitignore'] = r'''build/
third_party/
logs/*
!logs/.gitkeep
runtime/generated-config/*
!runtime/.gitkeep
src/sign/*.o
src/sign/src/*.o
src/sign/src/*.d
src/sign/node
src/sign/node-selftest
src/sign/node-*
config/toolchain.local.conf
.patch_backup/
'''

FILES['README.md'] = r'''# 两方门限 ML-DSA（2-of-2，无协调方，P_b 兼任 DFSS 比较方 C_b）

两个对称参与方 **P0**、**P1** 协作产生一份**标准 ML-DSA 签名**。外部验证者用普通
FIPS 204 验证接口即可验签，看不到任何门限成分。

与上一版（`P1` 兼协调方 + 独立比较节点 `C0/C1`，共四个进程）相比，本版本有两处结构性改动：

1. **取消协调方**。两方运行同一份顺序代码，每一步都是“同时交换”；签名由两方各自
   独立组装、各自用标准接口验证，最后交换签名摘要确认一致。没有任何一方替另一方
   “声明”打开值，也没有任何一方独占比较结果。
2. **取消独立的 FSS 比较服务器**。令 `C0 = P0`、`C1 = P1`：`P_b` 本来就持有 `z` 的加性
   份额 `z_b`，因此原来“把 `z_i` 再随机拆成两份分别发给两台比较机”这一步整体消失。
   进程数从 4 降到 2。

---

## 1. 目录结构

```
include/            公共头文件
src/sign/src/       协议实现（C）
src/sign/dispatch/  运行时参数集分发器（单一 node 入口，含 44/65/87）
src/dcf/            DFSS/EzPC 适配器（C++，随项目自带）
config/sign/        拓扑与私有身份
scripts/            构建与运行脚本
build/dfss/         DFSS 适配器构建产物（与参数集无关）
build/sign/         三种参数集的协议目标文件
logs/ runtime/      运行输出
```

协议实现的分层（每个文件的文件头注释写明了它的职责与边界）：

| 文件 | 职责 |
| --- | --- |
| `common.h` / `field.c` | ML-DSA 参数、模 q 运算、24 比特打包 |
| `mldsa_math.c` | 挑战乘法、`A·s`、高低位分解、Algorithm 7、审计承诺 `com` |
| `mldsa_compat.c` | FIPS 204 编码与标准验证 |
| `channel.c` | 两方 TCP 信道：同时交换、先承诺后打开 |
| `config.c` | 配置解析（旧四节点字段会被显式拒绝） |
| `party.c` | 生命周期、握手、度量、结果输出 |
| `dkg.c` | 两方 DKeyGen |
| `dcf_rejects.c` | DCF 离线池与在线批量比较（本方即 `C_b`） |
| `sign.c` | 签名主循环 |
| `open_check.c` | 打开一致性检查 |
| `mock_dcf.c` | **仅自检用**的进程内 DFSS 替身（不安全） |

---

## 2. 新物理机部署（一次配置、一次编译、多次运行）

### 2.1 系统要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Ubuntu 20.04 / 22.04 / 24.04 |
| 编译器 | gcc/g++ ≥ 9（EzPC 需要 C++17），binutils（`ld`、`objcopy`） |
| 构建工具 | make、cmake ≥ 3.16、git、python3 ≥ 3.8 |
| 内存 | ≥ 8 GB |
| 磁盘 | ≥ 10 GB |
| 网络 | 首次构建需能访问 GitHub |

### 2.2 第三方依赖

| 依赖 | 版本 | 用途 | 必需 |
| --- | --- | --- | --- |
| EzPC / SCI + FSS | `master` | 真实 DFSS 比较后端（半诚实） | 是 |
| OpenSSL / GMP / NTL / libsodium / Eigen3 / Boost | 发行版自带 | EzPC 编译依赖 | 是 |

本版本**不需要 MP-SPDZ**，代码与构建脚本中没有任何对它的引用；如果机器上还留着
MP-SPDZ 目录，可以直接删除。当前阶段也不使用 MAC（见第 6、7 节）。

### 2.3 一次性配置 + 编译

```bash
bash scripts/build_dependencies.sh                 # 系统包 + EzPC + 本项目 + 自检
bash scripts/build_dependencies.sh --skip-system   # 已装好系统包
```

或手动：

```bash
make                                   # 自动探测 EzPC；探测不到时按提示执行下一行（只需一次）
make EZPC_ROOT=/absolute/path/to/EzPC  # 路径会写入 config/toolchain.local.conf
```

EzPC 路径的**唯一**存放位置是 `config/toolchain.local.conf`（本机文件，不共享）。
相对路径以项目根目录为基准。`make` 会按以下顺序查找并自动写回：
`EZPC_ROOT` 变量/环境变量 → `config/toolchain.local.conf` → 自动探测
（`<项目>/third_party/EzPC`、`<项目>/../third_party/EzPC`、`<项目>/../EzPC`、`~/EzPC`）。

`make` 只产生**一个**二进制 `src/sign/node`，它同时包含 ML-DSA-44/65/87 三套实现：
协议源码分别以三种参数集编译、各自部分链接并把内部符号本地化，再与一个运行时分发器
链接在一起。DFSS 适配器与参数集无关，只构建一份。之后换参数集**不需要重新编译**。

### 2.4 验证构建

```bash
./src/sign/node modes                  # 输出 44 65 87
ldd src/sign/node | grep dfss          # 已链接真实适配器
make selftest                          # 协议自检（进程内替身，产物 node-selftest），三种参数集
bash scripts/run_local_simulation.sh   # 单机两进程完整签名，末行应为 ACCEPT
```

---

## 3. 运行

### 3.1 单机模拟（参数集运行时选择）

```bash
bash scripts/run_local_simulation.sh --mldsa-mode 44 --message "hello"
bash scripts/run_local_simulation.sh --mldsa-mode 65 --message "hello"
bash scripts/run_local_simulation.sh --mldsa-mode 87 --batch-size 1 --pool-size 8 \
  --pool-mode refill --open-check strict --timeout 900 --message "hello"
```

输出在 `logs/local-m<mode>-<时间戳>/`：`p0.log`、`p1.log`，以及每方的
`public_key.bin`、`signature.bin`、`message.txt`、`summary.json`。
每次运行的配置生成在各自独立的 `runtime/generated-config/...` 目录中，互不覆盖。

### 3.2 两台物理机

在两台机器上都（各自执行一次 `make`）：

```bash
# 1) 填 IP（两台内容必须完全一致）
vi config/sign/common.physical.conf     # 替换 REPLACE_WITH_P0_IP / REPLACE_WITH_P1_IP

# 2) 分发私有身份：p0.conf+p0.seed 只放 P0 机器，p1.conf+p1.seed 只放 P1 机器

# 3) 大致同时启动（P1 会在超时内反复重试连接 P0），两边 --mldsa-mode 必须相同
bash scripts/run_physical_node.sh --node p0 --mldsa-mode 65 --message "hello"    # 机器 A
bash scripts/run_physical_node.sh --node p1 --mldsa-mode 65 --message "hello"    # 机器 B
```

防火墙需放行：P0 的协议端口（默认 9001），以及两台机器各自的 DFSS 端口
`base`、`base+3`、`base+50`、`base+100`（默认 base 为 10101 / 10301）。

### 3.3 离线验签（按公钥长度自动识别参数集）

```bash
./src/sign/node verify logs/.../p0/public_key.bin logs/.../p0/signature.bin logs/.../p0/message.txt
```

---

## 4. 配置项

公共拓扑（两台机器必须一致）：

| 字段 | 说明 |
| --- | --- |
| `party=<b>,<ip>,<port>,<dfss_port>` | 两行，`b∈{0,1}`。`port` 是协议信道端口（只有 P0 监听）；`dfss_port` 是该方 DFSS 基端口 |
| `mldsa_mode` | 44/65/87，运行时选择（由 `--mldsa-mode` 写入本次运行的配置） |
| `dcf_batch_size` | 一批候选数 K，1..8 |
| `dcf_pregen_pool_size` | 离线池容量 L，K..64 |
| `dcf_pool_exhaustion_mode` | `fixed`（耗尽即停）/ `refill`（续生成） |
| `open_check_mode` | `strict` / `off` |
| `worker_threads` | DFSS 在线阶段线程数，0=自动 |
| `timeout_seconds` | 单次收发超时 |

私有身份（各自机器一份）：`self_index=0|1`、`private_seed_file=...`。

本机工具链（不共享）：`config/toolchain.local.conf` 中的 `ezpc_root=`。它**不属于**协议配置，
写在 `common.*.conf` 里是无效的（节点会忽略，构建也不会从那里读取）。

握手阶段会逐项比对上述参数与**待签消息的摘要**，任何一项不一致都会
`HANDSHAKE_FAILED`。这条规则也意味着：两方必须各自同意同一条消息，不存在某一方
替另一方决定签什么。

## 5. 终止原因

| `terminal_reason` | 含义 |
| --- | --- |
| `SUCCESS` | 两方都得到同一份通过标准验证的签名 |
| `HANDSHAKE_FAILED` | 参数或待签消息不一致 |
| `CHANNEL_ERROR` | 连接断开、超时或帧失步 |
| `DKG_FAILED` | 密钥生成失败 |
| `DCF_ERROR` | DFSS keygen/eval 失败，或双方池区间不一致 |
| `PREPROCESSING_EXHAUSTED` | `pool_mode=fixed` 且离线池用尽 |
| `POOL_REFILL_FAILED` | 续生成失败 |
| `OPEN_CHECK_FAILED` | 两方视图不一致 |
| `VERIFY_FAILED` | 组装出的签名过不了标准验证 |
| `PEER_DISAGREE` | 两方签名摘要不同 |

## 6. 安全边界（请勿在论文中写过头）

本实现提供的是**半诚实**结构下的两方门限签名。以下四点是协议层面的边界，不是实现缺陷，
运行日志中的 `audit:` 一行会把第 1 点的实测数值打印出来：

1. **任一方在一次签名后即可恢复 `s2`（进而恢复 `s1`）**。两方都知道完整的 `w`、`z`、`t`，
   而 `A z − c t = w − c s2` 是恒等式，因此 `c·s2` 可直接算出。
2. **`‖z‖∞` 的 DCF 检查在当前 nonce 参数下几乎不会拒绝**：每方份额界为
   `(B−4096)/2`，聚合后 `|z| ≤ B−4096+2τη < B`。实测 8 次尝试全部由 DCF 判通过，
   拒绝全部来自 `r0`，而 `r0` 是在明文上算的。
3. **被 Algorithm 7 拒绝的候选，其 `z` 已经向双方打开**。只有被 DCF 判拒的候选才真正
   没有打开过 `z`。要做到“只在接受后才打开”，必须把 `r0`/`ct0`/hint 判定也放进 MPC。
4. **`open_check` 不是恶意安全检查**。两方之间每条消息只发给唯一的对方，不存在
   equivocation，双方视图都是同一份转录的确定性函数；它检测的是传输错误、状态机分叉与
   实现缺陷，恶意一方可以直接在压缩值上说谎。

此外，DKG 没有可验证秘密分享（VSS），也没有机制把某一方绑定到它在 DKG 中的份额；
这类偏离会导致签名过不了验证（DoS），而不是伪造。

伪代码与逐步推导见同目录下的 `main.tex`。

## 7. 安全模型的演进路线

按“功能正确 → 半诚实 → 恶意安全”三步推进，每一步的总体目标：

- **功能正确（当前所处阶段）**：两方协作输出能通过标准 FIPS 204 验证的签名，接口、状态机、
  测试与度量框架齐备。允许存在第 6 节列出的中间值泄露。
- **半诚实安全**：假设双方严格按协议执行，要求任一方的全部视图（收到的消息 + 自己的份额与随机数）
  都能仅凭它自己的输入和最终签名模拟出来。对本项目而言，核心是消除第 6 节第 1、3 点：
  不公开完整 `t`/`w`，把全部拒绝判定（`z` 范数、`r0`、`ct0`、hint）放进 MPC，只有被接受的候选才打开，
  并给出基于模拟的证明。**这一步不需要 MAC**。
- **恶意安全（带中止）**：对手可任意偏离协议，要求任何偏离要么被检测到并中止，要么不影响输出正确性与私钥保密性。
  需要认证份额（SPDZ 类 MAC）或零知识证明、可验证 DKG、恶意安全的 OT/DCF 密钥生成与打开检查。
  MAC 属于这一步的工具。两方场景下一般只能做到“带中止”的安全，无法保证公平输出。
'''

EXECUTABLE = {
    "scripts/build_dependencies.sh",
    "scripts/run_local_simulation.sh",
    "scripts/run_physical_node.sh",
    "scripts/check_dfss_environment.py",
    "scripts/prepare_runtime_configs.py",
    "scripts/toolchain_config.py",
}

# ---------------------------------------------------------------------------
# 原地修改：(相对路径, 旧文本, 新文本)。新文本已存在则视为已应用。
# ---------------------------------------------------------------------------
HEADER_ABI_OLD = "#define DCF_DEALERLESS_BACKEND_ABI_VERSION 3u\n"
HEADER_ABI_NEW = """#define DCF_DEALERLESS_BACKEND_ABI_VERSION 4u

/* ABI v4：结构体大小与 ML-DSA 参数集无关，按最大参数集（ML-DSA-87: L+K=15）定长，
 * 这样一份 libdfss_sign_adapter 可同时服务 44/65/87 三套协议实现；实际长度由 coeff_count 给出。 */
#define DCF_MAX_SK_COEFFS ((7 + 8) * 256)
#if DILITHIUM_SK_COEFFS > DCF_MAX_SK_COEFFS
#error "DCF_MAX_SK_COEFFS too small for this ML-DSA parameter set"
#endif
"""

MAIN_OLD = "int main(int argc, char **argv) {\n"
MAIN_NEW = """/* 不再是进程入口：构建时被重命名为 node_main_<mode>，由 dispatch/node_dispatch.c 在运行时
 * 按参数集调用。同一个 node 二进制因此同时包含 ML-DSA-44/65/87。 */
int node_mode_main(int argc, char **argv);

int node_mode_main(int argc, char **argv) {
"""

CONFIG_KEY_OLD = """        } else if (strcmp(key, "timeout_seconds") == 0) {
            cfg->timeout_seconds = atoi(val);
        } else {"""
CONFIG_KEY_NEW = """        } else if (strcmp(key, "timeout_seconds") == 0) {
            cfg->timeout_seconds = atoi(val);
        } else if (strcmp(key, "ezpc_root") == 0) {
            /* 本机工具链路径属于 config/toolchain.local.conf，不是协议参数；这里忽略。 */
        } else {"""

EDITS: list[tuple[str, str, str]] = [
    ("include/dcf_dealerless_backend.h", HEADER_ABI_OLD, HEADER_ABI_NEW),
    ("include/dcf_dealerless_backend.h",
     "    uint32_t local_mask_shares[DILITHIUM_SK_COEFFS]; /* private r_b[j] */",
     "    uint32_t local_mask_shares[DCF_MAX_SK_COEFFS]; /* private r_b[j]，前 coeff_count 项有效 */"),
    ("include/config.h",
     " *   mldsa_mode=44|65|87                          必须与编译模式一致",
     " *   mldsa_mode=44|65|87                          运行时选择（同一 node 含三套实现）"),
    ("src/sign/src/main.c", MAIN_OLD, MAIN_NEW),
    ("src/sign/src/main.c",
     " * 两方运行的是同一个二进制、同一份代码；唯一区别是配置里的 self_index。\n",
     " * 两方运行的是同一个二进制、同一份代码；唯一区别是配置里的 self_index。\n"
     " * 参数集由 dispatch/node_dispatch.c 在运行时选择（--mldsa-mode 或配置中的 mldsa_mode）。\n"),
    ("src/sign/src/config.c", CONFIG_KEY_OLD, CONFIG_KEY_NEW),
    ("src/sign/src/config.c",
     '"[config] mldsa_mode=%d，但本二进制编译为 ML-DSA-%d\\n"',
     '"[config] mldsa_mode=%d，但分发器选中的实现是 ML-DSA-%d\\n"'),
    ("src/sign/src/dcf_rejects.c",
     " * DFSS 适配器 ABI（v3）保持不变：",
     " * DFSS 适配器 ABI（v4，结构体按最大参数集定长、与 ML-DSA 模式无关）："),
    ("src/dcf/CMakeLists.txt",
     "    target_compile_definitions(dfss_sign_adapter PRIVATE MLDSA_MODE=${DEALERLESS_MLDSA_MODE})\n",
     "    # 适配器 ABI v4 与 ML-DSA 参数集无关：不再按 MLDSA_MODE 编译，一份库服务 44/65/87。\n"),
    ("src/dcf/CMakeLists.txt",
     'set(DEALERLESS_MLDSA_MODE "44" CACHE STRING "ML-DSA mode for the sign/DFSS ABI")',
     'set(DEALERLESS_MLDSA_MODE "44" CACHE STRING "Deprecated and ignored: the DFSS ABI is mode-independent")'),
]

# 全局正则替换：(相对路径, 模式, 替换)
REGEX_EDITS: list[tuple[str, str, str]] = [
    ("src/dcf/integration/dfss_sign_adapter.cpp", r"\bDILITHIUM_SK_COEFFS\b", "DCF_MAX_SK_COEFFS"),
]

# 旧的单模式构建产物（会与新产物混淆，删除）
STALE_PATHS = [
    "src/sign/node", "src/sign/node-selftest",
    "src/sign/node-44", "src/sign/node-65", "src/sign/node-87",
    "build/dfss-44", "build/dfss-65", "build/dfss-87",
]


def say(msg: str) -> None:
    print(f"[apply] {msg}")


def warn(msg: str) -> None:
    print(f"[apply][warn] {msg}", file=sys.stderr)


class Plan:
    def __init__(self, root: Path):
        self.root = root
        self.writes: dict[Path, str] = {}
        self.removals: list[Path] = []
        self.errors: list[str] = []
        self.notes: list[str] = []

    def current(self, rel: str) -> str | None:
        p = self.root / rel
        if p in self.writes:
            return self.writes[p]
        return p.read_text(encoding="utf-8") if p.is_file() else None

    def set(self, rel: str, text: str) -> None:
        p = self.root / rel
        old = p.read_text(encoding="utf-8") if p.is_file() else None
        if old == text:
            self.writes.pop(p, None)
        else:
            self.writes[p] = text


def plan_changes(root: Path) -> Plan:
    plan = Plan(root)

    for rel, text in FILES.items():
        plan.set(rel, text)

    for rel, old, new in EDITS:
        cur = plan.current(rel)
        if cur is None:
            plan.errors.append(f"缺少文件 {rel}")
            continue
        if new in cur:
            continue
        if old not in cur:
            plan.errors.append(f"{rel}: 找不到要替换的原文（文件可能已被手工修改）：{old.strip()[:60]!r}")
            continue
        plan.set(rel, cur.replace(old, new, 1))

    for rel, pattern, repl in REGEX_EDITS:
        cur = plan.current(rel)
        if cur is None:
            plan.errors.append(f"缺少文件 {rel}")
            continue
        plan.set(rel, re.sub(pattern, repl, cur))

    # ezpc_root 从协议配置迁移到本机工具链配置
    tool_rel = "config/toolchain.local.conf"
    tool_text = plan.current(tool_rel)
    has_tool_key = bool(tool_text and re.search(r"(?m)^\s*ezpc_root\s*=", tool_text))
    for rel in ("config/sign/common.local.conf", "config/sign/common.physical.conf"):
        cur = plan.current(rel)
        if cur is None:
            continue
        found = re.findall(r"(?m)^\s*ezpc_root\s*=\s*(.+?)\s*$", cur)
        if not found:
            continue
        value = found[-1]
        stripped = re.sub(r"(?m)^\s*ezpc_root\s*=.*\n?", "", cur)
        plan.set(rel, stripped)
        plan.notes.append(f"已从 {rel} 移除 ezpc_root={value}（协议配置不放本机路径）")
        if not has_tool_key:
            resolved = (root / value).resolve() if not os.path.isabs(value) else Path(value)
            ok = (resolved / "FSS" / "src" / "CMakeLists.txt").is_file()
            plan.set(tool_rel,
                     "# 本机 EzPC 依赖路径（相对路径以项目根目录为基准）；不属于共享协议拓扑，勿提交到仓库。\n"
                     f"ezpc_root={value}\n")
            has_tool_key = True
            plan.notes.append(
                f"已迁移到 {tool_rel}: ezpc_root={value} -> {resolved} "
                + ("（有效）" if ok else "（该路径下未找到 FSS/src/CMakeLists.txt，构建时会自动探测其他位置）"))

    # 过期产物
    for rel in STALE_PATHS:
        p = root / rel
        if p.exists():
            plan.removals.append(p)
    for p in list((root / "src" / "sign" / "src").glob("*.o")) + list((root / "src" / "sign" / "src").glob("*.d")):
        plan.removals.append(p)
    cache = root / "build" / "dfss" / "CMakeCache.txt"
    if cache.is_file():
        m = re.search(r"(?m)^CMAKE_HOME_DIRECTORY:INTERNAL=(.*)$", cache.read_text(encoding="utf-8", errors="replace"))
        home = Path(m.group(1)).resolve() if m else None
        if home != (root / "src" / "dcf").resolve():
            plan.removals.append(root / "build" / "dfss")
            plan.notes.append(f"build/dfss 的 CMake 缓存来自其他目录（{home}），将删除后重新配置")
    return plan


def find_spdz(root: Path) -> list[Path]:
    bases = [root / "third_party", root.parent / "third_party", root.parent, Path.home(), Path.home() / "third_party"]
    found: list[Path] = []
    seen: set[Path] = set()
    for base in bases:
        if not base.is_dir():
            continue
        try:
            children = list(base.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_dir() and not child.is_symlink() and "spdz" in child.name.lower():
                rp = child.resolve()
                if rp not in seen and rp != root.resolve():
                    seen.add(rp)
                    found.append(child)
    return found


def backup(root: Path, paths: list[Path], stamp: str) -> Path:
    bdir = root / ".patch_backup" / stamp
    for p in paths:
        if not p.exists():
            continue
        dest = bdir / p.relative_to(root)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if p.is_dir():
            continue  # 构建目录不备份
        shutil.copy2(p, dest)
    return bdir


def run(cmd: list[str], cwd: Path) -> int:
    say("$ " + " ".join(cmd))
    return subprocess.call(cmd, cwd=str(cwd))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="项目根目录（默认当前目录）")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--build", action="store_true", help="修改后执行 make 与三种参数集自检")
    ap.add_argument("--purge-spdz", action="store_true", help="删除检测到的 MP-SPDZ 目录")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not (root / "src" / "sign" / "src" / "main.c").is_file() or not (root / "src" / "dcf").is_dir():
        print(f"[apply][error] {root} 看起来不是 threshold_mldsa_2party 项目根目录", file=sys.stderr)
        return 2

    plan = plan_changes(root)
    if plan.errors:
        print("[apply][error] 以下修改无法应用，未改动任何文件：", file=sys.stderr)
        for e in plan.errors:
            print("  - " + e, file=sys.stderr)
        return 1

    say(f"项目根目录：{root}")
    for p in sorted(plan.writes):
        say(("新建 " if not p.exists() else "修改 ") + str(p.relative_to(root)))
    for p in plan.removals:
        say("删除 " + str(p.relative_to(root)))
    for n in plan.notes:
        say(n)
    if not plan.writes and not plan.removals:
        say("代码已是最新，无需修改")

    spdz = find_spdz(root)
    if spdz:
        for d in spdz:
            say(f"发现 MP-SPDZ 目录：{d}（本项目不再使用）")
    else:
        say("未发现 MP-SPDZ 目录；项目代码中也没有对它的引用")

    if args.dry_run:
        say("dry-run：未写入任何文件")
        return 0

    stamp = time.strftime("%Y%m%d-%H%M%S")
    touched = list(plan.writes) + [p for p in plan.removals if p.is_file()]
    if touched:
        bdir = backup(root, touched, stamp)
        if bdir.exists():
            say(f"原文件已备份到 {bdir.relative_to(root)}")

    for p, text in plan.writes.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        rel = str(p.relative_to(root))
        if rel in EXECUTABLE:
            p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    for p in plan.removals:
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        elif p.exists():
            p.unlink()

    if args.purge_spdz:
        for d in spdz:
            say(f"删除 {d}")
            shutil.rmtree(d, ignore_errors=True)
    elif spdz:
        say("如需删除上述 MP-SPDZ 目录：python3 apply_fixes.py --purge-spdz（或手动 rm -rf）")

    # 报告 EzPC 解析结果（会自动探测并写入 config/toolchain.local.conf）
    rc = subprocess.call([sys.executable, str(root / "scripts" / "toolchain_config.py"), "--get"], cwd=str(root))
    if rc != 0:
        warn("暂未找到 EzPC；按上面的提示指定一次路径即可（make EZPC_ROOT=/absolute/path/to/EzPC）")

    if args.build:
        if run(["make"], root) != 0:
            return 1
        if run([str(root / "src" / "sign" / "node"), "selftest", "--all-modes"], root) != 0:
            return 1

    print()
    say("完成。之后的流程：")
    print("    make                                                   # 一次编译（含 ML-DSA-44/65/87）")
    print("    bash scripts/run_local_simulation.sh --mldsa-mode 44 --message hello")
    print("    bash scripts/run_local_simulation.sh --mldsa-mode 65 --message hello   # 换参数集无需重编")
    print("    bash scripts/run_local_simulation.sh --mldsa-mode 87 --message hello")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
