SHELL := /bin/bash
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
