# 签名协议构建：一次构建同时编译 ML-DSA-44/65/87 三套实现，链接成一个二进制。
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
