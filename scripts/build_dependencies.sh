#!/usr/bin/env bash
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
