#!/usr/bin/env bash
# 在一台机器上同时起 P0 与 P1 两个进程，跑一次完整的 2-of-2 门限签名。
# 两个进程运行的是同一个二进制；参数集（44/65/87）在运行时由 --mldsa-mode 选择，无需重新编译。
#
# 流程分三步，控制台按步骤打印：
#   1/3 生成待签消息 -> logs/<本次运行>/message.txt（由 scripts/gen_message.py 完成）
#   2/3 两方执行 DKeyGen / DCFPrep / DSign / Verify（节点只读第 1 步产生的那份消息文件）
#   3/3 汇总（scripts/report.py）+ 用标准 ML-DSA 接口离线复验
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE="${ROOT}/src/sign/node"
MODE=44; BATCH=1; POOL=8; POOL_MODE=refill; OPEN_CHECK=strict
TIMEOUT=900
MSG_MODE=""; MSG_TEXT=""; MSG_BYTES=64; MSG_SOURCE=""; DO_REPORT=1

usage() {
  cat <<'USAGE'
用法: scripts/run_local_simulation.sh [选项]
  --mldsa-mode 44|65|87      参数集，运行时选择，默认 44
  --batch-size K             一批的候选数，1..8，默认 1
  --pool-size L              离线 DCF 池容量，默认 8
  --pool-mode fixed|refill   池耗尽时停止或续生成，默认 refill
  --open-check strict|off    打开一致性检查，默认 strict
  --timeout N                单次收发超时秒数，默认 900

  待签消息（第 1 步生成，写到 logs/<本次运行>/message.txt）：
  --message TEXT             直接给定消息文本（等价于 --message-mode text）
  --message-mode MODE        timestamped(默认) | text | random | file | stdin
                             timestamped: 自动生成含运行号/时间/随机 nonce 的消息
  --message-bytes N          --message-mode random 时的长度，默认 64
  --message-source PATH      --message-mode file 时的源文件
  --no-report                跳过第 3 步的汇总表
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
    --message) MSG_TEXT="$2"; MSG_MODE="text"; shift 2 ;;
    --message-mode) MSG_MODE="$2"; shift 2 ;;
    --message-bytes) MSG_BYTES="$2"; shift 2 ;;
    --message-source) MSG_SOURCE="$2"; shift 2 ;;
    --no-report) DO_REPORT=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数 $1" >&2; usage; exit 2 ;;
  esac
done
[ -n "${MSG_MODE}" ] || MSG_MODE=timestamped

if [ ! -x "${NODE}" ]; then
  echo "找不到 ${NODE}。在项目根目录执行一次 make 即可（同时编译 ML-DSA-44/65/87）；" >&2
  echo "首次如需指定 EzPC：make EZPC_ROOT=/absolute/path/to/EzPC" >&2
  exit 1
fi
if ! "${NODE}" modes 2>/dev/null | tr ' ' '\n' | grep -qx "${MODE}"; then
  echo "当前 ${NODE} 不支持 ML-DSA-${MODE}（可能是旧版单模式二进制），请在项目根目录重新执行 make" >&2
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_ID="local-m${MODE}-${STAMP}"
OUT="${ROOT}/logs/${RUN_ID}"
mkdir -p "${OUT}/p0" "${OUT}/p1"

rule() { printf '%s\n' "────────────────────────────────────────────────────────────────────────"; }
head_line() { printf '%s\n' "════════════════════════════════════════════════════════════════════════"; }

head_line
printf ' 两方门限 ML-DSA 本地模拟   run=%s\n' "${RUN_ID}"
printf ' 参数集 ML-DSA-%-3s | 批大小 K=%-2s | 离线池 L=%-3s (%s) | 一致性检查 %s | 超时 %ss\n' \
  "${MODE}" "${BATCH}" "${POOL}" "${POOL_MODE}" "${OPEN_CHECK}" "${TIMEOUT}"
printf ' 日志目录 %s\n' "${OUT}"
head_line

# ---------------------------------------------------------------- 步骤 1/3
printf '\n[1/3] 生成待签消息\n'; rule
GEN_ARGS=(--out-dir "${OUT}" --mode "${MSG_MODE}" --run-id "${RUN_ID}" --label "ML-DSA-${MODE}")
[ -n "${MSG_TEXT}" ] && GEN_ARGS+=(--text "${MSG_TEXT}")
[ -n "${MSG_SOURCE}" ] && GEN_ARGS+=(--source "${MSG_SOURCE}")
GEN_ARGS+=(--bytes "${MSG_BYTES}")
MSG_FILE="$(python3 "${ROOT}/scripts/gen_message.py" "${GEN_ARGS[@]}")"
printf '消息文件 %s\n' "${MSG_FILE}"

# ---------------------------------------------------------------- 步骤 2/3
printf '\n[2/3] 执行两方协议（DKeyGen → DCFPrep → DSign → Verify）\n'; rule
CFG_DIR="$(python3 "${ROOT}/scripts/prepare_runtime_configs.py" --profile local \
  --mldsa-mode "${MODE}" --batch-size "${BATCH}" --pool-size "${POOL}" \
  --pool-mode "${POOL_MODE}" --open-check "${OPEN_CHECK}" --timeout "${TIMEOUT}")"
printf '运行配置 %s\n' "${CFG_DIR}"
printf '离线预处理通常是耗时大头（每个池项数百毫秒到数秒），请耐心等待…\n'

T0=$(date +%s%3N 2>/dev/null || echo 0)
# P1 先起（它会重试连接 P0），然后起 P0。两者地位对称，先后只影响 TCP 建连。
"${NODE}" "${CFG_DIR}/p1.conf" --message-file "${MSG_FILE}" --out-dir "${OUT}/p1" > "${OUT}/p1.log" 2>&1 &
P1=$!
sleep 0.5
set +e
timeout "$((TIMEOUT + 60))" "${NODE}" "${CFG_DIR}/p0.conf" --message-file "${MSG_FILE}" \
  --out-dir "${OUT}/p0" > "${OUT}/p0.log" 2>&1
RC0=$?
wait ${P1}; RC1=$?
set -e
T1=$(date +%s%3N 2>/dev/null || echo 0)
WALL=$((T1 - T0))

grep -hE "verify_result=" "${OUT}/p0.log" "${OUT}/p1.log" | sed 's/^/  /' || true
printf '进程退出码 p0=%s p1=%s，墙钟 %s ms\n' "${RC0}" "${RC1}" "${WALL}"

# ---------------------------------------------------------------- 步骤 3/3
printf '\n[3/3] 汇总与离线复验\n'; rule
if [ "${DO_REPORT}" -eq 1 ]; then
  python3 "${ROOT}/scripts/report.py" "${OUT}" --wall-ms "${WALL}" || true
fi

if [ ${RC0} -eq 0 ] && [ ${RC1} -eq 0 ]; then
  printf '\n'
  "${NODE}" verify "${OUT}/p0/public_key.bin" "${OUT}/p0/signature.bin" "${OUT}/message.txt"
  printf '[run] PASS   签名 %s\n' "${OUT}/p0/signature.bin"
  printf '[run] 完整日志 %s/p0.log %s/p1.log\n' "${OUT}" "${OUT}"
else
  printf '[run] FAIL  p0_rc=%s p1_rc=%s，最后若干行日志：\n' "${RC0}" "${RC1}" >&2
  tail -8 "${OUT}/p0.log" >&2 || true
  exit 1
fi
