#!/usr/bin/env bash
# 在物理机上启动本方节点。两台机器各执行一次，--node 不同即可；--mldsa-mode 两边必须一致。
# 先在两台机器上填好 config/sign/common.physical.conf 里的两个 IP。
#
# 关于待签消息：两台机器必须签**完全相同的字节**，所以物理部署不做本机随机生成。
#   推荐做法：在任意一台上 `python3 scripts/gen_message.py --out-dir /tmp/msg --mode timestamped`，
#   把生成的 message.txt 拷到另一台，两边都用 --message-file 指向它。
#   直接用 --message "文本" 也可以，但要保证两边一字不差（握手会校验消息摘要，不一致会中止）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE="${ROOT}/src/sign/node"
SELF=""; MODE=44; BATCH=1; POOL=8; POOL_MODE=refill; OPEN_CHECK=strict
TIMEOUT=900; MESSAGE=""; MESSAGE_FILE=""; DO_REPORT=1

usage() {
  cat <<'USAGE'
用法: scripts/run_physical_node.sh --node p0|p1 [选项]
  --mldsa-mode 44|65|87     参数集（两台必须相同）
  --batch-size K / --pool-size L / --pool-mode fixed|refill
  --open-check strict|off / --timeout N
  --message TEXT            待签消息文本（两台必须一字不差）
  --message-file PATH       待签消息文件（推荐：两台使用同一份拷贝）
  --no-report               跳过结束后的汇总表
USAGE
}

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
    --message-file) MESSAGE_FILE="$2"; shift 2 ;;
    --no-report) DO_REPORT=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数 $1" >&2; usage; exit 2 ;;
  esac
done
[ "${SELF}" = "p0" ] || [ "${SELF}" = "p1" ] || { echo "需要 --node p0|p1" >&2; exit 2; }
if [ -z "${MESSAGE}" ] && [ -z "${MESSAGE_FILE}" ]; then
  echo "需要 --message 或 --message-file（两台机器必须是同一条消息）" >&2
  exit 2
fi
if [ ! -x "${NODE}" ]; then
  echo "找不到 ${NODE}。在项目根目录执行一次 make 即可（同时编译 ML-DSA-44/65/87）" >&2
  exit 1
fi
if ! "${NODE}" modes 2>/dev/null | tr ' ' '\n' | grep -qx "${MODE}"; then
  echo "当前 ${NODE} 不支持 ML-DSA-${MODE}，请重新执行 make" >&2
  exit 1
fi

CONF="$(python3 "${ROOT}/scripts/prepare_runtime_configs.py" --profile physical --node "${SELF}" \
  --mldsa-mode "${MODE}" --batch-size "${BATCH}" --pool-size "${POOL}" \
  --pool-mode "${POOL_MODE}" --open-check "${OPEN_CHECK}" --timeout "${TIMEOUT}")"

OUT="${ROOT}/logs/physical-m${MODE}-$(date +%Y%m%d-%H%M%S)-${SELF}"
mkdir -p "${OUT}/${SELF}"

# 统一成“先落盘、再签名”：即使用了 --message，也先写成文件，日志里留下真正被签的字节。
if [ -n "${MESSAGE_FILE}" ]; then
  python3 "${ROOT}/scripts/gen_message.py" --out-dir "${OUT}" --mode file \
    --source "${MESSAGE_FILE}" >/dev/null
else
  python3 "${ROOT}/scripts/gen_message.py" --out-dir "${OUT}" --mode text \
    --text "${MESSAGE}" >/dev/null
fi
MSG_FILE="${OUT}/message.txt"

echo "════════════════════════════════════════════════════════════════════════"
printf ' %s  ML-DSA-%s  K=%s L=%s(%s)  open_check=%s\n' "${SELF}" "${MODE}" "${BATCH}" "${POOL}" "${POOL_MODE}" "${OPEN_CHECK}"
printf ' 配置 %s\n 日志 %s\n 消息 %s（sha256 见 message.meta.json）\n' "${CONF}" "${OUT}" "${MSG_FILE}"
echo "════════════════════════════════════════════════════════════════════════"

T0=$(date +%s%3N 2>/dev/null || echo 0)
set +e
"${NODE}" "${CONF}" --message-file "${MSG_FILE}" --out-dir "${OUT}/${SELF}" 2>&1 | tee "${OUT}/${SELF}.log"
RC="${PIPESTATUS[0]}"
set -e
T1=$(date +%s%3N 2>/dev/null || echo 0)

if [ "${DO_REPORT}" -eq 1 ]; then
  echo
  python3 "${ROOT}/scripts/report.py" "${OUT}" --wall-ms "$((T1 - T0))" || true
  echo "[run] 本机只看得到自己这一侧的 DFSS 记录；两侧合并请把对方的 ${SELF} 日志目录拷过来再跑 report.py。"
fi
exit "${RC}"
