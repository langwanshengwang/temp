#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apply_console_and_message_upgrade.py —— 在 threshold_mldsa_2party 项目根目录运行。

本脚本解决三件事：

1) 通信量统计看起来“掉了一个数量级”的疑问。
   结论：DFSS 的通信量一点没变，是**汇总表少统计了它**。节点的 summary.json 只记录
   P0↔P1 协议信道，所以离线阶段显示 `dcf_prep sent_bytes=48`——那 48 字节只是两方同步
   “池区间/池是否就绪”。真正的离线开销全部走 DFSS 栈自己的连接，只出现在日志里的
   DFSS_CORE_* 行中（ML-DSA-44、1024 lane：C0 发 5,430,784 B + C1 发 8,052,736 B，
   合计 13,483,520 B = 13167.5 KiB/池项；在线每次批量比较 45,048×2 B = 87.984 KiB）。
   这两个数与旧版四节点工程逐字节相同，旧版只是把它们并进了同一张表。
   本脚本新增 scripts/report.py，把 summary.json 与 DFSS_CORE_* 合并成一张表，
   dfss_wire_KiB 口径 = 两侧 sent 之和，与旧版 dfss_wire_kib/call 完全一致。

2) 控制台输出格式化。
   - 新增 scripts/report.py：运行概览 + 阶段汇总表 + 通信量总账，同时写入
     logs/<本次运行>/report.txt 与 report.json，事后可随时重新生成。
   - run_local_simulation.sh 改成分三步的结构化输出。
   - 节点自身的日志按“阶段 1/4 … 4/4”分块，收尾的 SUMMARY 改成对齐表格。

3) 待签消息先由脚本生成、落盘，再进入密钥生成与签名。
   - 新增 scripts/gen_message.py：把消息写到 logs/<本次运行>/message.txt，
     并附 message.meta.json（长度、SHA-256/SHA3-256、生成方式、时间戳）。
   - 节点新增 --message-file，run_local_simulation.sh 第 1 步先生成、第 2 步才启动协议。
   - 消息摘要本来就参与握手比对，因此两方读到不同文件会在握手阶段 fail-closed。

用法（在项目根目录）：
    python3 apply_console_and_message_upgrade.py --check-only   # 只看会改什么
    python3 apply_console_and_message_upgrade.py                # 应用（自动备份）
    python3 apply_console_and_message_upgrade.py --build        # 应用后立即 make + 自检
    python3 apply_console_and_message_upgrade.py --restore .patch_backup/<时间戳>
脚本可重复运行：已应用的改动会被跳过。
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

NEW_FILES: dict[str, str] = {}
EDITS: list[tuple[str, str, str]] = []
SPANS: list[tuple[str, str, str, str, str]] = []

NEW_FILES['scripts/gen_message.py'] = r'''#!/usr/bin/env python3
"""生成本次运行的待签消息文件（在真正执行密钥生成/签名之前调用）。

签名协议本身只接受“一条已经确定下来的消息”。把消息的产生独立成这一步，好处是：
运行记录里留下的是**实际被签名的那一份字节**，而不是命令行里的一个参数；两方也可以
核对彼此读到的是同一个文件。

输出（默认写在本次运行的日志目录下）：
  <out_dir>/message.txt        真正送进协议的消息内容（不追加换行）
  <out_dir>/message.meta.json  长度、SHA-256/SHA3-256 摘要、生成方式、时间戳

约束：节点把消息当成 C 字符串处理，因此消息不能含 NUL 字节，长度上限 1023 字节。

用法示例：
  python3 scripts/gen_message.py --out-dir logs/run-x --mode timestamped --run-id run-x
  python3 scripts/gen_message.py --out-dir logs/run-x --mode text --text "hello"
  python3 scripts/gen_message.py --out-dir logs/run-x --mode random --bytes 256
  python3 scripts/gen_message.py --out-dir logs/run-x --mode file --source /path/to/doc.txt
  cat doc.txt | python3 scripts/gen_message.py --out-dir logs/run-x --mode stdin
成功时向 stdout 打印 message.txt 的绝对路径（供 shell 脚本捕获）。
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

MAX_BYTES = 1023  # 与 C 端 MAX_MESSAGE_BYTES-1 对齐


def fail(msg: str) -> None:
    print(f"[gen-message] 错误：{msg}", file=sys.stderr)
    raise SystemExit(2)


def build_payload(args: argparse.Namespace) -> tuple[str, str]:
    """返回 (消息文本, 生成方式描述)。"""
    if args.mode == "text":
        if args.text is None:
            fail("--mode text 需要 --text")
        return args.text, "text(命令行给定)"

    if args.mode == "timestamped":
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = base64.b16encode(os.urandom(8)).decode().lower()
        body = (
            "threshold-mldsa-2of2 demo message\n"
            f"run={args.run_id}\n"
            f"mldsa={args.label}\n"
            f"utc={now}\n"
            f"nonce={nonce}"
        )
        return body, "timestamped(每次运行内容不同)"

    if args.mode == "random":
        n = args.bytes
        if not 1 <= n <= MAX_BYTES:
            fail(f"--bytes 必须在 1..{MAX_BYTES}")
        raw = base64.urlsafe_b64encode(os.urandom(n)).decode("ascii")[:n]
        return raw, f"random({n} 可打印字节)"

    if args.mode == "file":
        if not args.source:
            fail("--mode file 需要 --source")
        p = Path(args.source).expanduser()
        if not p.is_file():
            fail(f"找不到 {p}")
        data = p.read_bytes()
        try:
            return data.decode("utf-8"), f"file({p})"
        except UnicodeDecodeError:
            fail(f"{p} 不是 UTF-8 文本；当前协议只签名文本消息")

    if args.mode == "stdin":
        data = sys.stdin.buffer.read()
        try:
            return data.decode("utf-8"), "stdin"
        except UnicodeDecodeError:
            fail("stdin 不是 UTF-8 文本")

    fail(f"未知 --mode {args.mode}")
    raise AssertionError


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", required=True, help="本次运行的日志目录")
    ap.add_argument("--mode", default="timestamped",
                    choices=("timestamped", "text", "random", "file", "stdin"))
    ap.add_argument("--text", help="--mode text 时的消息内容")
    ap.add_argument("--bytes", type=int, default=64, help="--mode random 时的长度")
    ap.add_argument("--source", help="--mode file 时的源文件")
    ap.add_argument("--run-id", default="local", help="写进 timestamped 消息的运行标识")
    ap.add_argument("--label", default="", help="写进 timestamped 消息的参数集标识")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    text, how = build_payload(args)
    raw = text.encode("utf-8")
    if b"\x00" in raw:
        fail("消息不能包含 NUL 字节（节点按 C 字符串处理）")
    if not raw:
        fail("消息不能为空")
    if len(raw) > MAX_BYTES:
        fail(f"消息 {len(raw)} 字节，超过上限 {MAX_BYTES}")

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    msg_path = out_dir / "message.txt"
    msg_path.write_bytes(raw)

    meta = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": args.mode,
        "how": how,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sha3_256": hashlib.sha3_256(raw).hexdigest(),
        "path": str(msg_path),
        "preview": text if len(text) <= 120 else text[:117] + "...",
    }
    (out_dir / "message.meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if not args.quiet:
        print(f"[gen-message] 方式={how} 长度={len(raw)}B sha256={meta['sha256'][:16]}…",
              file=sys.stderr)
        preview = meta["preview"].replace("\n", "\\n")
        print(f"[gen-message] 内容预览: {preview}", file=sys.stderr)
    print(msg_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

NEW_FILES['scripts/report.py'] = r'''#!/usr/bin/env python3
"""把一次运行的结果汇总成一张表。

数据来源有两处，缺一不可：
  1. <run>/p{0,1}/summary.json —— 节点自己记录的**协议信道**（P0↔P1）分阶段耗时/轮数/字节；
  2. <run>/p{0,1}.log 里的 DFSS_CORE_* 行 —— DFSS/EzPC 适配器自己记录的 2PC 内部流量。

这两部分是分开计量的，这一点很重要：节点的 `phase=dcf_prep sent_bytes=48` 只是
两方在协议信道上同步“池区间/池是否就绪”的几十字节，真正的离线开销（每个池项数 MiB）
全部发生在 DFSS 栈自己的连接上，节点看不到，也就不会出现在 summary.json 里。
本脚本把两者合并，dfss_wire_KiB = 两方 sent_bytes 之和（每个字节只被发送一次，
因此这就是链路上的真实字节数），与旧版四节点工程 `dfss_wire_kib/call` 口径一致。

用法：
  python3 scripts/report.py <run_dir> [--wall-ms N] [--no-write]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

KV = re.compile(r"(\w+)=([-\w./]+)")

# (显示名, 汇总的 phase 列表, dfss 归属)
ROWS = [
    ("init(handshake)", ["handshake"], None),
    ("dkeygen", ["dkeygen"], None),
    ("dcf_offline", ["dcf_prep"], "offline"),
    ("sign_total", ["sign_attempt", "rejects_dcf_online", "open_zr_alg7",
                    "open_check", "verify"], "online"),
    ("  ├ sign_attempt", ["sign_attempt"], None),
    ("  ├ dcf_online_rejects", ["rejects_dcf_online"], "online"),
    ("  ├ open_zr_alg7", ["open_zr_alg7"], None),
    ("  ├ open_check", ["open_check"], None),
    ("  └ verify", ["verify"], None),
]


def parse_dfss(log: Path) -> dict:
    """从一个节点日志里取出该侧适配器记录的 DFSS 2PC 流量。"""
    out = {
        "offline": {"calls": 0, "ms": [], "sent": 0, "recv": 0},
        "online": {"calls": 0, "ms": [], "sent": 0, "recv": 0, "candidates": 0},
    }
    if not log.is_file():
        return out
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        if "DFSS_CORE_OFFLINE" in line:
            kind, ms_key = "offline", "core_offline_ms"
        elif "DFSS_CORE_ONLINE" in line:      # 同时覆盖 ONLINE 与 ONLINE_BATCH
            kind, ms_key = "online", "core_online_ms"
        else:
            continue
        kv = dict(KV.findall(line))
        slot = out[kind]
        slot["calls"] += 1
        try:
            slot["ms"].append(float(kv.get(ms_key, "0")))
            slot["sent"] += int(kv.get("dfss_sent_bytes", "0"))
            slot["recv"] += int(kv.get("dfss_recv_bytes", "0"))
            if kind == "online":
                slot["candidates"] += int(kv.get("candidates", "1"))
        except ValueError:
            pass
    return out


def merge_dfss(a: dict, b: dict) -> dict:
    merged = {}
    for kind in ("offline", "online"):
        calls = max(a[kind]["calls"], b[kind]["calls"])      # 每侧各记一次，取单侧调用数
        ms = a[kind]["ms"] + b[kind]["ms"]
        wire = a[kind]["sent"] + b[kind]["sent"]             # 链路真实字节
        merged[kind] = {
            "calls": calls,
            "core_ms_per_call": (sum(ms) / len(ms)) if ms else 0.0,
            "core_ms_total_per_party": (sum(ms) / 2.0) if ms else 0.0,
            "wire_bytes": wire,
            "wire_bytes_per_call": (wire / calls) if calls else 0.0,
            "candidates": a[kind].get("candidates", 0),
        }
    return merged


def load_summary(run: Path, party: str) -> dict | None:
    p = run / party / "summary.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def kib(n: float) -> float:
    return n / 1024.0


def dwidth(s: str) -> int:
    """显示宽度：CJK 全角字符按 2 列算，否则中英混排的表格会错位。"""
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def table(headers: list[str], rows: list[list[str]], aligns: str) -> str:
    widths = [dwidth(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], dwidth(cell))

    def fmt(cells: list[str]) -> str:
        parts = []
        for i, cell in enumerate(cells):
            fill = " " * (widths[i] - dwidth(cell))
            parts.append(cell + fill if aligns[i] == "l" else fill + cell)
        return " | ".join(parts)

    sep = "-+-".join("-" * w for w in widths)
    return "\n".join([fmt(headers), sep] + [fmt(r) for r in rows])


def build_report(run: Path, wall_ms: float | None) -> tuple[str, dict]:
    s0, s1 = load_summary(run, "p0"), load_summary(run, "p1")
    primary = s0 or s1
    lines: list[str] = []
    if primary is None:
        return (f"[report] {run} 下没有可用的 summary.json，无法汇总（运行可能在写出结果前就失败了）。\n",
                {})

    d0, d1 = parse_dfss(run / "p0.log"), parse_dfss(run / "p1.log")
    dfss = merge_dfss(d0, d1)
    cfg = primary.get("config", {})
    st = primary.get("stats", {})
    mode = primary.get("mldsa_mode", "?")
    ph0 = (s0 or {}).get("phases", {})
    ph1 = (s1 or {}).get("phases", {})

    def agg(ph: dict, names: list[str], key: str) -> float:
        return float(sum(ph.get(n, {}).get(key, 0) for n in names))

    body: list[list[str]] = []
    for name, names, dk in ROWS:
        d = dfss.get(dk) if dk else None
        body.append([
            name,
            f"{agg(ph0, names, 'time_ms'):.3f}" if ph0 else "-",
            f"{agg(ph1, names, 'time_ms'):.3f}" if ph1 else "-",
            f"{int(agg(ph0, names, 'rounds'))}",
            f"{kib(agg(ph0, names, 'sent_bytes')):.3f}",
            f"{kib(agg(ph0, names, 'recv_bytes')):.3f}",
            f"{d['calls']}" if d else "",
            f"{d['core_ms_per_call']:.3f}" if d and d["calls"] else "",
            f"{kib(d['wire_bytes_per_call']):.3f}" if d and d["calls"] else "",
            f"{kib(d['wire_bytes']):.1f}" if d and d["calls"] else "",
        ])
    allp = list(ph0.keys()) or list(ph1.keys())
    tot_wire = dfss["offline"]["wire_bytes"] + dfss["online"]["wire_bytes"]
    body.append([
        "TOTAL",
        f"{agg(ph0, allp, 'time_ms'):.3f}" if ph0 else "-",
        f"{agg(ph1, allp, 'time_ms'):.3f}" if ph1 else "-",
        f"{int(agg(ph0, allp, 'rounds'))}",
        f"{kib(agg(ph0, allp, 'sent_bytes')):.3f}",
        f"{kib(agg(ph0, allp, 'recv_bytes')):.3f}",
        f"{dfss['offline']['calls'] + dfss['online']['calls']}",
        "", "", f"{kib(tot_wire):.1f}",
    ])

    headers = ["function", "P0_time_ms", "P1_time_ms", "rounds", "ctrl_sent_KiB",
               "ctrl_recv_KiB", "dfss_calls", "dfss_core_ms/call",
               "dfss_wire_KiB/call", "dfss_wire_KiB"]
    lines.append("")
    lines.append(f"阶段汇总（ML-DSA-{mode}；2-of-2 对称、无协调方、P_b 兼任 C_b；真实 DFSS 后端）")
    lines.append(table(headers, body, "lrrrrrrrrr"))
    lines.append("")
    lines.append("列含义：ctrl_* 只统计 P0↔P1 协议信道（加性份额、承诺打开、一致性检查等）；")
    lines.append("        dfss_* 来自 DFSS 适配器自身的 DFSS_CORE_* 记录，dfss_wire_KiB = 两侧 sent 之和，")
    lines.append("        即链路上真实传输的字节数；两类流量走不同连接，不能相加成一个“信道”。")
    lines.append("        open_check 一行含 DKeyGen 阶段对 t 的那次一致性检查。")

    ctrl = agg(ph0, allp, "sent_bytes") + agg(ph0, allp, "recv_bytes")
    comm_rows = [
        ["协议信道 P0↔P1（单侧收+发）", f"{kib(ctrl):.3f}", f"{ctrl / 1048576.0:.4f}"],
        [f"DFSS 离线（{dfss['offline']['calls']} 个池项）",
         f"{kib(dfss['offline']['wire_bytes']):.1f}",
         f"{dfss['offline']['wire_bytes'] / 1048576.0:.2f}"],
        [f"DFSS 在线（{dfss['online']['calls']} 次批量比较）",
         f"{kib(dfss['online']['wire_bytes']):.1f}",
         f"{dfss['online']['wire_bytes'] / 1048576.0:.4f}"],
        ["合计", f"{kib(ctrl + tot_wire):.1f}", f"{(ctrl + tot_wire) / 1048576.0:.2f}"],
    ]
    lines.append("")
    lines.append("通信量总账")
    lines.append(table(["来源", "KiB", "MiB"], comm_rows, "lrr"))

    msg = run / "message.txt"
    msg_desc = "(缺失)"
    if msg.is_file():
        raw = msg.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        same = all((run / p / "message.txt").is_file() and
                   (run / p / "message.txt").read_bytes() == raw for p in ("p0", "p1"))
        msg_desc = (f"{len(raw)} 字节 sha256={digest[:16]}… "
                    f"两方实际签名的副本{'一致' if same else '不一致(!)'}")

    ov = [
        ["参数集", f"ML-DSA-{mode}"],
        ["批大小 K / 离线池 L / 池策略",
         f"{cfg.get('batch_size')} / {cfg.get('pool_size')} / {cfg.get('pool_mode')}"],
        ["打开一致性检查", str(cfg.get("open_check"))],
        ["待签消息", msg_desc],
        ["会话 session_id", str(primary.get("session_id"))],
        ["签名尝试次数 / 被接受的那次",
         f"{st.get('attempts')} / #{st.get('accept_attempt')}"],
        ["DCF 判定 accept/reject",
         f"{st.get('dcf_accepts')}/{st.get('dcf_rejects')}"],
        ["打开后被 Algorithm 7 拒绝",
         f"{st.get('alg7_rejects_after_open')} "
         f"(z={st.get('alg7_z_fail')} r0={st.get('alg7_r0_fail')} "
         f"ct0={st.get('alg7_ct0_fail')} hint={st.get('alg7_hint_fail')})"],
        ["离线池 生成/续池", f"{st.get('pool_items_generated')} / {st.get('pool_refills')}"],
        ["P0 验证结果 / 终止原因",
         f"{primary.get('verify_result')} / {primary.get('terminal_reason')}"],
        ["P1 验证结果 / 终止原因",
         f"{(s1 or {}).get('verify_result', '-')} / {(s1 or {}).get('terminal_reason', '-')}"],
        ["两方签名摘要一致",
         "是" if (s0 and s1 and s0.get("signature_sha3") == s1.get("signature_sha3")
                  and s0.get("signature_sha3")) else "否/未知"],
        ["签名 sha3-256", str(primary.get("signature_sha3", ""))[:32] + "…"],
    ]
    if wall_ms:
        ov.insert(0, ["本次运行墙钟耗时", f"{wall_ms / 1000.0:.2f} s"])
    lines.insert(0, table(["项目", "值"], ov, "ll"))
    lines.insert(0, "运行概览")
    lines.insert(0, "")

    report = "\n".join(lines) + "\n"
    data = {
        "run_dir": str(run),
        "mldsa_mode": mode,
        "wall_ms": wall_ms,
        "config": cfg,
        "stats": st,
        "dfss": dfss,
        "ctrl_bytes_p0": {"sent": agg(ph0, allp, "sent_bytes"),
                          "recv": agg(ph0, allp, "recv_bytes")},
        "phases_p0": ph0,
        "phases_p1": ph1,
        "verify_p0": primary.get("verify_result"),
        "terminal_p0": primary.get("terminal_reason"),
    }
    return report, data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    ap.add_argument("--wall-ms", type=float, default=None)
    ap.add_argument("--no-write", action="store_true", help="只打印，不写 report.txt/json")
    args = ap.parse_args()

    run = Path(args.run_dir).expanduser().resolve()
    if not run.is_dir():
        print(f"[report] 找不到运行目录 {run}", file=sys.stderr)
        return 2
    report, data = build_report(run, args.wall_ms)
    sys.stdout.write(report)
    if not args.no_write and data:
        (run / "report.txt").write_text(report, encoding="utf-8")
        (run / "report.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[report] 已写入 {run / 'report.txt'} 与 {run / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

NEW_FILES['scripts/run_local_simulation.sh'] = r'''#!/usr/bin/env bash
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
'''

NEW_FILES['scripts/run_physical_node.sh'] = r'''#!/usr/bin/env bash
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
'''

EDITS.append(('src/sign/src/main.c', r''' *   node <config.conf> --message "..."          指定待签消息（默认见 DEFAULT_MESSAGE）''', r''' *   node <config.conf> --message "..."          直接给出待签消息
 *   node <config.conf> --message-file <path>   从文件读取待签消息（scripts/gen_message.py 生成）'''))

EDITS.append(('src/sign/src/main.c', r'''            "  %s <config.conf> [--message <text>] [--out-dir <dir>]\n"''', r'''            "  %s <config.conf> [--message <text> | --message-file <path>] [--out-dir <dir>]\n"'''))

EDITS.append(('src/sign/src/main.c', r'''    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) message = argv[++i];
        else if (strcmp(argv[i], "--out-dir") == 0 && i + 1 < argc) out_dir = argv[++i];
        else { usage(argv[0]); return 2; }
    }''', r'''    static char msg_buf[MAX_MESSAGE_BYTES];
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) message = argv[++i];
        else if (strcmp(argv[i], "--message-file") == 0 && i + 1 < argc) {
            /* 推荐路径：消息由 scripts/gen_message.py 事先落盘，节点只读那一份字节，
             * 日志里因此留下的是“真正被签名的内容”，两方也能核对是同一个文件。 */
            const char *path = argv[++i];
            long n = read_file(path, (unsigned char *)msg_buf, sizeof(msg_buf) - 1);
            if (n < 0) {
                fprintf(stderr, "[node] 无法读取消息文件 %s（不存在，或超过 %d 字节）\n",
                        path, (int)sizeof(msg_buf) - 1);
                return 1;
            }
            msg_buf[n] = '\0';
            if ((long)strlen(msg_buf) != n) {
                fprintf(stderr, "[node] 消息文件 %s 含 NUL 字节，当前协议只签名文本消息\n", path);
                return 1;
            }
            if (n == 0) { fprintf(stderr, "[node] 消息文件 %s 为空\n", path); return 1; }
            message = msg_buf;
        }
        else if (strcmp(argv[i], "--out-dir") == 0 && i + 1 < argc) out_dir = argv[++i];
        else { usage(argv[0]); return 2; }
    }'''))

EDITS.append(('src/sign/src/party.c', r'''int party_run(Party *P) {
    plog(P, "启动：2-of-2 门限 %s，无协调方；本方同时是签名方 P%d 与 DFSS 比较方 C%d",
         MLDSA_LEVEL_NAME, P->b, P->b);''', r'''/* 阶段分隔线：让日志按“第几步在做什么”分块，便于定位。 */
static void pstage(const Party *P, int idx, const char *name) {
    printf("\n[P%d] ───────── 阶段 %d/4 · %s ─────────\n", P->b, idx, name);
    fflush(stdout);
}

int party_run(Party *P) {
    printf("\n[P%d] ══════════ 2-of-2 门限 %s · 本方 = 签名方 P%d = DFSS 比较方 C%d ══════════\n",
           P->b, MLDSA_LEVEL_NAME, P->b, P->b);
    plog(P, "拓扑：无协调方，两方运行同一份顺序代码，每一步同时交换");
    plog(P, "待签消息：%zu 字节，摘要见握手日志（两方不一致会在握手阶段中止）", strlen(P->message));'''))

EDITS.append(('src/sign/src/party.c', r'''    phase_begin(P, PH_HANDSHAKE);
    int rc = party_handshake(P);''', r'''    pstage(P, 1, "握手（校验参数与待签消息一致）");
    phase_begin(P, PH_HANDSHAKE);
    int rc = party_handshake(P);'''))

EDITS.append(('src/sign/src/party.c', r'''    if (dkg_run(P) != 0) {''', r'''    pstage(P, 2, "DKeyGen（分布式密钥生成）");
    if (dkg_run(P) != 0) {'''))

EDITS.append(('src/sign/src/party.c', r'''    if (dcf_pool_generate(P, 0, P->cfg.pool_size) != 0) {''', r'''    pstage(P, 3, "DCFPrep（离线：一次性 DFSS 密钥与掩码，通常是耗时大头）");
    if (dcf_pool_generate(P, 0, P->cfg.pool_size) != 0) {'''))

EDITS.append(('src/sign/src/party.c', r'''        return -1;
    }
    return sign_run(P);
}''', r'''        return -1;
    }
    pstage(P, 4, "DSign + Verify（候选、DCF 拒绝采样、打开、标准验签）");
    return sign_run(P);
}'''))

SPANS.append(('src/sign/src/party.c', r'''void party_print_summary(Party *P) {''', r'''static int write_file(const char *dir, const char *name''', r'''void party_print_summary(Party *P) {
    /* 表格用固定列宽渲染；标签一律放在竖线左侧的纯 ASCII 列里，避免中英混排错位。 */
    static const char *RULE =
        "──────────────────────┼────────────┼────────┼────────────┼────────────┼──────";
    printf("\n[P%d] ══════════ 阶段汇总（本方视角，仅 P0↔P1 协议信道）══════════\n", P->b);
    printf("  phase               │    time_ms │ rounds │   sent_KiB │   recv_KiB │ calls\n");
    printf("%s\n", RULE);
    uint64_t tot_r = 0, tot_s = 0, tot_v = 0;
    double tot_ms = 0;
    for (int i = 0; i < PH_COUNT; i++) {
        PhaseMetric *m = &P->phase[i];
        printf("  %-19s │ %10.3f │ %6llu │ %10.3f │ %10.3f │ %5d\n",
               phase_name((PhaseId)i), m->ms, (unsigned long long)m->rounds,
               (double)m->sent_bytes / 1024.0, (double)m->recv_bytes / 1024.0, m->entries);
        tot_ms += m->ms; tot_r += m->rounds; tot_s += m->sent_bytes; tot_v += m->recv_bytes;
    }
    printf("%s\n", RULE);
    printf("  %-19s │ %10.3f │ %6llu │ %10.3f │ %10.3f │\n",
           "TOTAL", tot_ms, (unsigned long long)tot_r,
           (double)tot_s / 1024.0, (double)tot_v / 1024.0);
    printf("  注：以上不含 DFSS 内部 2PC 流量——离线每个池项在 DFSS 自己的连接上要走数 MiB，\n"
           "      节点看不到，只能由适配器的 DFSS_CORE_* 行记录。两侧合并后的完整口径见\n"
           "      scripts/report.py 生成的 report.txt / report.json。\n");

    SignStats *s = &P->stats;
    printf("\n[P%d] ══════════ 本次运行 ══════════\n", P->b);
    printf("  · 配置：%s，K=%d，L=%d（%s），open_check=%s\n",
           MLDSA_LEVEL_NAME, P->cfg.batch_size, P->cfg.pool_size,
           pool_mode_name(P->cfg.pool_mode), open_check_mode_name(P->cfg.open_check));
    printf("  · 离线池：生成 %d 项 / %d 段 / 续池 %d 次；本方计时 keygen=%.3f ms，eval=%.3f ms\n",
           s->pool_items_generated, s->pool_segments, s->pool_refills,
           s->dfss_keygen_ms, s->dfss_eval_ms);
    printf("  · 拒绝采样：尝试 %d 次 / 批 %d 个；DCF accept=%d reject=%d；已打开候选 %d\n",
           s->attempts, s->batches, s->dcf_accepts, s->dcf_rejects, s->opened_candidates);
    printf("  · 打开后被 Algorithm 7 拒绝：%d 次（z=%d r0=%d ct0=%d hint=%d）\n",
           s->alg7_rejects_after_open, s->alg7_z_fail, s->alg7_r0_fail,
           s->alg7_ct0_fail, s->alg7_hint_fail);
    printf("  · 打开一致性检查：mode=%s，checks=%d，items=%d\n",
           open_check_mode_name(P->cfg.open_check), s->open_checks, s->open_check_items);
    if (P->terminal == TERM_SUCCESS) {
        printf("  · 审计：||c*s2||_inf=%d（%s）——这是协议边界，不是实现错误\n",
               s->cs2_audit_norm,
               s->cs2_audit_small ? "短向量，任一方可由 (w,z,t) 反解 s2" : "异常");
    }
    char sh[65];
    hex(sh, P->sig_hash, 32);
    printf("[P%d] verify_result=%s terminal_reason=%s accept_attempt=%d attempts=%d hint_ones=%d signature_sha3=%s\n",
           P->b, P->verify_ok ? "ACCEPT" : "REJECT", terminal_name(P->terminal),
           s->accept_attempt, s->attempts, s->hint_ones, P->terminal == TERM_SUCCESS ? sh : "-");
    printf("[P%d] ══════════════════════════════════════════════\n", P->b);
    fflush(stdout);
}

''', r'''阶段汇总（本方视角，仅 P0↔P1 协议信道）'''))

SPANS.append(('README.md', r'''## 3. 运行
''', r'''## 4. 配置项
''', r'''## 3. 运行

一次运行分三步，`scripts/run_local_simulation.sh` 会按步骤打印：

```
[1/3] 生成待签消息   scripts/gen_message.py  → logs/<本次运行>/message.txt
[2/3] 执行两方协议   src/sign/node ×2        → 只读第 1 步那份消息文件
[3/3] 汇总与复验     scripts/report.py       → logs/<本次运行>/report.txt
```

### 3.1 待签消息是先落盘、再签名的

消息不再只是命令行里的一个字符串：第 1 步先由 `scripts/gen_message.py` 把它写成
`logs/<本次运行>/message.txt`（另附 `message.meta.json`，含长度与 SHA-256/SHA3-256），
第 2 步两个节点通过 `--message-file` 读同一份字节。这样日志里留下的就是**真正被签名
的那份内容**，而且两方读到的是不是同一份，握手阶段就会校验出来（消息摘要参与握手比对）。

```bash
# 默认：自动生成带运行号/UTC 时间/随机 nonce 的消息，每次运行都不同
bash scripts/run_local_simulation.sh --mldsa-mode 44

# 指定文本
bash scripts/run_local_simulation.sh --mldsa-mode 44 --message "hello"

# 其它来源
bash scripts/run_local_simulation.sh --message-mode random --message-bytes 256
bash scripts/run_local_simulation.sh --message-mode file --message-source ./contract.txt
```

消息上限 1023 字节且不能含 NUL 字节（节点按 C 字符串处理）。也可以单独调用生成脚本：

```bash
python3 scripts/gen_message.py --out-dir /tmp/msg --mode timestamped
./src/sign/node <config> --message-file /tmp/msg/message.txt
```

### 3.2 单机模拟（参数集运行时选择）

```bash
bash scripts/run_local_simulation.sh --mldsa-mode 44 --message "hello"
bash scripts/run_local_simulation.sh --mldsa-mode 65 --message "hello"
bash scripts/run_local_simulation.sh --mldsa-mode 87 --batch-size 1 --pool-size 8 \
  --pool-mode refill --open-check strict --timeout 900 --message "hello"
```

输出目录 `logs/local-m<mode>-<时间戳>/`：

| 文件 | 内容 |
| --- | --- |
| `message.txt` / `message.meta.json` | 本次真正被签名的消息及其摘要 |
| `p0.log` / `p1.log` | 两方完整日志（含 DFSS 适配器的 `DFSS_CORE_*` 行） |
| `p0/`、`p1/` | 各方的 `public_key.bin`、`signature.bin`、`message.txt`、`summary.json` |
| `report.txt` / `report.json` | 第 3 步生成的汇总表（也会打印到控制台） |

### 3.3 汇总表怎么读：两类通信量是分开计量的

```bash
python3 scripts/report.py logs/local-m44-<时间戳>          # 事后随时重新生成
```

表里 `ctrl_*` 与 `dfss_*` 是**两条不同的链路**，不要相加成一个“信道”：

- `ctrl_sent_KiB / ctrl_recv_KiB`：P0↔P1 协议信道，来自各方 `summary.json`。
  份额交换、承诺打开、一致性检查走这里，量级是几十 KiB。
- `dfss_calls / dfss_core_ms per call / dfss_wire_KiB per call`：DFSS/EzPC 适配器
  自己那条连接，来自日志里的 `DFSS_CORE_*` 行。`dfss_wire_KiB = 两侧 sent 之和`，
  即链路上真实传输的字节数，与旧版四节点工程 `dfss_wire_kib/call` 口径一致。

**离线阶段的 `dcf_prep sent_bytes=48` 不是通信量下降**：那 48 字节只是两方在协议信道上
同步“池区间 / 池是否就绪”。真正的离线开销全部在 DFSS 栈内部——ML-DSA-44、1024 lane
时每个池项约 `13167.5 KiB ≈ 12.9 MiB`（C0 发 5,430,784 B + C1 发 8,052,736 B），
在线每次批量比较约 `87.98 KiB`。这两个数与旧版逐字节相同，只是旧版把它们并进了同一张表，
而节点自身的 `summary.json` 里从来就没有它们。所以要看总账，请以 `report.txt` 为准。

### 3.4 两台物理机

在两台机器上都（各自执行一次 `make`）：

```bash
# 1) 填 IP（两台内容必须完全一致）
vi config/sign/common.physical.conf     # 替换 REPLACE_WITH_P0_IP / REPLACE_WITH_P1_IP

# 2) 分发私有身份：p0.conf+p0.seed 只放 P0 机器，p1.conf+p1.seed 只放 P1 机器

# 3) 准备同一份消息：在任意一台生成后拷到另一台
python3 scripts/gen_message.py --out-dir /tmp/msg --mode timestamped
scp /tmp/msg/message.txt 对方主机:/tmp/msg/message.txt

# 4) 大致同时启动（P1 会在超时内反复重试连接 P0），两边 --mldsa-mode 必须相同
bash scripts/run_physical_node.sh --node p0 --mldsa-mode 65 --message-file /tmp/msg/message.txt
bash scripts/run_physical_node.sh --node p1 --mldsa-mode 65 --message-file /tmp/msg/message.txt
```

物理部署不做本机随机生成：两台必须签完全相同的字节，否则握手就会 `HANDSHAKE_FAILED`。
每台机器结束后只能看到自己那侧的 DFSS 记录；要合并两侧，把对方的日志目录拷过来再跑一次
`scripts/report.py`。

防火墙需放行：P0 的协议端口（默认 9001），以及两台机器各自的 DFSS 端口
`base`、`base+3`、`base+50`、`base+100`（默认 base 为 10101 / 10301）。

### 3.5 离线验签（按公钥长度自动识别参数集）

```bash
./src/sign/node verify logs/.../p0/public_key.bin logs/.../p0/signature.bin logs/.../message.txt
```

---

''', r'''### 3.3 汇总表怎么读'''))

EXECUTABLE = set(NEW_FILES)


def say(msg: str) -> None:
    print(f"[apply] {msg}")


class Plan:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.writes: dict[Path, str] = {}
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

    for rel, text in NEW_FILES.items():
        plan.set(rel, text)

    for rel, old, new in EDITS:
        cur = plan.current(rel)
        if cur is None:
            plan.errors.append(f"缺少文件 {rel}")
            continue
        if new in cur:
            continue                      # 已应用
        if cur.count(old) != 1:
            plan.errors.append(
                f"{rel}: 待替换的原文出现 {cur.count(old)} 次（期望 1 次），"
                f"文件可能已被手工修改：{old.strip().splitlines()[0][:70]!r}")
            continue
        plan.set(rel, cur.replace(old, new, 1))

    for rel, start, end, body, marker in SPANS:
        cur = plan.current(rel)
        if cur is None:
            plan.errors.append(f"缺少文件 {rel}")
            continue
        if marker in cur:
            continue                      # 已应用
        if start not in cur or end not in cur:
            plan.errors.append(f"{rel}: 找不到区段标记，文件可能已被手工修改")
            continue
        i, j = cur.index(start), cur.index(end)
        if i >= j:
            plan.errors.append(f"{rel}: 区段标记顺序异常")
            continue
        plan.set(rel, cur[:i] + body + cur[j:])

    # 目录结构说明里补一行（可选，失败不影响其它改动）
    readme = plan.current("README.md")
    if readme and "gen_message.py 生成待签消息" not in readme:
        old_line = "scripts/            构建与运行脚本\n"
        if old_line in readme:
            plan.set("README.md", readme.replace(
                old_line,
                "scripts/            构建与运行脚本（gen_message.py 生成待签消息，report.py 汇总表）\n", 1))

    return plan


def backup(root: Path, paths: list[Path], stamp: str) -> Path:
    bdir = root / ".patch_backup" / stamp
    for p in paths:
        if not p.is_file():
            continue
        dest = bdir / p.relative_to(root)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
    if bdir.exists():
        (bdir / "RESTORE.txt").write_text(
            "本目录是 apply_console_and_message_upgrade.py 应用前的原始文件备份。\n"
            f"回滚：python3 apply_console_and_message_upgrade.py --restore .patch_backup/{stamp}\n",
            encoding="utf-8")
    return bdir


def run(cmd: list[str], cwd: Path) -> int:
    say("$ " + " ".join(cmd))
    return subprocess.call(cmd, cwd=str(cwd))


def do_restore(root: Path, name: str) -> int:
    bdir = (root / name) if not Path(name).is_absolute() else Path(name)
    if not bdir.is_dir():
        print(f"[apply][error] 找不到备份目录 {bdir}", file=sys.stderr)
        return 2
    n = 0
    for p in bdir.rglob("*"):
        if not p.is_file() or p.name == "RESTORE.txt":
            continue
        rel = p.relative_to(bdir)
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, target)
        say("恢复 " + str(rel))
        n += 1
    say(f"已恢复 {n} 个文件；新增的 scripts/gen_message.py、scripts/report.py 如不再需要请手动删除。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="项目根目录（默认当前目录）")
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--build", action="store_true", help="应用后执行 make 并跑一次自检")
    ap.add_argument("--restore", metavar="BACKUP_DIR")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not (root / "src" / "sign" / "src" / "party.c").is_file() or not (root / "scripts").is_dir():
        print(f"[apply][error] {root} 看起来不是 threshold_mldsa_2party 项目根目录", file=sys.stderr)
        return 2

    if args.restore:
        return do_restore(root, args.restore)

    plan = plan_changes(root)
    if plan.errors:
        print("[apply][error] 以下改动无法应用，未改动任何文件：", file=sys.stderr)
        for e in plan.errors:
            print("  - " + e, file=sys.stderr)
        print("  提示：本脚本针对“取消协调方 + P_b 兼任 C_b”的那一版工程；"
              "若已手工改过 party.c/main.c，请先还原再运行。", file=sys.stderr)
        return 1

    say(f"项目根目录：{root}")
    if not plan.writes:
        say("所有改动都已应用过，无需重复执行。")
    for p in sorted(plan.writes):
        say(("新建 " if not p.exists() else "修改 ") + str(p.relative_to(root)))
    for n in plan.notes:
        say(n)

    if args.check_only or args.dry_run:
        say("未写入任何文件（--check-only / --dry-run）。")
        return 0

    if plan.writes:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        bdir = backup(root, list(plan.writes), stamp)
        if bdir.exists():
            say(f"原文件已备份到 {bdir.relative_to(root)}")
        for p, text in plan.writes.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            rel = str(p.relative_to(root))
            if rel in EXECUTABLE:
                p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    if args.build:
        if run(["make"], root) != 0:
            return 1
        if run([str(root / "src" / "sign" / "node"), "selftest", "--mldsa-mode", "44"], root) != 0:
            return 1

    print()
    say("完成。接下来：")
    print("    make                                     # 改了 C 代码，必须重新编译一次")
    print("    bash scripts/run_local_simulation.sh --mldsa-mode 44 --message \"hello\"")
    print("    bash scripts/run_local_simulation.sh --mldsa-mode 44        # 不给 --message 则自动生成")
    print("    python3 scripts/report.py logs/local-m44-<时间戳>            # 事后重出汇总表")
    print()
    print("  运行结束后 logs/<本次运行>/ 下会有：message.txt、message.meta.json、")
    print("  p0.log/p1.log、p0//p1/（公钥·签名·summary.json）、report.txt、report.json。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
