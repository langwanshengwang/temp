#!/usr/bin/env python3
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
