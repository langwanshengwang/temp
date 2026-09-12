#!/usr/bin/env python3
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
