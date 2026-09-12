#!/usr/bin/env python3
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
