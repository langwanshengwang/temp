#!/usr/bin/env python3
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
