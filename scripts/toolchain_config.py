#!/usr/bin/env python3
"""本机 EzPC 路径的唯一来源：config/toolchain.local.conf（不参与共享协议配置）。

解析顺序：
  1. 显式参数（--set / --ezpc-root / make EZPC_ROOT=...）
  2. 环境变量 EZPC_ROOT
  3. config/toolchain.local.conf 中的 ezpc_root=
  4. 旧版本误写在 config/sign/common.*.conf 里的 ezpc_root=（自动迁移）
  5. 自动探测：<项目>/third_party/EzPC、<项目>/../third_party/EzPC、<项目>/../EzPC、~/EzPC
第 1、2、4、5 步找到的有效路径会写回 config/toolchain.local.conf，之后无需再指定。
相对路径一律以**项目根目录**为基准。
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "toolchain.local.conf"
LEGACY_FILES = (
    ROOT / "config" / "sign" / "common.local.conf",
    ROOT / "config" / "sign" / "common.physical.conf",
)
CANDIDATES = (
    ROOT / "third_party" / "EzPC",
    ROOT.parent / "third_party" / "EzPC",
    ROOT.parent / "EzPC",
    Path.home() / "EzPC",
)
KEY_RE = re.compile(r"(?m)^\s*ezpc_root\s*=\s*(.+?)\s*$")


class ToolchainError(RuntimeError):
    pass


def _note(msg: str) -> None:
    print(f"[toolchain] {msg}", file=sys.stderr)


def _read_key(path: Path) -> str | None:
    if not path.is_file():
        return None
    matches = KEY_RE.findall(path.read_text(encoding="utf-8"))
    return matches[-1].strip() if matches else None


def _resolve_path(value: str) -> Path:
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = ROOT / p
    return p.resolve()


def _problem(root: Path) -> str | None:
    if not (root / "FSS" / "src" / "CMakeLists.txt").is_file():
        return f"{root}（缺少 FSS/src/CMakeLists.txt）"
    if not (root / "SCI" / "src").is_dir():
        return f"{root}（缺少 SCI/src）"
    return None


def _validate(value: str) -> Path:
    root = _resolve_path(value)
    problem = _problem(root)
    if problem:
        raise ToolchainError(f"EzPC 路径无效：{problem}")
    return root


def _stored(root: Path) -> str:
    """尽量存成相对项目根目录的路径，便于项目整体迁移到其他物理机。"""
    try:
        rel = os.path.relpath(root, ROOT)
    except ValueError:
        return str(root)
    if rel.startswith("../.."):
        return str(root)
    return rel


def save(value: str | Path) -> Path:
    root = _validate(str(value))
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    stored = _stored(root)
    old = _read_key(CONFIG)
    if old is None or _resolve_path(old) != root:
        CONFIG.write_text(
            "# 本机 EzPC 依赖路径（相对路径以项目根目录为基准）；不属于共享协议拓扑，勿提交到仓库。\n"
            f"ezpc_root={stored}\n", encoding="utf-8")
        _note(f"已写入 {CONFIG.relative_to(ROOT)}: ezpc_root={stored}")
    return root


def resolve(requested: str | None = None) -> Path:
    if requested:
        return save(requested)
    env = os.environ.get("EZPC_ROOT", "").strip()
    if env:
        return save(env)

    tried: list[str] = []
    saved = _read_key(CONFIG)
    if saved:
        root = _resolve_path(saved)
        problem = _problem(root)
        if problem is None:
            return root
        tried.append(f"config/toolchain.local.conf -> {problem}")

    for legacy in LEGACY_FILES:
        value = _read_key(legacy)
        if value:
            root = _resolve_path(value)
            problem = _problem(root)
            if problem is None:
                _note(f"从旧配置 {legacy.relative_to(ROOT)} 迁移 ezpc_root")
                return save(root)
            tried.append(f"{legacy.relative_to(ROOT)} -> {problem}")

    for cand in CANDIDATES:
        root = cand.resolve()
        problem = _problem(root)
        if problem is None:
            _note(f"自动探测到 EzPC: {root}")
            return save(root)
        tried.append(f"自动探测 -> {problem}")

    detail = "\n    ".join(tried) if tried else "(无)"
    raise ToolchainError(
        "找不到可用的 EzPC。已尝试：\n    " + detail + "\n"
        "解决办法（任选其一，只需做一次）：\n"
        "    make EZPC_ROOT=/absolute/path/to/EzPC\n"
        "    python3 scripts/toolchain_config.py --set ../third_party/EzPC   # 相对项目根目录\n"
        "    bash scripts/build_dependencies.sh                              # 自动克隆并配置")


def main() -> int:
    parser = argparse.ArgumentParser(description="读取或写入本机 EzPC 路径")
    parser.add_argument("--set", dest="set_value")
    parser.add_argument("--get", action="store_true")
    args = parser.parse_args()
    try:
        value = save(args.set_value) if args.set_value else resolve()
    except ToolchainError as exc:
        print(f"[toolchain] {exc}", file=sys.stderr)
        return 2
    if args.get or args.set_value:
        print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
