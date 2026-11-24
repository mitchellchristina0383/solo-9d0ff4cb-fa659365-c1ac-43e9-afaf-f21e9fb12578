#!/usr/bin/env python3
"""CI 批量补传客户端：把给定目录/文件列表中的 ELF 整批上传到符号服务。

用法:
  python scripts/ci_upload.py http://localhost:8000 path/to/elf1 path/to/dir ...
退出码: 0 成功（含重复文件幂等成功）；2 整批被退回；1 其它错误。
"""
from __future__ import annotations

import os
import sys

import httpx


def collect(paths: list[str]) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    for path in paths:
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                if os.path.isfile(full) and not name.startswith("."):
                    files.append((name, open(full, "rb").read()))
        else:
            with open(path, "rb") as fh:
                files.append((os.path.basename(path), fh.read()))
    return files


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 1
    base = sys.argv[1].rstrip("/")
    files = collect(sys.argv[2:])
    if not files:
        print("没有可上传的文件", file=sys.stderr)
        return 1
    try:
        resp = httpx.post(
            f"{base}/symbols/batch",
            files=[("files", (name, blob, "application/octet-stream")) for name, blob in files],
            timeout=60,
        )
    except httpx.HTTPError as exc:
        print(f"请求失败: {exc}", file=sys.stderr)
        return 1
    if resp.status_code == 200:
        data = resp.json()
        print(
            f"发布成功: 接收 {data['accepted']} 个, 新 Build ID {len(data['new_build_ids'])}, "
            f"重复 {data['redundant']} 个, 当前符号版本 {data['symbol_version']}"
        )
        for bid in data["new_build_ids"]:
            print(f"  new: {bid}")
        return 0
    print(f"整批退回 ({resp.status_code}):", file=sys.stderr)
    print(resp.text, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
