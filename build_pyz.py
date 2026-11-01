# -*- coding: utf-8 -*-
"""build_pyz.py —— 用标准库 zipapp 打全平台单文件包。

产物：dist/cf-hunt.pyz
任何装了 Python 3.8+ 的系统都能跑：
    python cf-hunt.pyz
    python3 cf-hunt.pyz          # Linux / macOS
"""
import os
import shutil
import subprocess
import sys
import zipapp

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
BUILD = os.path.join(HERE, "build_pyz")
NAME = "cf-hunt"

# 要打进去的文件（只收运行时需要的）
INCLUDE = ["app.py", "hosts_tool.py", "cf_hunt.py", "cf_final.py", "cf_ab.py"]


def main():
    os.makedirs(DIST, exist_ok=True)
    if os.path.isdir(BUILD):
        shutil.rmtree(BUILD)
    os.makedirs(BUILD)

    for f in INCLUDE:
        src = os.path.join(HERE, f)
        if not os.path.exists(src):
            print(f"[!] 缺少 {f}，跳过")
            continue
        shutil.copy2(src, os.path.join(BUILD, f))

    # zipapp 的入口必须是 module:function
    entry = "app:main"
    out = os.path.join(DIST, f"{NAME}.pyz")
    zipapp.create_archive(
        BUILD,
        target=out,
        interpreter="/usr/bin/env python3",
        main=entry,
        compressed=True,
    )
    size = os.path.getsize(out)
    print(f"[OK] {out}  ({size / 1024:.1f} KB)")

    # 本机试跑
    print("[..] 自检：运行 status")
    r = subprocess.run([sys.executable, out, "status"],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    if r.returncode == 0:
        print("[OK] 自检通过")
    else:
        print("[X] 自检失败：")
        print(r.stdout or "")
        print(r.stderr or "")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
