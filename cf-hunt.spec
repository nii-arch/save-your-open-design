# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

构建：
    pyinstaller cf-hunt.spec

产物：dist/cf-hunt-windows.exe（单文件，目标机无需 Python）
"""
import sys

block_cipher = None

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=["hosts_tool", "cf_hunt"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # 扫描器只用标准库，把用不到的大块头排掉，减小体积
        "tkinter", "unittest", "pydoc", "doctest", "test",
        "email", "html", "http", "xml", "xmlrpc",
        "multiprocessing", "asyncio", "sqlite3", "pickle",
        "lib2to3", "distutils", "setuptools", "pip",
        "numpy", "pandas", "PIL", "matplotlib",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="cf-hunt-windows",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,              # 保留控制台窗口，这是菜单程序
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # 让 Windows 知道这是需要提权的程序：清单里声明 asInvoker，
    # 实际提权由程序自己弹 UAC（双击也能跑，只是没权限时会提示手动）
    uac_admin=False,
)
