# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller build spec (Section 3 / Section 28 Phase 13).
#
# IMPORTANT: PyInstaller produces a platform-NATIVE executable - it does
# not cross-compile. Running `pyinstaller build.spec` on Windows produces
# USB-Security-System.exe; running it on Linux/macOS produces a
# Linux/macOS binary instead. This project targets Windows, so the real
# .exe must be built ON a Windows machine. This spec has been validated
# for correct PyInstaller syntax and dependency collection in this
# (Linux) development sandbox, but the resulting Windows .exe has not
# been produced or tested here - build and test it on Windows before a
# project defense.
#
# Build with:
#     pyinstaller build.spec
#
# Output: dist/USB-Security-System/USB-Security-System.exe (Windows)

import sys
from pathlib import Path

block_cipher = None

# --- Windows-only packages: only bundle these when actually building
# on Windows, since they are not installed/importable elsewhere. ---
windows_hidden_imports = []
if sys.platform == "win32":
    windows_hidden_imports = ["win32api", "win32con", "win32com", "win32com.client", "pythoncom", "wmi"]

hidden_imports = [
    "sqlalchemy.sql.default_comparator",
    "argon2",
    "_argon2_cffi_bindings",
    "reportlab.graphics.barcode",
    "PySide6.QtSvg",
] + windows_hidden_imports

datas = [
    # .env.example ships so a fresh install has a template to copy from.
    (".env.example", "."),
]

a = Analysis(
    ["main.py"],
    pathex=[str(Path(".").resolve())],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="USB-Security-System",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # GUI app - no console window on Windows
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="USB-Security-System",
)
