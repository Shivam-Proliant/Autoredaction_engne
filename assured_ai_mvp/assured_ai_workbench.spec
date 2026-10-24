# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

project = Path(SPECPATH)
webview_datas, webview_binaries, webview_hiddenimports = collect_all("webview")

analysis = Analysis(
    [str(project / "desktop.py")],
    pathex=[str(project)],
    binaries=webview_binaries,
    datas=webview_datas + [(str(project / "static"), "static")],
    hiddenimports=webview_hiddenimports + ["app", "engine"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="AssuredAI-RedactionWorkbench-1.1.0",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)
