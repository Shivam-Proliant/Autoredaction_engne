# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

project = Path(SPECPATH)
webview_datas, webview_binaries, webview_hiddenimports = collect_all("webview")
pythonnet_datas, pythonnet_binaries, pythonnet_hiddenimports = collect_all("pythonnet")
clr_loader_datas, clr_loader_binaries, clr_loader_hiddenimports = collect_all("clr_loader")
# Keep the managed runtime assembly as a binary only. Duplicating it as a data
# file can overwrite its correct runtime copy in a one-file extraction folder.
pythonnet_datas = [entry for entry in pythonnet_datas if not entry[0].lower().endswith(".dll")]

analysis = Analysis(
    [str(project / "desktop.py")],
    pathex=[str(project)],
    binaries=webview_binaries + pythonnet_binaries + clr_loader_binaries,
    datas=webview_datas + pythonnet_datas + clr_loader_datas + [(str(project / "static"), "static"), (str(project / "local_qwen_worker.py"), ".")],
    hiddenimports=webview_hiddenimports + pythonnet_hiddenimports + clr_loader_hiddenimports + ["app", "engine", "local_qwen"],
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
    [],
    analysis.datas,
    [],
    exclude_binaries=True,
    name="PromptVeil-RedactionWorkbench-1.2.6",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
app = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="PromptVeil-RedactionWorkbench-1.2.6",
)
