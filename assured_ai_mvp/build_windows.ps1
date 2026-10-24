$ErrorActionPreference = "Stop"
$Project = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $Project ".desktop-build-venv"

if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) {
    python -m venv $Venv
}

$Python = Join-Path $Venv "Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $Project "desktop_requirements.txt")
Push-Location $Project
try {
    & $Python -m PyInstaller --noconfirm --clean "assured_ai_workbench.spec"
} finally {
    Pop-Location
}

Write-Host "Desktop app created at: $(Join-Path $Project 'dist\PromptVeil-RedactionWorkbench-1.2.6\PromptVeil-RedactionWorkbench-1.2.6.exe')"
