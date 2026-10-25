$ErrorActionPreference = "Stop"
$aegisRoot = $PSScriptRoot
$aegisStatePath = Join-Path $aegisRoot ".aegis-processes.json"
if (-not (Test-Path -LiteralPath $aegisStatePath)) {
    Write-Host "No Aegis processes were launched by run_demo.ps1."
    exit 0
}

$aegisState = Get-Content -LiteralPath $aegisStatePath -Raw | ConvertFrom-Json
foreach ($aegisPid in $aegisState.pids) {
    $aegisProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $aegisPid" -ErrorAction SilentlyContinue
    if (-not $aegisProcess) { continue }
    $aegisCommandLine = [string]$aegisProcess.CommandLine
    $aegisPythonPath = (py -3.14 -c "import sys; print(sys.executable)").Trim()
    $aegisOwnsProcess = ([string]$aegisProcess.ExecutablePath -eq $aegisPythonPath) -and ($aegisCommandLine.Contains("uvicorn backend:app") -or $aegisCommandLine.Contains("-m streamlit run app.py"))
    if ($aegisOwnsProcess) {
        Stop-Process -Id $aegisPid -Force
        Write-Host "Stopped Aegis process $aegisPid."
    }
}
Remove-Item -LiteralPath $aegisStatePath -Force
