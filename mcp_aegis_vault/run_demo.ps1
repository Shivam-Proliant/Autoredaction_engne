$ErrorActionPreference = "Stop"
$aegisRoot = $PSScriptRoot
$aegisRuntimePackages = Join-Path $aegisRoot ".runtime_packages"
if (-not (Test-Path -LiteralPath $aegisRuntimePackages)) {
    throw "Missing .runtime_packages. Run: py -3.14 -m pip install --target .runtime_packages -r requirements.txt"
}

$aegisPython = (py -3.14 -c "import sys; print(sys.executable)").Trim()
$env:PYTHONPATH = "$aegisRuntimePackages;$aegisRoot"
$aegisLogDir = Join-Path $aegisRoot "runtime-logs"
New-Item -ItemType Directory -Path $aegisLogDir -Force | Out-Null
$aegisProcesses = @()

try { $null = Invoke-RestMethod "http://127.0.0.1:8000/health" -TimeoutSec 1 }
catch {
    $backend = Start-Process -FilePath $aegisPython -WorkingDirectory $aegisRoot -WindowStyle Hidden -PassThru `
        -ArgumentList @("-m", "uvicorn", "backend:app", "--host", "127.0.0.1", "--port", "8000") `
        -RedirectStandardOutput (Join-Path $aegisLogDir "backend.log") `
        -RedirectStandardError (Join-Path $aegisLogDir "backend-error.log")
    $aegisProcesses += $backend.Id
}

try { $null = Invoke-WebRequest "http://127.0.0.1:8502/_stcore/health" -TimeoutSec 1 }
catch {
    $ui = Start-Process -FilePath $aegisPython -WorkingDirectory $aegisRoot -WindowStyle Hidden -PassThru `
        -ArgumentList @("-m", "streamlit", "run", "app.py", "--server.address", "127.0.0.1", "--server.port", "8502", "--server.headless", "true", "--global.developmentMode", "false") `
        -RedirectStandardOutput (Join-Path $aegisLogDir "ui.log") `
        -RedirectStandardError (Join-Path $aegisLogDir "ui-error.log")
    $aegisProcesses += $ui.Id
}

$aegisReady = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    try {
        $health = Invoke-RestMethod "http://127.0.0.1:8000/health" -TimeoutSec 2
        $uiHealth = Invoke-WebRequest "http://127.0.0.1:8502/_stcore/health" -TimeoutSec 2
        if ($health.status -eq "ok" -and $uiHealth.StatusCode -eq 200) { $aegisReady = $true; break }
    } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $aegisReady) { throw "Aegis did not become ready. Check runtime-logs for details." }

if ($aegisProcesses.Count -gt 0) {
    @{ pids = $aegisProcesses; project = $aegisRoot } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $aegisRoot ".aegis-processes.json")
}

$aegisChromeCandidates = @(
    (Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Google\Chrome\Application\chrome.exe"),
    (Join-Path $env:LOCALAPPDATA "Google\Chrome\Application\chrome.exe")
)
$aegisChrome = $aegisChromeCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if ($aegisChrome) { Start-Process -FilePath $aegisChrome -ArgumentList @("--new-window", "http://127.0.0.1:8502") }
else { Start-Process "http://127.0.0.1:8502" }
Write-Host "Aegis is ready in your browser at http://127.0.0.1:8502"
Write-Host "MCP endpoint: http://127.0.0.1:8000/mcp"
