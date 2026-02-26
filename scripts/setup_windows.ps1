$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$PythonBin = if ($env:PY_BIN) { $env:PY_BIN } else { "python" }
$InstallDev = if ($env:INSTALL_DEV) { $env:INSTALL_DEV } else { "false" }

if (-not (Test-Path ".venv")) {
  & $PythonBin -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip
if ($InstallDev -eq "true") {
  & .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
} else {
  & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
  Copy-Item ".env.example" ".env"
  Write-Host "Created .env from .env.example"
}

Write-Host "Setup complete. Activate with: .\.venv\Scripts\Activate.ps1"
