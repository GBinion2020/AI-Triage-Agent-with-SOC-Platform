$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$HostAddress = if ($env:SOC_UI_HOST) { $env:SOC_UI_HOST } else { "0.0.0.0" }
$Port = if ($env:SOC_UI_PORT) { $env:SOC_UI_PORT } else { "8088" }

& .\.venv\Scripts\uvicorn.exe soc_case_ui.app:app --host $HostAddress --port $Port
