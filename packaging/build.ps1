<#
  Build WAFMXDetector.exe with PyInstaller.
  Usage:   powershell -ExecutionPolicy Bypass -File packaging\build.ps1 [-OneFile]
  Output:  dist\WAFMXDetector\WAFMXDetector.exe   (or dist\WAFMXDetector.exe with -OneFile)
  Python 3.10-3.12 (64-bit) recommended.
#>
param([switch]$OneFile, [switch]$SkipTests)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Test-Path .venv)) { python -m venv .venv }
$py = ".\.venv\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -r requirements-dev.txt

if (-not $SkipTests) { & $py -m pytest -q; if ($LASTEXITCODE) { throw "tests failed" } }

& $py packaging\make_icon.py
$mode = if ($OneFile) { "--onefile" } else { "--onedir" }
& $py -m PyInstaller --noconfirm --clean $mode --windowed `
    --name WAFMXDetector `
    --icon packaging\app.ico `
    --paths src `
    --collect-submodules pystray `
    --collect-all comtypes `
    --collect-all uiautomation `
    --collect-data truststore `
    --hidden-import truststore `
    packaging\launcher.py
if ($LASTEXITCODE) { throw "PyInstaller failed" }

$target = if ($OneFile) { "dist\WAFMXDetector.exe" } else { "dist\WAFMXDetector\WAFMXDetector.exe" }
Get-FileHash $target -Algorithm SHA256 | Format-List
Write-Host "Built $target"
