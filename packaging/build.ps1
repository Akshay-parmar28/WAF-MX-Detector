<#
  Build WAFMXDetector.exe with PyInstaller.
  Usage:   powershell -ExecutionPolicy Bypass -File packaging\build.ps1 [-OneFile]
  Output:  dist\WAFMXDetector\WAFMXDetector.exe (tray app) + WAFMXDetector-cli.exe (console, same folder)
           with -OneFile both land directly in dist\
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

# Console build for scripting from cmd/PowerShell: prints results and exit codes (0 = MX found, 2 = not found).
$cliDist = if ($OneFile) { "dist" } else { "dist\WAFMXDetector" }
& $py -m PyInstaller --noconfirm --onefile --console `
    --name WAFMXDetector-cli `
    --icon packaging\app.ico `
    --paths src `
    --distpath $cliDist `
    --workpath build\cli `
    --collect-data truststore `
    --hidden-import truststore `
    --exclude-module tkinter --exclude-module pystray --exclude-module PIL `
    packaging\launcher.py
if ($LASTEXITCODE) { throw "PyInstaller (cli) failed" }

$target = if ($OneFile) { "dist\WAFMXDetector.exe" } else { "dist\WAFMXDetector\WAFMXDetector.exe" }
Get-FileHash $target, "$cliDist\WAFMXDetector-cli.exe" -Algorithm SHA256 | Format-List
Write-Host "Built $target"
