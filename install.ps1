# Anty installer — Windows PowerShell
# Usage: irm https://anty.dev/install.ps1 | iex
#   or:  irm https://raw.githubusercontent.com/voulspiros/Anty/main/install.ps1 | iex
#
# Requires: PowerShell 5.1+ (ships with Windows 10/11)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── Configuration ────────────────────────────────────────────────────
$Repo       = 'voulspiros/Anty'
$BinaryName = 'anty.exe'
$Asset      = 'anty-windows-x86_64.exe'
$InstallDir = Join-Path $env:USERPROFILE '.anty\bin'

# ── Helpers ──────────────────────────────────────────────────────────
function Write-Info  { param([string]$Msg) Write-Host "  ▸ $Msg" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Msg) Write-Host "  ✔ $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "  ⚠ $Msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$Msg) Write-Host "  ✖ $Msg" -ForegroundColor Red; exit 1 }

# ── Banner ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "     █████╗  ███╗   ██╗ ████████╗ ██╗   ██╗" -ForegroundColor Yellow
Write-Host "    ██╔══██╗ ████╗  ██║ ╚══██╔══╝ ╚██╗ ██╔╝" -ForegroundColor Yellow
Write-Host "    ███████║ ██╔██╗ ██║    ██║     ╚████╔╝ " -ForegroundColor Yellow
Write-Host "    ██╔══██║ ██║╚██╗██║    ██║      ╚██╔╝  " -ForegroundColor Yellow
Write-Host "    ██║  ██║ ██║ ╚████║    ██║       ██║   " -ForegroundColor Yellow
Write-Host "    ╚═╝  ╚═╝ ╚═╝  ╚═══╝    ╚═╝       ╚═╝   " -ForegroundColor Yellow
Write-Host ""
Write-Host "    Developer-first security scanner" -ForegroundColor White
Write-Host ""

# ── Resolve latest release ───────────────────────────────────────────
Write-Info "Finding latest Anty release..."

$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $Release = Invoke-RestMethod -Uri $ApiUrl -Headers @{ 'User-Agent' = 'AntyInstaller' }
} catch {
    Write-Fail "Could not reach GitHub API. Check your network connection."
}

$Version = $Release.tag_name
if (-not $Version) {
    Write-Fail "Could not determine latest version."
}

Write-Info "Anty $Version for Windows x86_64"

# ── Download binary + checksums ──────────────────────────────────────
$BaseUrl     = "https://github.com/$Repo/releases/download/$Version"
$BinaryUrl   = "$BaseUrl/$Asset"
$ChecksumUrl = "$BaseUrl/SHA256SUMS.txt"

$TmpDir = Join-Path $env:TEMP "anty-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$BinaryPath   = Join-Path $TmpDir $Asset
$ChecksumPath = Join-Path $TmpDir 'SHA256SUMS.txt'

try {
    Write-Info "Downloading $Asset..."
    Invoke-WebRequest -Uri $BinaryUrl   -OutFile $BinaryPath   -UseBasicParsing
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing
} catch {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    Write-Fail "Download failed: $_"
}

# ── Verify SHA-256 checksum ──────────────────────────────────────────
Write-Info "Verifying SHA-256 checksum..."

$ChecksumLines = Get-Content $ChecksumPath
$ExpectedLine  = $ChecksumLines | Where-Object { $_ -match $Asset }

if (-not $ExpectedLine) {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    Write-Fail "No checksum entry found for $Asset in SHA256SUMS.txt"
}

$Expected = ($ExpectedLine -split '\s+')[0].ToLower()
$Actual   = (Get-FileHash -Path $BinaryPath -Algorithm SHA256).Hash.ToLower()

if ($Expected -ne $Actual) {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "  Expected: $Expected" -ForegroundColor DarkGray
    Write-Host "  Got:      $Actual"   -ForegroundColor DarkGray
    Write-Fail "Checksum mismatch! The download may be corrupted. Please try again."
}

Write-Ok "Checksum verified"

# ── Install ──────────────────────────────────────────────────────────
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$DestPath = Join-Path $InstallDir $BinaryName
Copy-Item -Path $BinaryPath -Destination $DestPath -Force
Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue

Write-Ok "Anty $Version installed to $DestPath"

# ── Add to PATH if missing ───────────────────────────────────────────
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($UserPath -notlike "*$InstallDir*") {
    Write-Info "Adding $InstallDir to your user PATH..."
    $NewPath = "$InstallDir;$UserPath"
    [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
    # Also update current session so the version check below works
    $env:Path = "$InstallDir;$env:Path"
    Write-Ok "PATH updated"
} else {
    Write-Ok "PATH already includes $InstallDir"
}

# ── Done ─────────────────────────────────────────────────────────────
Write-Host ""

try {
    $VersionOutput = & $DestPath --version 2>&1
    Write-Host "  $VersionOutput" -ForegroundColor Green
} catch {
    # Non-critical — binary is installed, just can't run version check
}

Write-Host ""
Write-Host "  Restart your terminal, then run:" -ForegroundColor White
Write-Host ""
Write-Host "    anty              " -NoNewline; Write-Host "# interactive wizard" -ForegroundColor DarkGray
Write-Host "    anty scan .       " -NoNewline; Write-Host "# scan current directory" -ForegroundColor DarkGray
Write-Host "    anty --version    " -NoNewline; Write-Host "# verify installation" -ForegroundColor DarkGray
Write-Host ""
