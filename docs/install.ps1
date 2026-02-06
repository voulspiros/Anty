$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repo = "voulspiros/Anty"
$apiUrl = "https://api.github.com/repos/$repo/releases/latest"
$assetName = "anty-windows-x86_64.exe"
$checksumsName = "SHA256SUMS.txt"

Write-Host "Installing ANTY..."

$headers = @{ "User-Agent" = "anty-installer" }
$release = Invoke-RestMethod -Uri $apiUrl -Headers $headers

$asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
$checksums = $release.assets | Where-Object { $_.name -eq $checksumsName } | Select-Object -First 1

if (-not $asset -or -not $checksums) {
    throw "Required release assets not found."
}

$tempDir = Join-Path $env:TEMP "anty-install"
if (Test-Path $tempDir) {
    Remove-Item -Path $tempDir -Recurse -Force
}
New-Item -Path $tempDir -ItemType Directory | Out-Null

$binaryPath = Join-Path $tempDir "anty.exe"
$checksumsPath = Join-Path $tempDir $checksumsName

Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $binaryPath -Headers $headers
Invoke-WebRequest -Uri $checksums.browser_download_url -OutFile $checksumsPath -Headers $headers

Write-Host "Verifying checksum..."

$checksumLine = Get-Content -Path $checksumsPath | Where-Object { $_ -match [regex]::Escape($assetName) } | Select-Object -First 1
if (-not $checksumLine) {
    throw "Checksum entry not found for $assetName."
}

$expectedHash = ($checksumLine -split "\s+")[0].ToLower()
if (-not $expectedHash) {
    throw "Checksum entry is malformed."
}

$actualHash = (Get-FileHash -Algorithm SHA256 -Path $binaryPath).Hash.ToLower()
if ($actualHash -ne $expectedHash) {
    throw "Checksum verification failed."
}

$installDir = Join-Path $env:USERPROFILE ".anty\bin"
if (-not (Test-Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory | Out-Null
}

$targetPath = Join-Path $installDir "anty.exe"
Move-Item -Path $binaryPath -Destination $targetPath -Force

$pathUser = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $pathUser) { $pathUser = "" }

$pathEntries = $pathUser -split ";" | Where-Object { $_ -ne "" }
if ($pathEntries -notcontains $installDir) {
    $newPath = if ($pathUser) { "$pathUser;$installDir" } else { $installDir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}

Write-Host "Installed successfully"
Write-Host "Open a NEW terminal and run: anty"
