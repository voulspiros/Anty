$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repo = "voulspiros/Anty"
$apiUrl = "https://api.github.com/repos/$repo/releases/latest"
$assetName = "anty-windows-x86_64.exe"
$checksumsName = "SHA256SUMS.txt"

Write-Host "Installing ANTY..."

$headers = @{ "User-Agent" = "anty-installer" }

try {
    $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 404) {
        throw "No GitHub Release found. Publish a release by pushing a version tag (e.g. git tag v0.1.0 && git push origin v0.1.0)."
    } elseif ($code -eq 403) {
        throw "GitHub API rate limit exceeded. Try again later."
    } else {
        throw "Failed to fetch release info (HTTP $code): $_"
    }
}

$tag = $release.tag_name
Write-Host "Found release: $tag"

$asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
$checksums = $release.assets | Where-Object { $_.name -eq $checksumsName } | Select-Object -First 1

if (-not $asset -or -not $checksums) {
    throw "Required release assets not found in release $tag."
}

$binaryUrl = $asset.browser_download_url
$checksumsUrl = $checksums.browser_download_url

if (-not $binaryUrl.StartsWith("https://")) { throw "Refusing non-HTTPS download URL." }
if (-not $checksumsUrl.StartsWith("https://")) { throw "Refusing non-HTTPS checksum URL." }

$tempDir = Join-Path $env:TEMP "anty-install"
if (Test-Path $tempDir) {
    Remove-Item -Path $tempDir -Recurse -Force
}
New-Item -Path $tempDir -ItemType Directory | Out-Null

$binaryPath = Join-Path $tempDir "anty.exe"
$checksumsPath = Join-Path $tempDir $checksumsName

Invoke-WebRequest -Uri $binaryUrl -OutFile $binaryPath -Headers $headers
Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -Headers $headers

Write-Host "Verifying checksum..."

$checksumLine = Get-Content -Path $checksumsPath | Where-Object { $_ -match [regex]::Escape($assetName) } | Select-Object -First 1
if (-not $checksumLine) {
    throw "Checksum entry not found for $assetName in release $tag."
}

$expectedHash = ($checksumLine -split "\s+")[0].ToLower()
if (-not $expectedHash -or $expectedHash.Length -ne 64) {
    throw "Checksum entry is malformed."
}

$actualHash = (Get-FileHash -Algorithm SHA256 -Path $binaryPath).Hash.ToLower()
if ($actualHash -ne $expectedHash) {
    throw "Checksum verification failed. Expected: $expectedHash Got: $actualHash"
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

Write-Host "Installed successfully ($tag)"
Write-Host "Open a NEW terminal and run: anty"
