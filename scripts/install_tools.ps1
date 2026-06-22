param(
    [string]$InstallDir = ".\tools\bin",
    [switch]$PreferGo,
    [switch]$SkipGo,
    [switch]$SkipRelease
)

$ErrorActionPreference = "Continue"
$root = Resolve-Path "."
$bin = Join-Path $root $InstallDir
$downloads = Join-Path $root ".\tools\downloads"
New-Item -ItemType Directory -Force -Path $bin, $downloads | Out-Null

$tools = @(
    @{
        Name = "katana"
        GoPackage = "github.com/projectdiscovery/katana/cmd/katana@latest"
        Repo = "projectdiscovery/katana"
        AssetRegex = "windows.*amd64.*\.zip$|windows.*x86_64.*\.zip$"
    },
    @{
        Name = "ffuf"
        GoPackage = "github.com/ffuf/ffuf/v2@latest"
        Repo = "ffuf/ffuf"
        AssetRegex = "windows.*amd64.*\.zip$|windows.*x86_64.*\.zip$"
    },
    @{
        Name = "gau"
        GoPackage = "github.com/lc/gau/v2/cmd/gau@latest"
        Repo = "lc/gau"
        AssetRegex = "windows.*amd64.*\.(zip|tar\.gz)$|windows.*x86_64.*\.(zip|tar\.gz)$"
    },
    @{
        Name = "paramspider"
        PythonPackage = "git+https://github.com/devanshbatham/ParamSpider.git"
        Repo = "devanshbatham/ParamSpider"
    }
)

function Get-LocalTool {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $localExe = Join-Path $bin "$Name.exe"
    if (Test-Path $localExe) { return $localExe }
    $localCmd = Join-Path $bin "$Name.cmd"
    if (Test-Path $localCmd) { return $localCmd }
    $goExe = Join-Path $env:USERPROFILE "go\bin\$Name.exe"
    if (Test-Path $goExe) { return $goExe }
    $pythonScriptDirs = @()
    if ($env:APPDATA) {
        $appPython = Join-Path $env:APPDATA "Python"
        if (Test-Path $appPython) {
            $pythonScriptDirs += Get-ChildItem -LiteralPath $appPython -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Join-Path $_.FullName "Scripts"
            }
        }
    }
    if ($env:LOCALAPPDATA) {
        $localPython = Join-Path $env:LOCALAPPDATA "Programs\Python"
        if (Test-Path $localPython) {
            $pythonScriptDirs += Get-ChildItem -LiteralPath $localPython -Directory -Filter "Python*" -ErrorAction SilentlyContinue | ForEach-Object {
                Join-Path $_.FullName "Scripts"
            }
        }
    }
    foreach ($dir in $pythonScriptDirs) {
        $pyExe = Join-Path $dir "$Name.exe"
        if (Test-Path $pyExe) { return $pyExe }
    }
    return ""
}

function Copy-ToolToBin {
    param([string]$Name, [string]$Source)
    if (-not $Source -or -not (Test-Path $Source)) { return "" }
    $extension = [System.IO.Path]::GetExtension($Source)
    $destName = if ($extension -eq ".cmd") { "$Name.cmd" } else { "$Name.exe" }
    $dest = Join-Path $bin $destName
    $srcResolved = (Resolve-Path -LiteralPath $Source).Path
    if ((Test-Path $dest) -and ((Resolve-Path -LiteralPath $dest).Path -eq $srcResolved)) {
        return $dest
    }
    if ($srcResolved -ne $dest) {
        Copy-Item -LiteralPath $Source -Destination $dest -Force
    }
    return $dest
}

function Install-GoTool {
    param([hashtable]$Tool)
    if ($SkipGo) { return $false }
    if (-not $Tool.GoPackage) { return $false }
    $go = Get-Command go -ErrorAction SilentlyContinue
    if (-not $go) { return $false }
    Write-Host "Installing $($Tool.Name) via go install..."
    & go install $Tool.GoPackage
    if ($LASTEXITCODE -ne 0) { return $false }
    $goExe = Join-Path $env:USERPROFILE "go\bin\$($Tool.Name).exe"
    return (Test-Path $goExe)
}

function Install-ReleaseTool {
    param([hashtable]$Tool)
    if ($SkipRelease) { return $false }
    if (-not $Tool.AssetRegex) { return $false }
    $api = "https://api.github.com/repos/$($Tool.Repo)/releases/latest"
    Write-Host "Downloading latest release metadata for $($Tool.Name)..."
    try {
        $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "ai-src-installer" } -TimeoutSec 30
    } catch {
        Write-Host "Release metadata failed for $($Tool.Name): $($_.Exception.Message)"
        return $false
    }

    $asset = $release.assets | Where-Object {
        $_.name -match $Tool.AssetRegex
    } | Select-Object -First 1
    if (-not $asset) {
        Write-Host "No Windows amd64 release asset found for $($Tool.Name)"
        return $false
    }

    $archive = Join-Path $downloads $asset.name
    Write-Host "Downloading $($asset.name)..."
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archive -Headers @{ "User-Agent" = "ai-src-installer" } -TimeoutSec 120
    } catch {
        Write-Host "Release download failed for $($Tool.Name): $($_.Exception.Message)"
        return $false
    }

    $extractDir = Join-Path $downloads "$($Tool.Name)-release"
    if (Test-Path $extractDir) {
        Remove-Item -LiteralPath $extractDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    try {
        if ($archive -match "\.zip$") {
            Expand-Archive -LiteralPath $archive -DestinationPath $extractDir -Force
        } elseif ($archive -match "\.tar\.gz$") {
            & tar -xzf $archive -C $extractDir
            if ($LASTEXITCODE -ne 0) { return $false }
        } else {
            Write-Host "Unsupported release archive for $($Tool.Name): $($asset.name)"
            return $false
        }
    } catch {
        Write-Host "Extract failed for $($Tool.Name): $($_.Exception.Message)"
        return $false
    }

    $exe = Get-ChildItem -LiteralPath $extractDir -Recurse -Filter "$($Tool.Name).exe" | Select-Object -First 1
    if (-not $exe) {
        Write-Host "Executable not found in release archive for $($Tool.Name)"
        return $false
    }
    Copy-Item -LiteralPath $exe.FullName -Destination (Join-Path $bin "$($Tool.Name).exe") -Force
    return $true
}

function Install-PythonTool {
    param([hashtable]$Tool)
    if (-not $Tool.PythonPackage) { return $false }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) { return $false }
    Write-Host "Installing $($Tool.Name) via python -m pip..."
    & python -m pip install --upgrade $Tool.PythonPackage
    if ($LASTEXITCODE -ne 0) { return $false }
    return [bool](Get-LocalTool -Name $Tool.Name)
}

function Install-ParamSpiderCompat {
    $compat = Join-Path $root ".\tools\paramspider_compat.py"
    if (-not (Test-Path $compat)) { return $false }
    $cmdPath = Join-Path $bin "paramspider.cmd"
    $content = @(
        "@echo off",
        "python ""%~dp0..\paramspider_compat.py"" %*"
    )
    $content | Set-Content -Encoding ASCII -LiteralPath $cmdPath
    return (Test-Path $cmdPath)
}

$status = @()
$missing = @()

foreach ($tool in $tools) {
    $name = $tool.Name
    $path = Get-LocalTool -Name $name
    if ($path) {
        $copied = Copy-ToolToBin -Name $name -Source $path
        $status += [pscustomobject]@{ tool = $name; status = "installed"; path = $copied }
        Write-Host "$name available: $copied"
        continue
    }

    $ok = $false
    if ($tool.PythonPackage) {
        $ok = Install-PythonTool -Tool $tool
        if (-not $ok -and $name -eq "paramspider") {
            Write-Host "Using local ParamSpider-compatible fallback..."
            $ok = Install-ParamSpiderCompat
        }
    } elseif ($PreferGo) {
        $ok = Install-GoTool -Tool $tool
        if (-not $ok) {
            $ok = Install-ReleaseTool -Tool $tool
        }
    } else {
        $ok = Install-ReleaseTool -Tool $tool
        if (-not $ok) {
            $ok = Install-GoTool -Tool $tool
        }
    }

    $path = Get-LocalTool -Name $name
    if ($path) {
        $copied = Copy-ToolToBin -Name $name -Source $path
        $status += [pscustomobject]@{ tool = $name; status = "installed"; path = $copied }
        Write-Host "$name installed: $copied"
    } else {
        $releaseUrl = "https://github.com/$($tool.Repo)/releases/latest"
        $status += [pscustomobject]@{ tool = $name; status = "missing"; path = "" }
        if ($tool.PythonPackage) {
            $missing += "$name.exe or $name.cmd -> tools\bin; try: python -m pip install --upgrade $($tool.PythonPackage)"
        } else {
            $missing += "$name.exe -> tools\bin\$name.exe; try: go install $($tool.GoPackage); fallback: download Windows amd64 zip from $releaseUrl"
        }
    }
}

$status | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 ".\tools\tool_install_status.json"
$missing | Set-Content -Encoding UTF8 ".\tools\TO_DOWNLOAD.txt"

Write-Host "Tool status: .\tools\tool_install_status.json"
if ($missing.Count -gt 0) {
    Write-Host "Missing list: .\tools\TO_DOWNLOAD.txt"
}
