# Setup script for SymCrypt development terminal
# This script:
# 1. Finds and runs vcvarsall.bat to set up MSVC environment
# 2. Activates Python venv if it exists

function Initialize-VisualStudioEnvironment {
    <#
    .SYNOPSIS
    Sets up the MSVC environment by finding and invoking vcvarsall.bat
    #>
    
    $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    
    if (-not (Test-Path $vswherePath)) {
        Write-Warning "vswhere.exe not found at: $vswherePath"
        return
    }
    
    $vsPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    
    if (-not $vsPath) {
        Write-Warning "Visual Studio installation not found"
        return
    }
    
    Write-Host "Found Visual Studio at: $vsPath" -ForegroundColor Green
    
    $vcvarsall = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
    
    if (-not (Test-Path $vcvarsall)) {
        Write-Warning "vcvarsall.bat not found at: $vcvarsall"
        return
    }
    
    Write-Host "Setting up MSVC environment..." -ForegroundColor Cyan
    
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { "x64" }
        "ARM64" { "arm64" }
        default { "x86" }
    }
    
    Write-Host "Configuring for architecture: $arch" -ForegroundColor Cyan
    
    # We can't directly invoke vcvarsall.bat to set the environment variables, because
    # batch scripts can't modify the PowerShell environment. So we have to capture the
    # variables we care about and set them explicitly.
    $output = & "${env:COMSPEC}" /s /c "`"$vcvarsall`" $arch && set"
    
    # Parse and set environment variables
    foreach ($line in $output) {
        if ($line -match '^([^=]+)=(.*)$') {
            $name = $matches[1]
            $value = $matches[2]
            
            if ($name -in @('PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'WindowsSdkDir', 'WindowsSDKVersion', 
                            'VCINSTALLDIR', 'VCToolsInstallDir', 'VCToolsRedistDir', 'Platform', 
                            'VisualStudioVersion', 'VSCMD_ARG_TGT_ARCH')) {
                Set-Item -Path "env:$name" -Value $value
            }
        }
    }
    
    Write-Host "MSVC environment configured successfully" -ForegroundColor Green
}

function Initialize-PythonVirtualEnvironment {
    <#
    .SYNOPSIS
    Activates the Python virtual environment if it exists
    #>
    
    $venvActivate = Join-Path $PSScriptRoot "..\.venv\Scripts\Activate.ps1"
    
    if (-not (Test-Path $venvActivate)) {
        return
    }
    
    Write-Host "Activating Python virtual environment..." -ForegroundColor Cyan
    & $venvActivate
    Write-Host "Python venv activated" -ForegroundColor Green
}

# Main execution
Initialize-VisualStudioEnvironment
Initialize-PythonVirtualEnvironment