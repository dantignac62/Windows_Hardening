# Configuration
$Config = @{
    InstallerFilter = "*.msi"
    TransformFile = ""  # Optional: specify transform file path if needed
    LogDir = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
    LogFileName = "MSIInstall.log"
    MSIArguments = "/quiet /norestart"  # Customizable MSI arguments
    TempInstallDir = "C:\Windows\Temp\Absolute"
}

# Function to write minimal log
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    try {
        if (-not (Test-Path $Config.LogDir)) {
            New-Item -Path $Config.LogDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path "$($Config.LogDir)\$($Config.LogFileName)" -Value $logMessage
    }
    catch {
        Write-Error "Failed to write to log: $_"
    }
}

# Function to install MSI package
function Install-MSIPackage {
    param (
        [string]$InstallerPath,
        [string]$TransformPath,
        [string]$MSIArguments
    )
    $arguments = "/i `"$InstallerPath`""
    if ($TransformPath) {
        $arguments += " TRANSFORMS=`"$TransformPath`""
    }
    if ($MSIArguments) {
        $arguments += " $MSIArguments"
    }
    
    Write-Log "Starting installation with arguments: $arguments"
    try {
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
        if ($process.ExitCode -eq 0) {
            Write-Log "Installation successful"
            return $true
        }
        else {
            Write-Log "Installation failed with exit code: $($process.ExitCode)"
            throw "Installation failed with exit code: $($process.ExitCode)"
        }
    }
    catch {
        Write-Log "Installation error: $_"
        throw
    }
}

# Main script execution
try {
    Write-Log "Starting MSI installation process"
    
    # Create temporary directory
    Write-Log "Creating temporary directory: $($Config.TempInstallDir)"
    if (-not (Test-Path $Config.TempInstallDir)) {
        New-Item -Path $Config.TempInstallDir -ItemType Directory -Force | Out-Null
    }
    
    # Copy contents to temporary directory
    Write-Log "Copying contents from script root to $($Config.TempInstallDir)"
    Copy-Item -Path "$PSScriptRoot\*" -Destination $Config.TempInstallDir -Recurse -Force -ErrorAction Stop
    
    # Find installer in temporary directory
    $installer = Get-ChildItem -Path $Config.TempInstallDir -Filter $Config.InstallerFilter -ErrorAction Stop | Select-Object -First 1
    if (-not $installer) {
        Write-Log "No MSI installer found in temporary directory"
        Remove-Item -Path $Config.TempInstallDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
    
    # Check for transform file if specified
    if ($Config.TransformFile) {
        $transformPath = Join-Path $Config.TempInstallDir (Split-Path $Config.TransformFile -Leaf)
        if (-not (Test-Path $transformPath)) {
            Write-Log "Transform file not found at $transformPath"
            Remove-Item -Path $Config.TempInstallDir -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }
    }
    else {
        $transformPath = ""
    }
    
    # Perform installation
    Install-MSIPackage -InstallerPath $installer.FullName -TransformPath $transformPath -MSIArguments $Config.MSIArguments
    
    Write-Log "Installation completed successfully"
    
    # Clean up temporary directory
    Write-Log "Removing temporary directory: $($Config.TempInstallDir)"
    Remove-Item -Path $Config.TempInstallDir -Recurse -Force -ErrorAction SilentlyContinue
    
    exit 0
}
catch {
    Write-Log "Script execution failed: $_"
    # Clean up temporary directory on failure
    if (Test-Path $Config.TempInstallDir) {
        Write-Log "Removing temporary directory due to failure: $($Config.TempInstallDir)"
        Remove-Item -Path $Config.TempInstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit 1
}