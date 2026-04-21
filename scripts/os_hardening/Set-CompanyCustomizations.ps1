#Requires -RunAsAdministrator
#Requires -Version 5.1
<#

.SYNOPSIS
    Company-specific image customizations beyond CIS L1 hardening.
    Runs online against the live OS (audit-mode VM reference image).

.DESCRIPTION
    Registry-based customizations that are not part of the CIS benchmark
    but are standard for the enterprise gold image. Intended to run after
    Set-CISL1Hardening.ps1 and before Set-CipherSuiteHardening.ps1.

    Current customizations:
      - Microsoft Edge: suppress first-run experience, disable telemetry,
        disable shopping assistant, disable default-browser prompt
      - Windows Search: disable web/Bing results in Start and taskbar
      - Time Zone: enable automatic detection, enforce via policy
      - Delivery Optimization: disable peer-to-peer, enforce via policy
      - OneDrive: uninstall Win32 client, prevent reinstallation
      - PowerShell: ExecutionPolicy set to RemoteSigned via policy

    All settings use HKLM policy paths so non-administrator users cannot
    override them via Settings.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Set-CompanyCustomizations.log

.NOTES
    Version : 1.1.0 | Date: 2026-04-21
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Log Format: CMTrace-compatible
    Changes :
      1.1.0 - Added Automatic Time Zone, Delivery Optimization disable,
              OneDrive uninstall.
      1.0.0 - Edge FRE suppression, web search disable.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs\Set-CompanyCustomizations.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-CompanyCustomizations'

Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).BuildNumber)"

# ===========================================================================
# Microsoft Edge - First Run / Telemetry
# ===========================================================================
Write-LogSection 'Microsoft Edge Policy'

$Edge = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'

# First-run experience
Set-HardenedRegistry -Path $Edge -Name 'HideFirstRunExperience'       -Value 1 -Description 'Edge: Skip first-run wizard'
Set-HardenedRegistry -Path $Edge -Name 'AutoImportAtFirstRun'         -Value 4 -Description 'Edge: Do not auto-import from other browsers'
Set-HardenedRegistry -Path $Edge -Name 'DefaultBrowserSettingEnabled' -Value 0 -Description 'Edge: No default-browser prompt'

# Telemetry / personalization
Set-HardenedRegistry -Path $Edge -Name 'MetricsReportingEnabled'         -Value 0 -Description 'Edge: Disable usage/crash metrics'
Set-HardenedRegistry -Path $Edge -Name 'PersonalizationReportingEnabled' -Value 0 -Description 'Edge: Disable ad personalization telemetry'
Set-HardenedRegistry -Path $Edge -Name 'DiagnosticData'                  -Value 0 -Description 'Edge: Diagnostic data off'
Set-HardenedRegistry -Path $Edge -Name 'SendSiteInfoToImproveServices'   -Value 0 -Description 'Edge: No site info to Microsoft'

# Feature bloat
Set-HardenedRegistry -Path $Edge -Name 'EdgeShoppingAssistantEnabled' -Value 0 -Description 'Edge: Disable shopping assistant'
Set-HardenedRegistry -Path $Edge -Name 'StartupBoostEnabled'          -Value 0 -Description 'Edge: Disable startup boost (background preload)'
Set-HardenedRegistry -Path $Edge -Name 'HubsSidebarEnabled'           -Value 0 -Description 'Edge: Disable Copilot/Discover sidebar'
Set-HardenedRegistry -Path $Edge -Name 'SpotlightExperiencesAndRecommendationsEnabled' -Value 0 -Description 'Edge: Disable spotlight recommendations'

# ===========================================================================
# Windows Search - Disable Web/Bing
# ===========================================================================
Write-LogSection 'Windows Search - Disable Web Results'

$Search   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
$Explorer = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'

Set-HardenedRegistry -Path $Search -Name 'DisableWebSearch'         -Value 1 -Description 'Search: Disable web search'
Set-HardenedRegistry -Path $Search -Name 'ConnectedSearchUseWeb'    -Value 0 -Description 'Search: No web-connected search'
Set-HardenedRegistry -Path $Search -Name 'AllowCloudSearch'         -Value 0 -Description 'Search: No cloud search'
Set-HardenedRegistry -Path $Search -Name 'AllowSearchToUseLocation' -Value 0 -Description 'Search: No location for search'

# Win11 22H2+: disables Bing suggestions in the search box
Set-HardenedRegistry -Path $Explorer -Name 'DisableSearchBoxSuggestions' -Value 1 -Description 'Search: No Bing suggestions in search box'

# Win11 25H2: disables dynamic web content in the search bar widget
Set-HardenedRegistry -Path $Search -Name 'EnableDynamicContentInWSB' -Value 0 -Description 'Search: No web content in search bar'

# ===========================================================================
# Automatic Time Zone
# ===========================================================================
Write-LogSection 'Automatic Time Zone'

# Step 1: Set service start types via Set-Service (SCM API) and registry.
# Set-Service updates the Service Control Manager; the registry write is
# belt-and-suspenders for offline/sysprep persistence.

# 1a: Geolocation Service (lfsvc) — provides location data to tzautoupdate.
# CIS 5.18 recommends disabling it; company policy overrides for auto-TZ.
try {
    Set-Service -Name 'lfsvc' -StartupType Manual -ErrorAction Stop
    Write-Log 'Geolocation service (lfsvc): set to Manual (overrides CIS 5.18)' -Level APPLIED
} catch { Write-Log "lfsvc Set-Service failed: $($_.Exception.Message)" -Level WARN }
Set-HardenedRegistry -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc' `
    -Name 'Start' -Value 3 -Description 'lfsvc registry: Manual/Trigger (auto-TZ override)'

# 1b: Auto Time Zone Updater (tzautoupdate) — consumes location, sets TZ.
# Start=4 (Disabled) is the Enterprise default. Flip to Manual (Trigger Start).
try {
    Set-Service -Name 'tzautoupdate' -StartupType Manual -ErrorAction Stop
    Write-Log 'Time Zone Auto Update service (tzautoupdate): set to Manual' -Level APPLIED
} catch { Write-Log "tzautoupdate Set-Service failed: $($_.Exception.Message)" -Level WARN }
Set-HardenedRegistry -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' `
    -Name 'Start' -Value 3 -Description 'tzautoupdate registry: Manual/Trigger'

# Step 2: Turn ON the Location Services master switch.
# The Settings > Privacy > Location toggle reads the PER-USER consent store
# (HKCU), which overrides the machine-level HKLM value. We must set both:
#   a) HKLM — machine default, read by system services
#   b) HKCU — current user (the audit-mode admin building this image)
#   c) Default profile hive — so new users created after sysprep get "Allow"
#
# Three consent scopes must be set:
#   ...\location\Value             = "Allow"  (master: "Location services")
#   ...\location\NonPackaged\Value = "Allow"  ("Let desktop apps access your location")
# Without NonPackaged=Allow, lfsvc/svchost.exe (a desktop app) cannot query
# location, and tzautoupdate never gets a trigger.

# Master location toggle
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' `
    -Name 'Value' -Value 'Allow' -Type String -Description 'Location consent (HKLM): Allow'
Set-HardenedRegistry -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' `
    -Name 'Value' -Value 'Allow' -Type String -Description 'Location consent (HKCU): Allow'

# Let desktop apps access your location (NonPackaged = Win32/svchost)
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged' `
    -Name 'Value' -Value 'Allow' -Type String -Description 'Desktop app location (HKLM): Allow'
Set-HardenedRegistry -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged' `
    -Name 'Value' -Value 'Allow' -Type String -Description 'Desktop app location (HKCU): Allow'

# Set the default user profile so new accounts after sysprep inherit both.
$defHive = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
$defMounted = $false
if (Test-Path -LiteralPath $defHive) {
    try {
        & reg.exe load 'HKU\DefaultProfile' $defHive 2>&1 | Out-Null
        $defMounted = $true
        foreach ($sub in @('location', 'location\NonPackaged')) {
            $defPath = "Registry::HKU\DefaultProfile\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$sub"
            if (-not (Test-Path $defPath)) { New-Item -Path $defPath -Force | Out-Null }
            Set-ItemProperty -Path $defPath -Name 'Value' -Value 'Allow' -Type String -Force
        }
        Write-Log 'Location consent (Default profile): Allow (master + NonPackaged)' -Level APPLIED
    }
    catch { Write-Log "Default profile hive write failed: $($_.Exception.Message)" -Level WARN }
    finally {
        if ($defMounted) {
            [GC]::Collect(); [GC]::WaitForPendingFinalizers()
            Start-Sleep -Milliseconds 500
            & reg.exe unload 'HKU\DefaultProfile' 2>&1 | Out-Null
        }
    }
} else {
    Write-Log "Default profile NTUSER.DAT not found at $defHive" -Level WARN
}

# The sensor permission override for the Windows Location Provider.
# GUID {BFA794E4-F964-4FDB-90F6-51056BFE4B44} is the platform location sensor.
Set-HardenedRegistry `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' `
    -Name 'SensorPermissionState' -Value 1 -Description 'Location sensor: enabled'

# Step 3: Ensure Group Policy does not blanket-disable location.
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' `
    -Name 'DisableLocation' -Value 0 -Description 'Location policy: not force-disabled'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' `
    -Name 'DisableWindowsLocationProvider' -Value 0 -Description 'Location policy: Windows provider not force-disabled'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' `
    -Name 'DisableLocationScripting' -Value 0 -Description 'Location policy: scripting not force-disabled'

# Step 4: Start lfsvc so it is ready when CamSvc re-reads consent on reboot.
# tzautoupdate is trigger-start-only; it activates when lfsvc delivers a
# location change event. The Settings Location toggle requires a reboot to
# reflect registry-based consent changes (CamSvc caches at boot).
try {
    $svc = Get-Service -Name 'lfsvc' -ErrorAction Stop
    if ($svc.Status -ne 'Running') {
        Start-Service -Name 'lfsvc' -ErrorAction Stop
        Write-Log 'Started service: lfsvc' -Level APPLIED
    } else {
        Write-Log 'Service already running: lfsvc' -Level SKIP
    }
} catch { Write-Log "Could not start lfsvc: $($_.Exception.Message)" -Level WARN }

Write-Log 'tzautoupdate is trigger-start: activates on location change from lfsvc' -Level SKIP
Write-Log 'Location + Auto-TZ toggles will show ON after reboot (CamSvc reads consent at boot)'

# ===========================================================================
# Delivery Optimization - Disable
# ===========================================================================
Write-LogSection 'Delivery Optimization - Disable'

$DO = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'

# DODownloadMode controls peer-to-peer behavior:
#   0 = HTTP only (download from Microsoft CDN, no peering)
#   1 = LAN peers only
#   2 = Group (AD site / domain peers)
#   3 = Internet peers
#  99 = Simple (legacy equivalent of 0)
# 100 = Bypass (disable DO entirely, fall back to BITS)
#
# 0 disables all peer-to-peer while keeping the DO download engine.
# Use 100 if DO should not handle any downloads at all.
Set-HardenedRegistry -Path $DO -Name 'DODownloadMode'       -Value 0 -Description 'DO: HTTP only, no peer-to-peer'

# Cap upload to zero so even if mode policy drifts, no data leaves via peering.
Set-HardenedRegistry -Path $DO -Name 'DOMaxUploadBandwidth' -Value 0 -Description 'DO: Zero upload bandwidth'

# The HKLM Policies path enforces this machine-wide. The Settings > Windows
# Update > Delivery Optimization page shows the toggle as grayed/managed.
# Non-admins cannot override.

# ===========================================================================
# OneDrive - Remove and Prevent Reinstallation
# ===========================================================================
Write-LogSection 'OneDrive - Remove'

# Policy: prevent OneDrive from being used for file storage. Grays out the
# OneDrive integration in Explorer and prevents sign-in. Machine-wide;
# non-admins cannot override.
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' `
    -Name 'DisableFileSyncNGSC' -Value 1 -Description 'OneDrive: Disable file sync'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' `
    -Name 'DisableLibrariesDefaultSaveToOneDrive' -Value 0 -Description 'OneDrive: Do not default-save to OneDrive'

# Prevent OneDrive network activity before any user signs in
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' `
    -Name 'PreventNetworkTrafficPreUserSignIn' -Value 1 -Description 'OneDrive: No pre-sign-in network traffic'

# Uninstall the Win32 OneDrive client if present. The AppX/MSIX package
# (Microsoft.OneDriveSync) is handled by Invoke-Win11Debloat.ps1 (removed
# from the AllowList in v4.0.1); this catches the traditional per-machine
# setup.exe installation.
$oneDriveSetup = Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe'
if (-not (Test-Path -LiteralPath $oneDriveSetup)) {
    $oneDriveSetup = Join-Path $env:SystemRoot 'SysWOW64\OneDriveSetup.exe'
}

if (Test-Path -LiteralPath $oneDriveSetup) {
    if ($PSCmdlet.ShouldProcess($oneDriveSetup, 'Uninstall OneDrive')) {
        Write-Log "Uninstalling OneDrive via $oneDriveSetup /uninstall"
        try {
            Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
            $proc = Start-Process -FilePath $oneDriveSetup -ArgumentList '/uninstall' `
                        -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
            switch ($proc.ExitCode) {
                0       { Write-Log 'OneDrive Win32 client uninstalled.' -Level APPLIED }
                # -2147219813 (0x8004069B): nothing to uninstall / already removed.
                # Common when the AppX package was removed first by Invoke-Win11Debloat.
                -2147219813 { Write-Log 'OneDrive already removed (setup returned 0x8004069B).' -Level SKIP }
                default { Write-Log "OneDriveSetup /uninstall exited with code $($proc.ExitCode)" -Level WARN }
            }
        }
        catch { Write-Log "OneDrive uninstall failed: $($_.Exception.Message)" -Level WARN }
    }
} else {
    Write-Log 'OneDriveSetup.exe not found; Win32 client not installed.' -Level SKIP
}

# Clean up residual OneDrive folders in the default user profile so they
# do not appear in new profiles created after sysprep.
$defaultProfile = Join-Path $env:SystemDrive 'Users\Default'
foreach ($folder in @('OneDrive', 'AppData\Local\Microsoft\OneDrive')) {
    $target = Join-Path $defaultProfile $folder
    if (Test-Path -LiteralPath $target) {
        if ($PSCmdlet.ShouldProcess($target, 'Remove OneDrive folder from default profile')) {
            try {
                Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
                Write-Log "Removed default profile folder: $folder" -Level APPLIED
            }
            catch { Write-Log "Could not remove $target - $($_.Exception.Message)" -Level WARN }
        }
    }
}

# ===========================================================================
# PowerShell Execution Policy
# ===========================================================================
Write-LogSection 'PowerShell Execution Policy'

# Set via Group Policy path so non-admins cannot override with Set-ExecutionPolicy.
# EnableScripts=1 activates the policy; ExecutionPolicy sets the scope.
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' `
    -Name 'EnableScripts' -Value 1 -Description 'PS ExecutionPolicy: policy enabled'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' `
    -Name 'ExecutionPolicy' -Value 'RemoteSigned' -Type String -Description 'PS ExecutionPolicy: RemoteSigned'

# ===========================================================================
# Add company-specific customizations below this line
# ===========================================================================
# Write-LogSection 'Company: <Section Name>'
#
# Examples:
#   Set-HardenedRegistry -Path 'HKLM:\...' -Name 'ValueName' -Value 1 -Description 'What it does'
#
#   # Disable Cortana
#   Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
#       -Name 'AllowCortana' -Value 0 -Description 'Disable Cortana'

Write-LogSummary -ScriptName 'Set-CompanyCustomizations'
