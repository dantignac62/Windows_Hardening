#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Debloats Windows 11 25H2 Enterprise.
    Runs online against the live OS (intended use: audit-mode VM reference image).

.DESCRIPTION
    Removes provisioned AppX, disables optional features, disables consumer
    services, disables scheduled tasks, suppresses consumer experience via
    registry.

    $AppxProtectList is evaluated BEFORE $AppxAllowList for both provisioned
    and per-user AppX removal. Any package matching the protect list is
    skipped without attempting removal. The protect list is derived from
    packages Windows guards with 0x80070032 on Build 26200 (shell, OOBE,
    credential UI, sign-in broker, SmartScreen, etc.) plus obfuscated
    MicrosoftWindows framework packages observed on that build.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Invoke-Win11Debloat.log

.NOTES
    Version : 4.0.1 | Date: 2026-04-20
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Log Format: CMTrace-compatible
    Changes :
      4.0.0 - Dropped offline (mounted-WIM) support. Script now runs only
              against the live OS, intended for execution inside an
              audit-mode VM before sysprep+capture. -OfflinePath removed;
              scheduled-task and per-user AppX phases always run;
              service disable goes through Set-Service (no registry
              fallback).
      3.0.1 - Added $AppxProtectList; evaluated before $AppxAllowList on both
              provisioned and per-user paths.
      3.0.0 - Initial consolidated release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs\Invoke-Win11Debloat.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Load shared infrastructure --
. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Invoke-Win11Debloat'

Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

# -- Contains-match against a list of -like patterns (preserves v3.0.0 semantics).
#    Patterns may include trailing or embedded * wildcards.
function Test-AppxPatternMatch {
    param(
        [Parameter(Mandatory)][string]$PackageName,
        [Parameter(Mandatory)][string[]]$Patterns
    )
    foreach ($pattern in $Patterns) {
        $p = $pattern.TrimEnd('*')
        if ($PackageName -like "*$p*") { return $true }
    }
    return $false
}

# ===========================================================================
# PHASE 1: AppX Provisioned Package Removal
# ===========================================================================
Write-LogSection 'Phase 1: AppX Provisioned Package Removal'

# Platform components Windows guards with 0x80070032 on Build 26200.
# Evaluated BEFORE $AppxAllowList. Any match -> skipped, no removal attempt.
# Protects against (a) noisy warnings on protected components, (b) future
# breakage if MS relaxes OS-level protection or if applied to older images
# where protection was weaker.
$AppxProtectList = @(
    # --- Sign-in / credentials / biometric ---
    'Microsoft.AAD.BrokerPlugin'                    # Entra/AAD token broker
    'Microsoft.AccountsControl'                     # Credential UI
    'Microsoft.BioEnrollment'                       # Windows Hello
    'Microsoft.CredDialogHost'                      # Credential dialog
    'Microsoft.LockApp'                             # Lock screen

    # --- Shell surfaces (Start, taskbar, File Explorer, Settings) ---
    'Microsoft.Windows.ShellExperienceHost'
    'Microsoft.Windows.StartMenuExperienceHost'
    'Microsoft.Windows.PeopleExperienceHost'
    'MicrosoftWindows.Client.FileExp'               # File Explorer
    'windows.immersivecontrolpanel'                 # Settings

    # --- Core platform client packages ---
    'MicrosoftWindows.Client.CBS'
    'MicrosoftWindows.Client.Core'
    'MicrosoftWindows.Client.CoreAI'
    'MicrosoftWindows.Client.OOBE'
    'MicrosoftWindows.Client.Photon'
    'MicrosoftWindows.UndockedDevKit'

    # --- OOBE / provisioning / cloud experience ---
    'Microsoft.Windows.CloudExperienceHost'
    'Microsoft.Windows.OOBENetworkCaptivePortal'
    'Microsoft.Windows.OOBENetworkConnectionFlow'

    # --- Input / text / accessibility ---
    'Microsoft.AsyncTextService'
    'Microsoft.ECApp'                               # Eye Control
    'Microsoft.Windows.NarratorQuickStart'
    'Microsoft.Ink.Handwriting*'                    # in-use during run

    # --- Security / filter surfaces ---
    'Microsoft.Windows.Apprep.ChxApp'               # SmartScreen
    'Microsoft.Windows.AssignedAccessLockApp'       # Kiosk mode
    'Microsoft.Windows.ParentalControls'
    'Microsoft.Windows.SecureAssessmentBrowser'

    # --- Misc shell dialogs / system UI ---
    'Microsoft.Windows.CapturePicker'
    'Microsoft.Windows.ContentDeliveryManager'
    'Microsoft.Windows.PinningConfirmationDialog'
    'Microsoft.Windows.PrintQueueActionCenter'
    'Microsoft.Windows.XGpuEjectDialog'
    'Microsoft.MicrosoftEdgeDevToolsClient'
    'Microsoft.PPIProjection'                       # Miracast
    'Microsoft.Win32WebViewHost'
    'Microsoft.XboxGameCallableUI'
    'Windows.CBSPreview'
    'Windows.PrintDialog'


    # --- Framework runtimes (in-use / dependency-locked) ---
    'Microsoft.Windows.AugLoop.CBS'
    'Microsoft.WindowsAppRuntime.*'                 # 1.6/1.7/1.8/CBS family

    # --- Obfuscated Copilot/AI framework packages ---
    # Pattern: MicrosoftWindows.<digits>.<token>. <digits> changes per
    # version; token names observed on 26200 are listed below.
    'MicrosoftWindows.*.Livtop'
    'MicrosoftWindows.*.Speion'
    'MicrosoftWindows.*.Voiess'
    'MicrosoftWindows.*.InpApp'
    'MicrosoftWindows.*.Filons'
    'MicrosoftWindows.*.Tasbar'
)

$AppxAllowList = @(
    'Microsoft.DesktopAppInstaller'; 'Microsoft.SecHealthUI'; 'Microsoft.StorePurchaseApp'
    'Microsoft.VCLibs*'; 'Microsoft.UI.Xaml*'; 'Microsoft.NET.Native*'
    'Microsoft.WindowsStore'; 'Microsoft.WindowsNotepad'; 'Microsoft.WindowsTerminal'
    'Microsoft.WindowsCalculator'; 'Microsoft.Paint'; 'Microsoft.ScreenSketch'
    'Microsoft.HEIFImageExtension'; 'Microsoft.HEVCVideoExtension'
    'Microsoft.WebMediaExtensions'; 'Microsoft.WebpImageExtension'
    'Microsoft.RawImageExtension'; 'Microsoft.VP9VideoExtensions'; 'Microsoft.AV1VideoExtension'
    # v3.0.1 additions
    'MicrosoftCorporationII.QuickAssist'            # helpdesk remote assist
    # v4.0.1: Removed Microsoft.OneDriveSync (company policy: OneDrive disabled)
    'Microsoft.Winget.Source'                       # winget source cache
    # v4.0.1: System AppX GUIDs that throw 0x80070032 on Build 26200
    '1527c705-839a-4832-9118-54d4Bd6a0c89'     # FilePicker
    'c5e2524a-ea46-4f67-841f-6a9465d9d515'     # FileExplorer
    'E2A4F912-2574-4A75-9BB0-0D023378592B'     # AppResolverUX
    'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE'     # AddSuggestedFoldersToLibraryDialog
)

try {
    $provisioned = Get-AppxProvisionedPackage -Online
    Write-Log "Found $($provisioned.Count) provisioned packages"

    foreach ($pkg in $provisioned) {
        $displayName = if ($pkg.DisplayName) { $pkg.DisplayName } else { $pkg.PackageName }
        $pkgDetails = @{ PackageName = $pkg.PackageName; DisplayName = $displayName; Scope = 'Provisioned' }

        # Protect list is absolute: evaluated first, overrides allowlist.
        if (Test-AppxPatternMatch -PackageName $pkg.PackageName -Patterns $AppxProtectList) {
            Write-Log "Protected: $displayName" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'AppX' -Target $pkg.PackageName `
                -Description 'On protect list; removal intentionally skipped' -Details $pkgDetails
            continue
        }

        if (Test-AppxPatternMatch -PackageName $pkg.PackageName -Patterns $AppxAllowList) {
            Write-Log "Kept: $displayName" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'AppX' -Target $pkg.PackageName `
                -Description 'On allow list; kept' -Details $pkgDetails
            continue
        }

        if ($PSCmdlet.ShouldProcess($displayName, 'Remove-AppxProvisionedPackage')) {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop | Out-Null
                Write-Log "Removed provisioned: $displayName" -Level APPLIED
                Write-ChangeEvent -Action 'APPLIED' -Category 'AppX' -Target $pkg.PackageName `
                    -Description 'Provisioned package removed' -Details $pkgDetails
            }
            catch { Write-Log "Failed: $displayName - $($_.Exception.Message)" -Level WARN }
        }
    }
}
catch { Write-Log "AppxProvisionedPackage error: $($_.Exception.Message)" -Level ERROR }

# Per-user cleanup
Write-Log '-- Phase 1b: Per-User AppX Cleanup --'
try {
    foreach ($pkg in (Get-AppxPackage -AllUsers)) {
        $puDetails = @{ PackageName = $pkg.Name; PackageFullName = $pkg.PackageFullName; Scope = 'PerUser' }

        # Protect list evaluated first against short name.
        if (Test-AppxPatternMatch -PackageName $pkg.Name -Patterns $AppxProtectList) {
            Write-Log "Protected per-user: $($pkg.Name)" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'AppX' -Target $pkg.PackageFullName `
                -Description 'Per-user: on protect list; removal intentionally skipped' -Details $puDetails
            continue
        }

        # Allowlisted per-user items are quiet-skipped (no ledger entry) to
        # keep the artifact size manageable: there can be many per-user
        # entries for common frameworks, and the allowlist is fixed and
        # already fully documented in the script. The protect list and the
        # removal entries are what matter for evidence.
        if (Test-AppxPatternMatch -PackageName $pkg.Name -Patterns $AppxAllowList) {
            continue
        }

        if ($PSCmdlet.ShouldProcess($pkg.Name, 'Remove-AppxPackage -AllUsers')) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                Write-Log "Removed per-user: $($pkg.Name)" -Level APPLIED
                Write-ChangeEvent -Action 'APPLIED' -Category 'AppX' -Target $pkg.PackageFullName `
                    -Description 'Per-user package removed (AllUsers)' -Details $puDetails
            }
            catch { Write-Log "Failed per-user: $($pkg.Name) - $($_.Exception.Message)" -Level WARN }
        }
    }
}
catch { Write-Log "Per-user AppX error: $($_.Exception.Message)" -Level WARN }

# ===========================================================================
# PHASE 2: Optional Features
# ===========================================================================
Write-LogSection 'Phase 2: Disable Optional Features'

# v3.0.1: Removed entries no longer present on 25H2 26200:
#   MicrosoftWindowsPowerShellV2Root, MicrosoftWindowsPowerShellV2
#   (PS 2.0 engine removed from OS), Internet-Explorer-Optional-amd64.
# SMB1 and XPS retained - may not be already-disabled on pristine images.
# v4.0.1: Removed features already disabled on pristine 25H2 26200:
#   SMB1Protocol, SMB1Protocol-Client, SMB1Protocol-Server,
#   Printing-XPSServices-Features.
$FeaturesToDisable = @(
    'WindowsMediaPlayer'
    'WorkFolders-Client'
)

foreach ($feature in $FeaturesToDisable) {
    try {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($null -eq $state) {
            Write-Log "Feature not found: $feature" -Level SKIP
            Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Feature' -Target $feature `
                -Description 'Optional feature not present on this image' -Details @{ FeatureName = $feature }
            continue
        }
        $before = [string]$state.State
        if ($state.State -eq 'Disabled') {
            Write-Log "Already disabled: $feature" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'Feature' -Target $feature `
                -Description 'Optional feature already disabled' -Details @{ FeatureName = $feature; StateBefore = $before; StateAfter = $before }
            continue
        }
        if ($PSCmdlet.ShouldProcess($feature, 'Disable-WindowsOptionalFeature')) {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
            Write-Log "Disabled feature: $feature" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'Feature' -Target $feature `
                -Description 'Optional feature disabled' -Details @{ FeatureName = $feature; StateBefore = $before; StateAfter = 'Disabled' }
        }
    }
    catch { Write-Log "Failed feature $feature - $($_.Exception.Message)" -Level WARN }
}

# ===========================================================================
# PHASE 3: Consumer Services
# ===========================================================================
Write-LogSection 'Phase 3: Disable Consumer Services'

# v4.0.1: Removed services not installed or already disabled on 25H2 26200:
#   WMPNetworkSvc (not installed), Fax (not installed),
#   RemoteRegistry (already disabled by default).
$ServicesToDisable = @(
    @{ Name = 'XblAuthManager';   Desc = 'Xbox Live Auth Manager' }
    @{ Name = 'XblGameSave';      Desc = 'Xbox Live Game Save' }
    @{ Name = 'XboxGipSvc';       Desc = 'Xbox Accessory Management' }
    @{ Name = 'XboxNetApiSvc';    Desc = 'Xbox Live Networking' }
    @{ Name = 'DiagTrack';        Desc = 'Connected User Experiences and Telemetry' }
    @{ Name = 'dmwappushservice'; Desc = 'WAP Push Message Routing' }
    @{ Name = 'MapsBroker';       Desc = 'Downloaded Maps Manager' }
    # lfsvc (Geolocation) removed: company policy requires auto-timezone
    @{ Name = 'RetailDemo';       Desc = 'Retail Demo Service' }
)

foreach ($svc in $ServicesToDisable) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Write-Log "Service not found: $($svc.Name)" -Level SKIP
            Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Service' -Target $svc.Name `
                -Description "$($svc.Desc) - service not installed on this image" `
                -Details @{ ServiceName = $svc.Name; DisplayName = $svc.Desc }
            continue
        }
        $startBefore = [string]$service.StartType
        if ($service.StartType -eq 'Disabled') {
            Write-Log "Already disabled: $($svc.Name)" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'Service' -Target $svc.Name `
                -Description "$($svc.Desc) - already disabled" `
                -Details @{ ServiceName = $svc.Name; DisplayName = $svc.Desc; StartTypeBefore = $startBefore; StartTypeAfter = $startBefore }
            continue
        }
        if ($PSCmdlet.ShouldProcess("$($svc.Name)", 'Disable')) {
            if ($service.Status -eq 'Running') { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
            Write-Log "Disabled: $($svc.Name) ($($svc.Desc))" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'Service' -Target $svc.Name `
                -Description "$($svc.Desc) - disabled" `
                -Details @{ ServiceName = $svc.Name; DisplayName = $svc.Desc; StartTypeBefore = $startBefore; StartTypeAfter = 'Disabled' }
        }
    }
    catch { Write-Log "Failed: $($svc.Name) - $($_.Exception.Message)" -Level WARN }
}

# ===========================================================================
# PHASE 4: Scheduled Tasks
# ===========================================================================
Write-LogSection 'Phase 4: Scheduled Tasks'

foreach ($task in @(
    '\Microsoft\Windows\Autochk\Proxy'
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator'
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip'
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
    # v4.0.1: Removed MapsUpdateTask (already disabled on 25H2 26200).
    '\Microsoft\Windows\Maps\MapsToastTask'
    '\Microsoft\Windows\Shell\FamilySafetyMonitor'
    '\Microsoft\Windows\Shell\FamilySafetyRefreshTask'
    '\Microsoft\XblGameSave\XblGameSaveTask'
)) {
    try {
        $tp = $task -replace '[^\\]*$', ''; $tn = $task -replace '.*\\', ''
        $taskDetails = @{ TaskPath = $tp; TaskName = $tn; FullPath = $task }
        $t = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue
        if ($null -eq $t) {
            Write-Log "Task not found: $task" -Level SKIP
            Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'ScheduledTask' -Target $task `
                -Description 'Scheduled task not present on this image' -Details $taskDetails
            continue
        }
        $stateBefore = [string]$t.State
        if ($t.State -eq 'Disabled') {
            Write-Log "Already disabled: $task" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'ScheduledTask' -Target $task `
                -Description 'Scheduled task already disabled' `
                -Details ($taskDetails + @{ StateBefore = $stateBefore; StateAfter = $stateBefore })
            continue
        }
        if ($PSCmdlet.ShouldProcess($task, 'Disable-ScheduledTask')) {
            Disable-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop | Out-Null
            Write-Log "Disabled task: $task" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'ScheduledTask' -Target $task `
                -Description 'Scheduled task disabled' `
                -Details ($taskDetails + @{ StateBefore = $stateBefore; StateAfter = 'Disabled' })
        }
    }
    catch { Write-Log "Failed task $task - $($_.Exception.Message)" -Level WARN }
}

# ===========================================================================
# PHASE 5: Registry - Consumer Experience
# ===========================================================================
Write-LogSection 'Phase 5: Suppress Consumer Features'

Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'     -Name 'DisableWindowsConsumerFeatures' -Value 1 -Description 'Disable consumer experience'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'     -Name 'DisableSoftLanding'             -Value 1 -Description 'Disable tips/suggestions'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'     -Name 'DisableCloudOptimizedContent'   -Value 1 -Description 'Disable cloud-optimized content'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Value 0 -Description 'Disable Start suggestions'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'  -Name 'DisabledByGroupPolicy'          -Value 1 -Description 'Disable Advertising ID'
#Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Copilot'  -Name 'TurnOffWindowsCopilot'          -Value 1 -Description 'Disable Windows Copilot'

Write-LogSummary -ScriptName 'Invoke-Win11Debloat'
Write-Host '  Reboot recommended.' -ForegroundColor Yellow
