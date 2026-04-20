#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Installs pending Windows updates as stage 0 of the Win11 25H2
    hardening pipeline. Emits the sidecar contract the orchestrator
    expects (.summary.json + .changes.jsonl under .\Logs\).

.DESCRIPTION
    Three execution paths, chosen by parameters:

      1. Offline  (-OfflinePath + -MsuSourcePath set):
         Applies MSU/CAB packages to a mounted WIM via Add-WindowsPackage.
         DISM handles SSU+LCU dependency ordering when -PackagePath is a
         folder containing multiple packages. Reboot state is not
         evaluated against a mounted image.

      2. Online, local MSU source (-MsuSourcePath set, no -OfflinePath):
         Applies packages from the folder to the running OS via
         Add-WindowsPackage -Online.

      3. Online, Windows Update (default):
         Uses the Windows Update Agent (WUA) COM API to search, download,
         and install missing updates, filtered by -Category, -IncludePreview,
         -IncludeDrivers. No PSGallery dependency.

    Logging and counters are delegated to ImageHardeningLib.ps1 via
    Initialize-HardeningLog / Write-Log. The sidecar .changes.jsonl is
    written directly (using the lib's $script:ChangesFile path) so KB-level
    events appear in the orchestrator's ChangeLedger.

    The summary sidecar extends the library's standard shape with fields
    the orchestrator uses to gate the reboot-halt decision:
      RebootRequired, RebootReasons, Mode, KbsApplied, KbsFailed,
      BuildUbrBefore, BuildUbrAfter.

.PARAMETER OfflinePath
    Root of a mounted Windows image (e.g. 'D:\Mount'). When set, operates
    against that image. Requires -MsuSourcePath.

.PARAMETER MsuSourcePath
    Folder of pre-downloaded MSU/CAB packages. When set, updates are applied
    from this folder instead of via Windows Update.

.PARAMETER Category
    WUA filter. Security, Critical, SecurityAndCritical (default), All.
    Ignored when -MsuSourcePath is set.

.PARAMETER IncludePreview
    Include preview cumulative updates in WUA results.

.PARAMETER IncludeDrivers
    Include driver updates in WUA results. Off by default.

.PARAMETER MinBuildUbr
    Pre-flight gate: if the running OS is at or above this Build.UBR
    (e.g. '26200.8246'), WUA is skipped with a VERIFIED event.
    Not applied in MSU-source modes.

.PARAMETER RebootBehavior
    DetectOnly (default) : flag reboot state in summary; orchestrator halts.
    Fail                 : non-zero exit if reboot required.
    Reboot               : Restart-Computer. Not recommended from orchestrator.

.PARAMETER Quiet
    Suppress console output. Log file still written.

.PARAMETER LogPath
    CMTrace log path. Default: .\Logs\Install-PendingUpdates.log

.NOTES
    Version : 1.1.0 | Date: 2026-04-20
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Changes :
      1.1.0 - Integrated with ImageHardeningLib.ps1 (Initialize-HardeningLog,
              Write-Log with uppercase levels). Removed inline Write-Log shim.
              Uses $script:ChangesFile / $script:LogFile from lib. Extended
              summary sidecar written directly; Write-LogSummary not called
              (it would overwrite with the reduced shape).
      1.0.0 - Initial release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OfflinePath,
    [string]$MsuSourcePath,
    [ValidateSet('Security','Critical','SecurityAndCritical','All')]
    [string]$Category = 'SecurityAndCritical',
    [switch]$IncludePreview,
    [switch]$IncludeDrivers,
    [string]$MinBuildUbr,
    [ValidateSet('DetectOnly','Reboot','Fail')]
    [string]$RebootBehavior = 'DetectOnly',
    [switch]$Quiet,
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs\Install-PendingUpdates.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Library setup --------------------------------------------------

. "$PSScriptRoot\ImageHardeningLib.ps1"
# Initialize-OfflineMode is intentionally not called. This script manages its
# own offline package application (Add-WindowsPackage / DISM) and does not use
# Mount-OfflineHives or Resolve-RegPath.
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Install-PendingUpdates'
Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).BuildNumber)"

# ---------- KB tracking (supplements lib counters) ------------------------

$script:kbsApplied = New-Object System.Collections.Generic.List[string]
$script:kbsFailed  = New-Object System.Collections.Generic.List[string]

function Add-Ledger {
    # Writes directly to $script:ChangesFile (set by Initialize-HardeningLog)
    # so orchestrator's Get-ChangeLedger picks up patching events.
    # SKIPPED and FAILED are extensions beyond the lib's APPLIED/VERIFIED/NOT_APPLICABLE;
    # they render in the orchestrator markdown but are not tallied by lib counters.
    param(
        [Parameter(Mandatory)]
        [ValidateSet('APPLIED','VERIFIED','NOT_APPLICABLE','SKIPPED','FAILED')]
        [string]$Action,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Target,
        [string]$Description,
        [hashtable]$Details
    )
    if (-not $script:ChangesFile) { return }
    $record = [ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Component    = 'Install-PendingUpdates'
        Action       = $Action
        Category     = $Category
        Target       = $Target
        Description  = $Description
        Details      = if ($Details) { $Details } else { @{} }
    }
    try { ($record | ConvertTo-Json -Compress -Depth 5) | Out-File -FilePath $script:ChangesFile -Append -Encoding utf8 }
    catch { }
}

# ---------- State helpers --------------------------------------------------

function Get-OnlineBuildUbr {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    try {
        $b = (Get-ItemProperty -Path $cv -Name CurrentBuild -ErrorAction Stop).CurrentBuild
        $u = (Get-ItemProperty -Path $cv -Name UBR          -ErrorAction Stop).UBR
        return "$b.$u"
    } catch { return $null }
}

function Compare-BuildUbr {
    # 1 if Left > Right, 0 if equal, -1 if Left < Right, $null on parse failure.
    param([string]$Left, [string]$Right)
    if (-not $Left -or -not $Right) { return $null }
    try {
        $l = [version]$Left; $r = [version]$Right
        if ($l -gt $r) { return 1 } elseif ($l -eq $r) { return 0 } else { return -1 }
    } catch { return $null }
}

function Test-PendingReboot {
    $reasons = New-Object System.Collections.Generic.List[string]
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons.Add('CBS.RebootPending')
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons.Add('WU.RebootRequired')
    }
    try {
        $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        if ($sm.PSObject.Properties.Name -contains 'PendingFileRenameOperations' -and $sm.PendingFileRenameOperations) {
            $reasons.Add('SM.PendingFileRenameOperations')
        }
    } catch { }
    [pscustomobject]@{ Required = ($reasons.Count -gt 0); Reasons = @($reasons) }
}

# ---------- DISM-based package install (offline or local MSU online) ------

function Install-PackagesFromFolder {
    param(
        [Parameter(Mandatory)][string]$SourceFolder,
        [string]$OfflineImagePath
    )

    if (-not (Test-Path -LiteralPath $SourceFolder)) {
        throw "MSU source folder not found: $SourceFolder"
    }

    $packages = @(Get-ChildItem -LiteralPath $SourceFolder -File -Recurse -Include '*.msu','*.cab' -ErrorAction SilentlyContinue)
    if ($packages.Count -eq 0) {
        Write-Log "No .msu or .cab packages found under $SourceFolder" -Level WARN
        Add-Ledger -Action NOT_APPLICABLE -Category Patching -Target $SourceFolder `
                   -Description 'No packages in source folder' -Details @{}
        return
    }

    # Pass the folder to Add-WindowsPackage. DISM resolves SSU+LCU dependency
    # order when the folder contains multiple packages. Documented on Win10 1803+.
    $targetDesc = if ($OfflineImagePath) { "offline image at $OfflineImagePath" } else { 'running OS' }
    Write-Log "Applying $($packages.Count) package(s) from $SourceFolder to $targetDesc"

    if ($PSCmdlet.ShouldProcess($targetDesc, "Add-WindowsPackage from $SourceFolder")) {
        try {
            if ($OfflineImagePath) {
                Add-WindowsPackage -Path $OfflineImagePath -PackagePath $SourceFolder `
                                   -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            } else {
                Add-WindowsPackage -Online -PackagePath $SourceFolder `
                                   -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
            foreach ($p in $packages) {
                $kb        = [regex]::Match($p.Name, '(?i)\bKB\d{6,7}\b').Value
                $kbTarget  = if ($kb) { $kb } else { $p.Name }
                $script:kbsApplied.Add($kbTarget)
                Write-Log "Installed: $kbTarget" -Level APPLIED
                Add-Ledger -Action APPLIED -Category Patching -Target $kbTarget `
                           -Description "Installed package $($p.Name)" `
                           -Details @{
                               Source    = $p.FullName
                               Mode      = if ($OfflineImagePath) { 'Offline' } else { 'Online-Local' }
                               ImagePath = $OfflineImagePath
                           }
            }
        }
        catch {
            Write-Log "Add-WindowsPackage failed: $($_.Exception.Message)" -Level ERROR
            foreach ($p in $packages) {
                $kb       = [regex]::Match($p.Name, '(?i)\bKB\d{6,7}\b').Value
                $kbTarget = if ($kb) { $kb } else { $p.Name }
                $script:kbsFailed.Add($kbTarget)
                Add-Ledger -Action FAILED -Category Patching -Target $kbTarget `
                           -Description "Add-WindowsPackage error: $($_.Exception.Message)" `
                           -Details @{ Source = $p.FullName }
            }
        }
    } else {
        foreach ($p in $packages) {
            $kb       = [regex]::Match($p.Name, '(?i)\bKB\d{6,7}\b').Value
            $kbTarget = if ($kb) { $kb } else { $p.Name }
            Write-Log "WhatIf: would install $kbTarget" -Level SKIP
            Add-Ledger -Action SKIPPED -Category Patching -Target $kbTarget `
                       -Description 'WhatIf: would install package' -Details @{ Source = $p.FullName }
        }
    }
}

# ---------- WUA-based install (online, no local source) ------------------

function Install-UpdatesFromWindowsUpdate {
    param(
        [string]$Category,
        [bool]$IncludePreview,
        [bool]$IncludeDrivers
    )

    Write-Log "Querying Windows Update (Category=$Category IncludePreview=$IncludePreview IncludeDrivers=$IncludeDrivers)"

    $criteria = "IsInstalled=0 and IsHidden=0 and DeploymentAction='Installation'"
    if ($IncludeDrivers) { $criteria += " and (Type='Software' or Type='Driver')" }
    else                 { $criteria += " and Type='Software'" }

    $session = $null
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $session.ClientApplicationID = 'Install-PendingUpdates'
        $searcher = $session.CreateUpdateSearcher()
        # ssWindowsUpdate = 2: query public WU even on WSUS-joined machines.
        $searcher.ServerSelection = 2
        $result = $searcher.Search($criteria)
    }
    catch {
        Write-Log "WUA search failed: $($_.Exception.Message)" -Level ERROR
        Add-Ledger -Action FAILED -Category Patching -Target 'WUA' `
                   -Description "Search failed: $($_.Exception.Message)" -Details @{}
        return
    }

    if ($result.Updates.Count -eq 0) {
        Write-Log 'Windows Update: no pending updates.'
        Add-Ledger -Action VERIFIED -Category Patching -Target 'WindowsUpdate' `
                   -Description 'No pending updates' -Details @{ Searched = $criteria }
        return
    }

    $allowedCategoryNames = switch ($Category) {
        'Security'            { @('Security Updates') }
        'Critical'            { @('Critical Updates') }
        'SecurityAndCritical' { @('Security Updates','Critical Updates') }
        'All'                 { @() }
    }

    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl

    foreach ($u in $result.Updates) {
        $title     = [string]$u.Title
        $kbFirst   = ($u.KBArticleIDs | Select-Object -First 1)
        $kbTarget  = if ($kbFirst) { "KB$kbFirst" } else { $u.Identity.UpdateID }
        $isPreview = $title -match '(?i)\bpreview\b'

        if ($isPreview -and -not $IncludePreview) {
            Write-Log "Skipped (preview): $title" -Level SKIP
            Add-Ledger -Action SKIPPED -Category Patching -Target $kbTarget `
                       -Description 'Preview update excluded' -Details @{ Title = $title }
            continue
        }

        if ($allowedCategoryNames.Count -gt 0) {
            $names   = @($u.Categories | ForEach-Object { $_.Name })
            $matched = $false
            foreach ($n in $allowedCategoryNames) {
                if ($names -contains $n) { $matched = $true; break }
            }
            if (-not $matched) {
                Write-Log "Skipped (category filter): $title" -Level SKIP
                Add-Ledger -Action SKIPPED -Category Patching -Target $kbTarget `
                           -Description 'Not in selected category' `
                           -Details @{ Title = $title; Categories = $names }
                continue
            }
        }

        if (-not $u.EulaAccepted) {
            try { $u.AcceptEula() }
            catch { Write-Log "AcceptEula failed for '$title': $($_.Exception.Message)" -Level WARN }
        }
        $toInstall.Add($u) | Out-Null
    }

    if ($toInstall.Count -eq 0) {
        Write-Log 'No updates match the filter after exclusions.'
        Add-Ledger -Action VERIFIED -Category Patching -Target 'WindowsUpdate' `
                   -Description 'No updates after filter' -Details @{ Category = $Category }
        return
    }

    if (-not $PSCmdlet.ShouldProcess('Windows Update', "Download + install $($toInstall.Count) update(s)")) {
        for ($i = 0; $i -lt $toInstall.Count; $i++) {
            $u        = $toInstall.Item($i)
            $kbFirst  = ($u.KBArticleIDs | Select-Object -First 1)
            $kbTarget = if ($kbFirst) { "KB$kbFirst" } else { $u.Identity.UpdateID }
            Write-Log "WhatIf: would install $kbTarget" -Level SKIP
            Add-Ledger -Action SKIPPED -Category Patching -Target $kbTarget `
                       -Description 'WhatIf: would install' -Details @{ Title = $u.Title }
        }
        return
    }

    Write-Log "Downloading $($toInstall.Count) update(s)..."
    try {
        $downloader         = $session.CreateUpdateDownloader()
        $downloader.Updates = $toInstall
        $downloader.Download() | Out-Null
    }
    catch {
        Write-Log "WUA download failed: $($_.Exception.Message)" -Level ERROR
        Add-Ledger -Action FAILED -Category Patching -Target 'WUA' `
                   -Description "Download failed: $($_.Exception.Message)" -Details @{}
        return
    }

    $readyToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    for ($i = 0; $i -lt $toInstall.Count; $i++) {
        $u        = $toInstall.Item($i)
        $kbFirst  = ($u.KBArticleIDs | Select-Object -First 1)
        $kbTarget = if ($kbFirst) { "KB$kbFirst" } else { $u.Identity.UpdateID }
        if ($u.IsDownloaded) {
            $readyToInstall.Add($u) | Out-Null
        } else {
            Write-Log "Download incomplete: $($u.Title)" -Level WARN
            Add-Ledger -Action FAILED -Category Patching -Target $kbTarget `
                       -Description 'Download incomplete' -Details @{ Title = $u.Title }
            $script:kbsFailed.Add($kbTarget)
        }
    }

    if ($readyToInstall.Count -eq 0) {
        Write-Log 'No downloaded updates to install.' -Level WARN
        return
    }

    Write-Log "Installing $($readyToInstall.Count) update(s)..."
    try {
        $installer         = $session.CreateUpdateInstaller()
        $installer.Updates = $readyToInstall
        $installResult     = $installer.Install()
    }
    catch {
        Write-Log "WUA install failed: $($_.Exception.Message)" -Level ERROR
        for ($i = 0; $i -lt $readyToInstall.Count; $i++) {
            $u        = $readyToInstall.Item($i)
            $kbFirst  = ($u.KBArticleIDs | Select-Object -First 1)
            $kbTarget = if ($kbFirst) { "KB$kbFirst" } else { $u.Identity.UpdateID }
            Add-Ledger -Action FAILED -Category Patching -Target $kbTarget `
                       -Description "Installer exception: $($_.Exception.Message)" -Details @{ Title = $u.Title }
            $script:kbsFailed.Add($kbTarget)
        }
        return
    }

    # ResultCode: 2 = Succeeded, 3 = SucceededWithErrors.
    for ($i = 0; $i -lt $readyToInstall.Count; $i++) {
        $u        = $readyToInstall.Item($i)
        $per      = $installResult.GetUpdateResult($i)
        $kbFirst  = ($u.KBArticleIDs | Select-Object -First 1)
        $kbTarget = if ($kbFirst) { "KB$kbFirst" } else { $u.Identity.UpdateID }
        $rc       = [int]$per.ResultCode

        switch ($rc) {
            2 {
                $script:kbsApplied.Add($kbTarget)
                Write-Log "Installed: $kbTarget - $($u.Title)" -Level APPLIED
                Add-Ledger -Action APPLIED -Category Patching -Target $kbTarget `
                           -Description $u.Title `
                           -Details @{ ResultCode = $rc; HResult = $per.HResult }
            }
            3 {
                $script:kbsApplied.Add($kbTarget)
                Write-Log "Installed (SucceededWithErrors): $kbTarget - $($u.Title)" -Level WARN
                Add-Ledger -Action APPLIED -Category Patching -Target $kbTarget `
                           -Description "$($u.Title) [SucceededWithErrors]" `
                           -Details @{ ResultCode = $rc; HResult = $per.HResult }
            }
            default {
                $script:kbsFailed.Add($kbTarget)
                Write-Log "Failed (RC=$rc): $kbTarget - $($u.Title)" -Level ERROR
                Add-Ledger -Action FAILED -Category Patching -Target $kbTarget `
                           -Description $u.Title `
                           -Details @{ ResultCode = $rc; HResult = $per.HResult }
            }
        }
    }

    Write-Log ("WUA overall ResultCode={0} RebootRequired={1}" -f `
        ([int]$installResult.ResultCode), $installResult.RebootRequired)
}

# ---------- Main flow -----------------------------------------------------

$buildUbrBefore = $null
$buildUbrAfter  = $null
$mode           = $null

try {
    if ($OfflinePath) {
        if (-not (Test-Path -LiteralPath (Join-Path $OfflinePath 'Windows\System32\config\SYSTEM'))) {
            throw "OfflinePath does not look like a mounted Windows image (missing Windows\System32\config\SYSTEM): $OfflinePath"
        }
        if (-not $MsuSourcePath) {
            throw 'Offline mode requires -MsuSourcePath pointing at a folder of .msu/.cab packages.'
        }
        $mode = 'Offline'
        Write-Log "Mode: Offline image servicing. Image=$OfflinePath Source=$MsuSourcePath"
        Install-PackagesFromFolder -SourceFolder $MsuSourcePath -OfflineImagePath $OfflinePath
    }
    elseif ($MsuSourcePath) {
        $mode           = 'Online-LocalMsu'
        $buildUbrBefore = Get-OnlineBuildUbr
        Write-Log "Mode: Online local MSU. Source=$MsuSourcePath Build.UBR before=$buildUbrBefore"
        Install-PackagesFromFolder -SourceFolder $MsuSourcePath
    }
    else {
        $mode           = 'Online-WindowsUpdate'
        $buildUbrBefore = Get-OnlineBuildUbr
        Write-Log "Mode: Online Windows Update. Build.UBR before=$buildUbrBefore"

        $skip = $false
        if ($MinBuildUbr) {
            $cmp = Compare-BuildUbr -Left $buildUbrBefore -Right $MinBuildUbr
            if ($null -ne $cmp -and $cmp -ge 0) {
                Write-Log "Build.UBR $buildUbrBefore >= MinBuildUbr $MinBuildUbr - skipping WUA."
                Add-Ledger -Action VERIFIED -Category Patching -Target 'WindowsUpdate' `
                           -Description 'Build at or above MinBuildUbr' `
                           -Details @{ BuildUbr = $buildUbrBefore; MinBuildUbr = $MinBuildUbr }
                $skip = $true
            }
        }
        if (-not $skip) {
            Install-UpdatesFromWindowsUpdate -Category $Category `
                                             -IncludePreview:$IncludePreview.IsPresent `
                                             -IncludeDrivers:$IncludeDrivers.IsPresent
        }
    }
}
catch {
    Write-Log "Fatal error in patching pipeline: $($_.Exception.Message)" -Level ERROR
    Add-Ledger -Action FAILED -Category Patching -Target 'Pipeline' `
               -Description $_.Exception.Message -Details @{}
}

# ---------- Post-run state (online only) ----------------------------------

$rebootInfo = [pscustomobject]@{ Required = $false; Reasons = @() }
if (-not $OfflinePath) {
    $rebootInfo    = Test-PendingReboot
    $buildUbrAfter = Get-OnlineBuildUbr
    if ($rebootInfo.Required) {
        Write-Log "Pending reboot detected. Reasons: $($rebootInfo.Reasons -join ', ')" -Level WARN
    } else {
        Write-Log 'No pending reboot detected.'
    }
}

# ---------- Extended summary sidecar -------------------------------------
#
# Write directly to the path the lib would use for its own sidecar, with
# the lib's counter values plus KB-specific fields. We do NOT call
# Write-LogSummary because it emits a reduced shape that would overwrite
# the extended one we need for the orchestrator's reboot-halt logic.

$sidecarPath = $script:LogFile -replace '\.log$', '.summary.json'
$payload = [ordered]@{
    ScriptName     = 'Install-PendingUpdates'
    Component      = 'Install-PendingUpdates'
    Version        = '1.1.0'
    Mode           = $mode
    FinishedUtc    = (Get-Date).ToUniversalTime().ToString('o')
    LogFile        = $script:LogFile
    ChangesFile    = $script:ChangesFile
    Counters       = @{
        Applied = $script:Counters.Applied
        Skipped = $script:Counters.Skipped
        Warned  = $script:Counters.Warned
        Errors  = $script:Counters.Errors
    }
    KbsApplied     = @($script:kbsApplied)
    KbsFailed      = @($script:kbsFailed)
    BuildUbrBefore = $buildUbrBefore
    BuildUbrAfter  = $buildUbrAfter
    RebootRequired = [bool]$rebootInfo.Required
    RebootReasons  = @($rebootInfo.Reasons)
}
try { ($payload | ConvertTo-Json -Depth 6) | Out-File -FilePath $sidecarPath -Encoding utf8 -Force }
catch { Write-Log "Could not write summary sidecar to ${sidecarPath}: $($_.Exception.Message)" -Level WARN }

# Console summary (mirrors Write-LogSummary presentation)
Write-Host ''
Write-Host '  Install-PendingUpdates - Complete' -ForegroundColor Cyan
Write-Host '  +---------------------------------+'
Write-Host "  | Applied : $($script:Counters.Applied.ToString().PadLeft(5))                   |" -ForegroundColor Green
Write-Host "  | Skipped : $($script:Counters.Skipped.ToString().PadLeft(5))                   |" -ForegroundColor DarkGray
Write-Host "  | Warnings: $($script:Counters.Warned.ToString().PadLeft(5))                   |" -ForegroundColor $(if ($script:Counters.Warned -gt 0) { 'Yellow' } else { 'DarkGray' })
Write-Host "  | Errors  : $($script:Counters.Errors.ToString().PadLeft(5))                   |" -ForegroundColor $(if ($script:Counters.Errors -gt 0) { 'Red' } else { 'DarkGray' })
Write-Host '  +---------------------------------+'
Write-Host "  | Reboot  : $($rebootInfo.Required)              |" -ForegroundColor $(if ($rebootInfo.Required) { 'Yellow' } else { 'DarkGray' })
Write-Host '  +---------------------------------+'
if ($script:LogFile) { Write-Host "  Log: $($script:LogFile)" -ForegroundColor DarkGray }
Write-Host ''

# ---------- RebootBehavior -----------------------------------------------

if ($rebootInfo.Required) {
    switch ($RebootBehavior) {
        'Fail'   { Write-Log 'RebootBehavior=Fail. Exiting non-zero.' -Level ERROR; exit 3 }
        'Reboot' {
            Write-Log 'RebootBehavior=Reboot. Restarting in 30 seconds.' -Level WARN
            Start-Sleep -Seconds 30
            Restart-Computer -Force
        }
        default  { }
    }
}

if ($script:Counters.Errors -gt 0) { exit 2 }
exit 0
