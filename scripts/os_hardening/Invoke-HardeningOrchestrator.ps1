#Requires -RunAsAdministrator
#Requires -Version 5.1
<#

.SYNOPSIS
    Runs the full Windows 11 25H2 hardening pipeline in order and emits
    a HITRUST-friendly evidence artifact. Intended use: single command
    before sysprep+capture of an audit-mode VM.

.DESCRIPTION
    Executes, in order:
      0. Install-PendingUpdates.ps1  (smart gate: reads Build.UBR,
         queries WUA for pending Security/Critical updates. If current,
         writes UpdatesFinished.txt and proceeds without reboot. If
         updates needed, installs them, writes sentinel, registers
         RunOnce, reboots. Skipped on re-run when sentinel exists.)
      1. Invoke-Win11Debloat.ps1
      2. Set-CISL1Hardening.ps1
      3. Set-CompanyCustomizations.ps1
      4. Set-CipherSuiteHardening.ps1
      5. Set-BitLockerConfig.ps1

    A failure in one script is logged and the next still runs (failures
    do not abort the pipeline) - each area lands independently.

    Each child script writes its own CMTrace log under .\Logs\; this wrapper
    prints a combined per-script pass/fail summary, writes an evidence
    artifact, and exits non-zero if any child reported an error.

    Artifact location:  .\Evidence\<yyyyMMdd_HHmmss>\report.{json,md}

    Artifact contents (audit-mode hardening evidence, not patching):
      - Host identity: OS name/version/build.UBR, edition, architecture,
        installed KBs, TPM state, operator, machine
      - Baseline reference: CIS Microsoft Windows 11 Enterprise L1 v5.0.0
      - Per-script execution: status, start/end UTC, duration, log path,
        log SHA256, counters (Applied/Skipped/Warned/Errors) read from
        each script's sidecar summary file
      - UpdatePolicy: sentinel file state, KBs applied/failed,
        Build.UBR before and after
      - Pre-run and post-run state snapshots (same shape, taken from the
        running OS before and after the pipeline):
          Firewall profiles, BitLocker volume protection+method,
          Defender real-time+tamper protection, SMB signing, SCHANNEL
          TLS protocol enablement, UAC, RDP NLA+encryption level
      - StateDelta: flattened list of leaf values that changed between
        pre and post snapshots (dotted path, old value, new value)
      - ChangeLedger: per-setting record of every Set-HardenedRegistry
        call, with Action (APPLIED = state transition, VERIFIED =
        already at target), path, name, old/new value, CIS ref,
        description — read from each script's .changes.jsonl

.PARAMETER Quiet
    Suppress child-script console output. Log files still written.

.PARAMETER EvidencePath
    Override for the evidence root. Default: .\Evidence

.NOTES
    Version : 1.6.0 | Date: 2026-04-21
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Changes :
      1.6.0 - Stage 0: added Get-HotFix cross-check so KBs that DISM
              slipstreamed (but WUA's DataStore.edb does not reflect)
              are recognised as already installed. WUA criteria now
              includes DeploymentAction='Installation' to align with
              Install-PendingUpdates.ps1. Prevents false-positive patch
              cycles on offline-serviced images booted into Audit Mode.
      1.5.0 - Stage 0 smart gate: reads Build.UBR, queries WUA for
              pending Security/Critical updates before deciding to
              patch. If system is current, writes sentinel and
              proceeds directly to hardening (no reboot). If updates
              installed but no reboot needed, also proceeds without
              reboot. Reboot + RunOnce only when WUA reports
              RebootRequired.
      1.4.0 - Replaced SkipPatching/reboot-halt with sentinel file
              (UpdatesFinished.txt) + RunOnce registry entry.
              Added Set-CompanyCustomizations.ps1 as stage 3.
      1.3.0 - Added Install-PendingUpdates.ps1 as stage 0.
              Silent-failure promotion: Status=Failed when child exits
              cleanly but summary.Counters.Errors > 0.
      1.2.0 - Added PreRunState, StateDelta, ChangeLedger.
      1.1.0 - Initial HITRUST artifact with host identity, pipeline
              results, and post-run state.
      1.0.0 - Pipeline runner without artifact.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $EvidencePath) {
    $EvidencePath = Join-Path $PSScriptRoot 'Evidence'
}
$runStamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$evidenceDir   = Join-Path $EvidencePath $runStamp
if (-not (Test-Path -LiteralPath $evidenceDir)) {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
}

# ---------- Helpers --------------------------------------------------------

function Get-FileSha256Hex {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { return $null }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $v.$Name
    } catch { return $null }
}

function Get-HostSnapshot {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $ubr = Get-RegValue $cv 'UBR'
    $build = Get-RegValue $cv 'CurrentBuild'
    $kbs = @()
    try { $kbs = @(Get-HotFix -ErrorAction Stop | Select-Object -ExpandProperty HotFixID | Sort-Object -Unique) } catch { }

    $tpm = [ordered]@{ Present = $null; Ready = $null; SpecVersion = $null }
    try {
        $t = Get-Tpm -ErrorAction Stop
        $tpm.Present = [bool]$t.TpmPresent
        $tpm.Ready   = [bool]$t.TpmReady
        $tpm.SpecVersion = (Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
    } catch { }

    [pscustomobject]@{
        OsProductName    = (Get-RegValue $cv 'ProductName')
        OsDisplayVersion = (Get-RegValue $cv 'DisplayVersion')
        OsEditionId      = (Get-RegValue $cv 'EditionID')
        OsInstallationType = (Get-RegValue $cv 'InstallationType')
        OsVersion        = if ($os) { $os.Version } else { $null }
        Build            = if ($build) { [int]$build } else { $null }
        UBR              = if ($ubr)   { [int]$ubr }   else { $null }
        BuildUbr         = if ($build -and $ubr) { "$build.$ubr" } else { $null }
        Architecture     = $env:PROCESSOR_ARCHITECTURE
        Operator         = $env:USERNAME
        Machine          = $env:COMPUTERNAME
        InstalledKBs     = $kbs
        Tpm              = $tpm
    }
}

function Get-SystemStateSnapshot {
    # Best-effort state readback. Each section is independent and swallows
    # its own errors - a missing cmdlet on an old image must not block the
    # artifact. Called twice by the orchestrator: once before the pipeline
    # (PreRunState) and once after (PostRunState).
    $snapshot = [ordered]@{}

    # Firewall
    $fw = @{}
    try {
        foreach ($p in Get-NetFirewallProfile -ErrorAction Stop) {
            $fw[$p.Name] = [ordered]@{
                Enabled              = [bool]$p.Enabled
                DefaultInboundAction  = [string]$p.DefaultInboundAction
                DefaultOutboundAction = [string]$p.DefaultOutboundAction
            }
        }
    } catch { $fw['_error'] = $_.Exception.Message }
    $snapshot['Firewall'] = $fw

    # BitLocker (recovery key hash, not the plaintext password)
    $bl = @()
    try {
        foreach ($v in Get-BitLockerVolume -ErrorAction Stop) {
            $protectors = @($v.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType } | Sort-Object -Unique)
            $bl += [ordered]@{
                MountPoint          = $v.MountPoint
                VolumeType          = [string]$v.VolumeType
                ProtectionStatus    = [string]$v.ProtectionStatus
                EncryptionMethod    = [string]$v.EncryptionMethod
                VolumeStatus        = [string]$v.VolumeStatus
                EncryptionPercentage = [int]$v.EncryptionPercentage
                KeyProtectorTypes   = $protectors
            }
        }
    } catch { $bl = @([ordered]@{ _error = $_.Exception.Message }) }
    $snapshot['BitLocker'] = $bl

    # Defender
    $def = [ordered]@{}
    try {
        $m = Get-MpComputerStatus -ErrorAction Stop
        $def.RealTimeProtectionEnabled = [bool]$m.RealTimeProtectionEnabled
        $def.TamperProtected           = [bool]$m.IsTamperProtected
        $def.AMServiceEnabled          = [bool]$m.AMServiceEnabled
        $def.AntispywareEnabled        = [bool]$m.AntispywareEnabled
        $def.AntivirusEnabled          = [bool]$m.AntivirusEnabled
    } catch { $def['_error'] = $_.Exception.Message }
    $snapshot['Defender'] = $def

    # SMB signing
    $smb = [ordered]@{
        ClientRequireSecuritySignature = (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature')
        ServerRequireSecuritySignature = (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'       'RequireSecuritySignature')
    }
    $snapshot['SMB'] = $smb

    # SCHANNEL protocols
    $schBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $sch = [ordered]@{}
    foreach ($p in @('TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3','SSL 3.0')) {
        $sch[$p] = [ordered]@{
            ClientEnabled = (Get-RegValue "$schBase\$p\Client" 'Enabled')
            ServerEnabled = (Get-RegValue "$schBase\$p\Server" 'Enabled')
        }
    }
    $snapshot['Schannel'] = $sch

    # UAC
    $polSys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $snapshot['UAC'] = [ordered]@{
        EnableLUA                 = (Get-RegValue $polSys 'EnableLUA')
        ConsentPromptBehaviorAdmin = (Get-RegValue $polSys 'ConsentPromptBehaviorAdmin')
        FilterAdministratorToken  = (Get-RegValue $polSys 'FilterAdministratorToken')
    }

    # RDP
    $ts = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $snapshot['RDP'] = [ordered]@{
        UserAuthentication = (Get-RegValue $ts 'UserAuthentication')
        MinEncryptionLevel = (Get-RegValue $ts 'MinEncryptionLevel')
    }

    return $snapshot
}

function Get-ScriptSummary {
    # Locate and parse the .summary.json sidecar that Write-LogSummary
    # emits next to the child's CMTrace log.
    param([string]$ScriptPath)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
    $sidecar = Join-Path $PSScriptRoot "Logs\$stem.summary.json"
    if (-not (Test-Path -LiteralPath $sidecar)) { return $null }
    try { return (Get-Content -LiteralPath $sidecar -Raw -ErrorAction Stop | ConvertFrom-Json) }
    catch { return $null }
}

function Get-ChangeLedger {
    # Reads the per-setting JSONL ledger a child script emitted via
    # Write-ChangeEvent. Returns an array of pscustomobjects (one per
    # APPLIED or VERIFIED setting). Empty array when the file is missing
    # or empty - children that don't use Set-HardenedRegistry (e.g., the
    # debloat script, which mostly calls DISM/Get-Service) may emit only
    # a handful of events or none.
    param([string]$ChangesFile)
    if (-not $ChangesFile -or -not (Test-Path -LiteralPath $ChangesFile)) { return @() }
    $events = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($line in Get-Content -LiteralPath $ChangesFile -ErrorAction Stop) {
            if (-not $line.Trim()) { continue }
            try { $events.Add(($line | ConvertFrom-Json)) } catch { }
        }
    } catch { }
    return ,$events.ToArray()
}

function ConvertTo-FlatDict {
    # Flattens an arbitrarily nested hashtable/ordered/array/scalar graph
    # into a plain hashtable of dotted-path -> scalar value, suitable for
    # leaf-by-leaf diffing. Array elements are suffixed with [i].
    param($Obj, [string]$Prefix = '')
    $out = @{}
    if ($null -eq $Obj) { $out[$Prefix] = $null; return $out }
    if ($Obj -is [System.Collections.IDictionary]) {
        foreach ($k in $Obj.Keys) {
            $p = if ($Prefix) { "$Prefix.$k" } else { [string]$k }
            $child = ConvertTo-FlatDict -Obj $Obj[$k] -Prefix $p
            foreach ($ck in $child.Keys) { $out[$ck] = $child[$ck] }
        }
        return $out
    }
    if ($Obj -is [System.Collections.IEnumerable] -and $Obj -isnot [string]) {
        $i = 0
        foreach ($el in $Obj) {
            $p = if ($Prefix) { "$Prefix[$i]" } else { "[$i]" }
            $child = ConvertTo-FlatDict -Obj $el -Prefix $p
            foreach ($ck in $child.Keys) { $out[$ck] = $child[$ck] }
            $i++
        }
        return $out
    }
    $out[$Prefix] = $Obj
    return $out
}

function Get-StateDelta {
    # Produce a list of leaves whose value changed between Before and
    # After. Comparison is done on compact-JSON serialisation so nulls,
    # bools, and numbers compare correctly across the OrderedDict round
    # trip. Entries missing from one side surface as OldValue=$null or
    # NewValue=$null.
    param($Before, $After)
    $b = ConvertTo-FlatDict -Obj $Before
    $a = ConvertTo-FlatDict -Obj $After
    $keys = @($b.Keys) + @($a.Keys) | Sort-Object -Unique
    $deltas = New-Object System.Collections.Generic.List[object]
    foreach ($k in $keys) {
        $bv = if ($b.ContainsKey($k)) { $b[$k] } else { $null }
        $av = if ($a.ContainsKey($k)) { $a[$k] } else { $null }
        # Use -InputObject to prevent PS 5.1 from unrolling arrays through the
        # pipeline. '$arr | ConvertTo-Json' returns N strings; '-InputObject $arr'
        # returns one JSON array string. -ne on a string[] vs string throws
        # System.ArgumentException under Set-StrictMode -Version Latest.
        $bj = if ($null -eq $bv) { 'null' } else { ConvertTo-Json -InputObject $bv -Compress -Depth 3 }
        $aj = if ($null -eq $av) { 'null' } else { ConvertTo-Json -InputObject $av -Compress -Depth 3 }
        if ($bj -ne $aj) {
            $deltas.Add([pscustomobject]@{
                Path     = $k
                OldValue = $bv
                NewValue = $av
            })
        }
    }
    return ,$deltas.ToArray()
}

# ---------- Stage 0: Patching (smart gate) ---------------------------------
#
# Flow:
#   1. If UpdatesFinished.txt exists -> skip patching, proceed to hardening.
#   2. Otherwise read Build.UBR, query WUA for pending Security/Critical
#      updates. If none -> write sentinel, proceed to hardening (no reboot).
#   3. If updates found -> run Install-PendingUpdates.ps1, write sentinel,
#      register RunOnce, reboot. After reboot, orchestrator re-launches
#      via RunOnce, finds sentinel, proceeds to hardening.

$sentinelFile = Join-Path $PSScriptRoot 'UpdatesFinished.txt'
$patchScript  = Join-Path $PSScriptRoot 'Install-PendingUpdates.ps1'

if (-not (Test-Path -LiteralPath $sentinelFile)) {
    Write-Host ''
    Write-Host '  Stage 0: Patching' -ForegroundColor Cyan
    Write-Host ''

    # Read current Build.UBR
    $cvPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $curBuild = (Get-ItemProperty -Path $cvPath -Name CurrentBuild -EA SilentlyContinue).CurrentBuild
    $curUbr   = (Get-ItemProperty -Path $cvPath -Name UBR -EA SilentlyContinue).UBR
    $buildUbr = if ($curBuild -and $curUbr) { "$curBuild.$curUbr" } else { 'unknown' }
    Write-Host "  Current Build.UBR: $buildUbr" -ForegroundColor White

    # Query WUA for pending Security + Critical updates
    $pendingCount = 0
    try {
        # Build a set of KBs the OS already has, via Get-HotFix.
        # On offline-serviced images WUA's DataStore.edb may lag behind
        # the actual CBS state, reporting IsInstalled=0 for KBs already
        # present. Get-HotFix reads the Win32_QuickFixEngineering WMI
        # class, which reflects CBS reality regardless of WUA sync state.
        # Note: Get-WindowsPackage -Online is NOT useful here — the CU
        # is stored as Package_for_RollupFix (no KB in the name), so a
        # KB-regex match would miss it entirely.
        $installedKBs = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        try {
            foreach ($hf in @(Get-HotFix -ErrorAction Stop)) {
                if ($hf.HotFixID) { [void]$installedKBs.Add($hf.HotFixID) }
            }
        } catch { }
        if ($installedKBs.Count -gt 0) {
            Write-Host "  Installed KBs (HotFix): $($installedKBs.Count) ($($installedKBs -join ', '))" -ForegroundColor DarkGray
        }

        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.ServerSelection = 2  # ssWindowsUpdate (public WU)
        # DeploymentAction='Installation' aligns with Install-PendingUpdates.ps1
        # and excludes updates WUA has detected but not yet offered for install.
        $criteria = "IsInstalled=0 and IsHidden=0 and DeploymentAction='Installation' and Type='Software'"
        $wuResult = $searcher.Search($criteria)

        # Filter to Security + Critical only (match the orchestrator's intent)
        foreach ($u in $wuResult.Updates) {
            $cats = @($u.Categories | ForEach-Object { $_.Name })
            $isPreview = [string]$u.Title -match '(?i)\bpreview\b'
            if (-not $isPreview -and ($cats -contains 'Security Updates' -or $cats -contains 'Critical Updates')) {
                $kbId = ($u.KBArticleIDs | Select-Object -First 1)
                $kbLabel = if ($kbId) { "KB$kbId" } else { $u.Identity.UpdateID }

                # Cross-check: if Get-HotFix already has this KB, WUA is stale.
                if ($kbId -and $installedKBs.Contains("KB$kbId")) {
                    Write-Host "  Already installed: $kbLabel - WUA stale, skipping" -ForegroundColor DarkGray
                    continue
                }

                $pendingCount++
                Write-Host "  Pending: $kbLabel - $($u.Title)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  [WARN] WUA query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Falling back to running Install-PendingUpdates.ps1 unconditionally." -ForegroundColor Yellow
        $pendingCount = -1  # force patching on query failure
    }

    if ($pendingCount -eq 0) {
        # System is current. Write sentinel and proceed to hardening (no reboot).
        Write-Host "  System is current at Build.UBR $buildUbr. No pending Security/Critical updates." -ForegroundColor Green
        "No updates needed. Build.UBR=$buildUbr at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
            Set-Content -LiteralPath $sentinelFile -Encoding UTF8 -Force
        Write-Host "  Written: $sentinelFile" -ForegroundColor Green

    } else {
        # Updates available (or query failed). Run the patching script.
        if ($pendingCount -gt 0) {
            Write-Host "  $pendingCount Security/Critical update(s) pending. Installing..." -ForegroundColor Cyan
        }

        if (-not (Test-Path -LiteralPath $patchScript)) {
            Write-Host "  [MISSING] Install-PendingUpdates.ps1" -ForegroundColor Red
            exit 1
        }

        $patchArgs = @{ RebootBehavior = 'DetectOnly' }
        if ($Quiet) { $patchArgs['Quiet'] = $true }
        & $patchScript @patchArgs

        $patchSummary = Get-ScriptSummary -ScriptPath $patchScript
        $patchFailed  = $patchSummary -and $patchSummary.Counters -and ([int]$patchSummary.Counters.Errors -gt 0)

        if ($patchFailed) {
            Write-Host '  [ERR] Patching reported errors. Fix before re-running.' -ForegroundColor Red
            exit 1
        }

        # Check if a reboot is actually needed (Install-PendingUpdates reports this)
        $needsReboot = $patchSummary -and
                        $patchSummary.PSObject.Properties.Name -contains 'RebootRequired' -and
                        [bool]$patchSummary.RebootRequired

        # Write sentinel
        $afterUbr = (Get-ItemProperty -Path $cvPath -Name UBR -EA SilentlyContinue).UBR
        $afterBuildUbr = if ($curBuild -and $afterUbr) { "$curBuild.$afterUbr" } else { 'unknown' }
        "Updates completed. Build.UBR=$afterBuildUbr at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
            Set-Content -LiteralPath $sentinelFile -Encoding UTF8 -Force
        Write-Host "  Written: $sentinelFile" -ForegroundColor Green

        if ($needsReboot) {
            # Register RunOnce and reboot
            $runOnceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            $runOnceCmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
            if ($Quiet)              { $runOnceCmd += ' -Quiet' }
            Set-ItemProperty -Path $runOnceKey -Name 'HardeningResume' -Value $runOnceCmd -Type String -Force
            Write-Host '  Registered RunOnce: HardeningResume' -ForegroundColor Green

            Write-Host ''
            Write-Host '  Rebooting in 15 seconds to apply updates...' -ForegroundColor Yellow
            Write-Host '  After reboot, hardening resumes automatically via RunOnce.' -ForegroundColor Yellow
            Start-Sleep -Seconds 15
            Restart-Computer -Force
        } else {
            # Updates installed but no reboot needed. Proceed to hardening.
            Write-Host "  Updates applied. Build.UBR now $afterBuildUbr. No reboot required." -ForegroundColor Green
        }
    }
} else {
    Write-Host ''
    Write-Host "  Stage 0: Patching skipped (UpdatesFinished.txt found)" -ForegroundColor DarkGray
}

# ---------- Hardening Pipeline (stages 1-5) --------------------------------

$pipeline = @(
    @{ Name = 'Invoke-Win11Debloat.ps1';      Args = @{} }
    @{ Name = 'Set-CISL1Hardening.ps1';       Args = @{} }
    @{ Name = 'Set-CompanyCustomizations.ps1'; Args = @{} }
    @{ Name = 'Set-CipherSuiteHardening.ps1'; Args = @{} }
    @{ Name = 'Set-BitLockerConfig.ps1';       Args = @{} }
)

$common = @{ Quiet = $Quiet }
if ($WhatIfPreference) { $common['WhatIf'] = $true }

$results         = New-Object System.Collections.Generic.List[object]
$skippedStages   = New-Object System.Collections.Generic.List[string]
$preHost    = Get-HostSnapshot
Write-Host '  Capturing pre-run state snapshot...' -ForegroundColor Cyan
$preState   = Get-SystemStateSnapshot
$runStart   = (Get-Date).ToUniversalTime()

foreach ($step in $pipeline) {
    $path = Join-Path $PSScriptRoot $step.Name
    $startUtc = (Get-Date).ToUniversalTime()

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "`n  [MISSING] $($step.Name)" -ForegroundColor Red
        $results.Add([pscustomobject]@{
            Script    = $step.Name
            Status    = 'Missing'
            StartUtc  = $startUtc.ToString('o')
            EndUtc    = $startUtc.ToString('o')
            DurationSec = 0
            Error     = "Not found: $path"
        })
        continue
    }

    Write-Host ''
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  $($step.Name)" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan

    $callArgs = @{}
    foreach ($k in $common.Keys)    { $callArgs[$k] = $common[$k] }
    foreach ($k in $step.Args.Keys) { $callArgs[$k] = $step.Args[$k] }

    $status = 'OK'
    $err    = $null
    try {
        & $path @callArgs
    }
    catch {
        $status = 'Failed'
        $err    = $_.Exception.Message
        Write-Host "  [ERR]  $($step.Name): $err" -ForegroundColor Red
    }

    $endUtc  = (Get-Date).ToUniversalTime()
    $summary = Get-ScriptSummary -ScriptPath $path

    # Silent-failure promotion: child caught its own errors internally and
    # returned cleanly, but the sidecar shows Counters.Errors > 0.
    if ($status -eq 'OK' -and $summary -and $summary.Counters -and ([int]$summary.Counters.Errors -gt 0)) {
        $status = 'Failed'
    }

    $logPath     = if ($summary) { [string]$summary.LogFile }     else { $null }
    $changesPath = if ($summary -and $summary.PSObject.Properties.Name -contains 'ChangesFile') { [string]$summary.ChangesFile } else { $null }
    $ledger      = Get-ChangeLedger -ChangesFile $changesPath

    $results.Add([pscustomobject]@{
        Script         = $step.Name
        Status         = $status
        StartUtc       = $startUtc.ToString('o')
        EndUtc         = $endUtc.ToString('o')
        DurationSec    = [math]::Round(($endUtc - $startUtc).TotalSeconds, 2)
        LogPath        = $logPath
        LogSha256      = if ($logPath) { Get-FileSha256Hex -Path $logPath } else { $null }
        ChangesPath    = $changesPath
        ChangesSha256  = if ($changesPath) { Get-FileSha256Hex -Path $changesPath } else { $null }
        Counters       = if ($summary) { $summary.Counters } else { $null }
        ChangeLedger   = $ledger
        Error          = $err
    })

}

$runEnd = (Get-Date).ToUniversalTime()

# ---------- Post-run state + artifact --------------------------------------

Write-Host ''
Write-Host '  Capturing post-run state snapshot...' -ForegroundColor Cyan
$postState = Get-SystemStateSnapshot
$stateDelta = Get-StateDelta -Before $preState -After $postState

$patchSummary = Get-ScriptSummary -ScriptPath (Join-Path $PSScriptRoot 'Install-PendingUpdates.ps1')
$updatePolicy = [ordered]@{}
$updatePolicy['SentinelFile']   = $sentinelFile
$updatePolicy['PatchingRanPriorToReboot'] = (Test-Path -LiteralPath $sentinelFile)
$updatePolicy['Mode']           = if ($patchSummary) { [string]$patchSummary.Mode } else { $null }
$updatePolicy['KbsApplied']     = if ($patchSummary) { @($patchSummary.KbsApplied) } else { @() }
$updatePolicy['KbsFailed']      = if ($patchSummary) { @($patchSummary.KbsFailed)  } else { @() }
$updatePolicy['BuildUbrBefore'] = if ($patchSummary) { [string]$patchSummary.BuildUbrBefore } else { $null }
$updatePolicy['BuildUbrAfter']  = if ($patchSummary) { [string]$patchSummary.BuildUbrAfter  } else { $null }

# Build artifact incrementally. PS 5.1 reports the opening line of
# [ordered]@{} for ANY error in the value expressions, making monolithic
# hashtable literals impossible to debug. Incremental .Add() gives each
# assignment its own traceable line number.
$artifact = [ordered]@{}
$artifact['GeneratedUtc']        = $runEnd.ToString('o')
$artifact['OrchestratorVersion'] = '1.6.0'
$artifact['Baseline']            = 'CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1'
$artifact['HitrustCsfRefs']      = @('01.x Access Control','09.x Communications and Operations Management','10.x Information Systems Acquisition, Development, and Maintenance')
$artifact['RunStartUtc']         = $runStart.ToString('o')
$artifact['RunEndUtc']           = $runEnd.ToString('o')
$artifact['RunDurationSec']      = [math]::Round(($runEnd - $runStart).TotalSeconds, 2)
$artifact['UpdatePolicy']        = $updatePolicy
$artifact['Host']                = $preHost
$artifact['Pipeline']            = $results.ToArray()
$artifact['PreRunState']         = $preState
$artifact['PostRunState']        = $postState
$artifact['StateDelta']          = $stateDelta

$jsonPath = Join-Path $evidenceDir 'report.json'
$mdPath   = Join-Path $evidenceDir 'report.md'

# Use -InputObject to serialize the OrderedDictionary as a whole. Piping
# an OrderedDictionary through the pipeline enumerates its DictionaryEntry
# objects in PS 5.1, producing per-entry JSON fragments instead of one object.
ConvertTo-Json -InputObject $artifact -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

# Markdown rendering -------------------------------------------------------
$md = New-Object System.Collections.Generic.List[string]
$md.Add('# Windows 11 Hardening - Evidence Artifact')
$md.Add('')
$md.Add('| Field | Value |')
$md.Add('| --- | --- |')
$md.Add("| Generated | $($artifact.GeneratedUtc) |")
$md.Add("| Operator | $($preHost.Operator) |")
$md.Add("| Machine | $($preHost.Machine) |")
$md.Add("| OS | $($preHost.OsProductName) $($preHost.OsDisplayVersion) ($($preHost.OsEditionId)) |")
$md.Add("| Build.UBR | **$($preHost.BuildUbr)** |")
$md.Add("| Architecture | $($preHost.Architecture) |")
$md.Add("| TPM | Present=$($preHost.Tpm.Present), Ready=$($preHost.Tpm.Ready), Version=$($preHost.Tpm.SpecVersion) |")
$md.Add("| Baseline | $($artifact.Baseline) |")
$md.Add("| Run duration (s) | $($artifact.RunDurationSec) |")
$md.Add('')
$md.Add('## Installed KBs')
$md.Add('')
if ($preHost.InstalledKBs.Count -eq 0) { $md.Add('_none detected_') }
else { $md.Add(($preHost.InstalledKBs -join ', ')) }
$md.Add('')
$md.Add('## Pipeline')
$md.Add('')
$md.Add('| Script | Status | Duration (s) | Applied | Skipped | Warned | Errors |')
$md.Add('| --- | --- | ---: | ---: | ---: | ---: | ---: |')
foreach ($r in $results) {
    $a = if ($r.Counters) { $r.Counters.Applied } else { '-' }
    $s = if ($r.Counters) { $r.Counters.Skipped } else { '-' }
    $w = if ($r.Counters) { $r.Counters.Warned }  else { '-' }
    $e = if ($r.Counters) { $r.Counters.Errors }  else { '-' }
    $md.Add("| $($r.Script) | $($r.Status) | $($r.DurationSec) | $a | $s | $w | $e |")
}
$md.Add('')
$md.Add('## State Delta (Pre vs Post)')
$md.Add('')
if ($stateDelta.Count -eq 0) {
    $md.Add('_No leaf-level state changes detected. The image was already at target before the pipeline ran._')
} else {
    $md.Add("_$($stateDelta.Count) leaf value(s) changed._")
    $md.Add('')
    $md.Add('| Path | Old | New |')
    $md.Add('| --- | --- | --- |')
    foreach ($d in $stateDelta) {
        $o = if ($null -eq $d.OldValue) { '_null_' } else { ConvertTo-Json -InputObject $d.OldValue -Compress -Depth 3 }
        $n = if ($null -eq $d.NewValue) { '_null_' } else { ConvertTo-Json -InputObject $d.NewValue -Compress -Depth 3 }
        $md.Add("| $($d.Path) | $o | $n |")
    }
}
$md.Add('')
$md.Add('## Change Ledger')
$md.Add('')
$md.Add('Per-action record. **APPLIED** = state transition; **VERIFIED** = already at target (compliance evidence); **NOT_APPLICABLE** = target does not exist on this image (evidence that it was evaluated).')
$md.Add('')
foreach ($r in $results) {
    $ledger = $r.ChangeLedger
    $md.Add("### $($r.Script)")
    $md.Add('')
    if (-not $ledger -or $ledger.Count -eq 0) {
        $md.Add('_No ledger events recorded._')
        $md.Add('')
        continue
    }
    $applied  = @($ledger | Where-Object { $_.Action -eq 'APPLIED' }).Count
    $verified = @($ledger | Where-Object { $_.Action -eq 'VERIFIED' }).Count
    $na       = @($ledger | Where-Object { $_.Action -eq 'NOT_APPLICABLE' }).Count
    $md.Add("Total events: $($ledger.Count) (APPLIED: $applied, VERIFIED: $verified, NOT_APPLICABLE: $na)")
    $md.Add('')
    $md.Add('| Action | Category | Target | Description | Details |')
    $md.Add('| --- | --- | --- | --- | --- |')
    foreach ($e in $ledger) {
        $target = if ($e.Target) { $e.Target } else { '-' }
        $desc   = if ($e.Description) { $e.Description } else { '-' }
        $detailSummary = if ($e.Details) {
            ($e.Details | ConvertTo-Json -Compress -Depth 3)
        } else { '-' }
        # Escape pipes inside cell content so markdown tables stay intact.
        $detailSummary = $detailSummary -replace '\|', '\|'
        $desc = $desc -replace '\|', '\|'
        $md.Add("| $($e.Action) | $($e.Category) | $target | $desc | $detailSummary |")
    }
    $md.Add('')
}
$md.Add('## Post-run State')
$md.Add('')
$md.Add('### Firewall')
$md.Add('')
$md.Add('| Profile | Enabled | Inbound | Outbound |')
$md.Add('| --- | --- | --- | --- |')
foreach ($k in @('Domain','Private','Public','DomainProfile','PrivateProfile','PublicProfile')) {
    if ($postState.Firewall.Contains($k)) {
        $p = $postState.Firewall[$k]
        $md.Add("| $k | $($p.Enabled) | $($p.DefaultInboundAction) | $($p.DefaultOutboundAction) |")
    }
}
$md.Add('')
$md.Add('### BitLocker')
$md.Add('')
$md.Add('| Mount | Type | Protection | Method | Status | % | Protectors |')
$md.Add('| --- | --- | --- | --- | --- | ---: | --- |')
foreach ($v in $postState.BitLocker) {
    if ($v.Contains('_error')) { $md.Add("| _error_ | | $($v['_error']) | | | | |"); continue }
    $kp = if ($v.KeyProtectorTypes) { ($v.KeyProtectorTypes -join ', ') } else { '-' }
    $md.Add("| $($v.MountPoint) | $($v.VolumeType) | $($v.ProtectionStatus) | $($v.EncryptionMethod) | $($v.VolumeStatus) | $($v.EncryptionPercentage) | $kp |")
}
$md.Add('')
$md.Add('### Defender')
$md.Add('')
foreach ($k in $postState.Defender.Keys) { $md.Add("- **$k**: $($postState.Defender[$k])") }
$md.Add('')
$md.Add('### SMB Signing')
$md.Add('')
$md.Add("- **Client RequireSecuritySignature**: $($postState.SMB.ClientRequireSecuritySignature)")
$md.Add("- **Server RequireSecuritySignature**: $($postState.SMB.ServerRequireSecuritySignature)")
$md.Add('')
$md.Add('### SCHANNEL TLS Enablement')
$md.Add('')
$md.Add('| Protocol | Client Enabled | Server Enabled |')
$md.Add('| --- | ---: | ---: |')
foreach ($p in $postState.Schannel.Keys) {
    $md.Add("| $p | $($postState.Schannel[$p].ClientEnabled) | $($postState.Schannel[$p].ServerEnabled) |")
}
$md.Add('')
$md.Add('### UAC')
$md.Add('')
foreach ($k in $postState.UAC.Keys) { $md.Add("- **$k**: $($postState.UAC[$k])") }
$md.Add('')
$md.Add('### RDP')
$md.Add('')
foreach ($k in $postState.RDP.Keys) { $md.Add("- **$k**: $($postState.RDP[$k])") }
$md.Add('')
$md.Add('## Reference')
$md.Add('')
$md.Add('- CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1')
$md.Add('- HITRUST CSF families: ' + ($artifact.HitrustCsfRefs -join '; '))

($md -join "`r`n") | Set-Content -LiteralPath $mdPath -Encoding UTF8

# ---------- Console summary ------------------------------------------------

Write-Host ''
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Pipeline Summary" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
foreach ($r in $results) {
    $color = switch ($r.Status) {
        'OK'                     { 'Green' }
        'Failed'                 { 'Red' }
        'Missing'                { 'Red' }
        'Skipped-RebootRequired' { 'Yellow' }
        default                  { 'Yellow' }
    }
    Write-Host ("  {0,-40} {1}" -f $r.Script, $r.Status) -ForegroundColor $color
}
Write-Host ''
Write-Host "  Evidence: $jsonPath"                 -ForegroundColor Cyan
Write-Host "  Evidence: $mdPath"                   -ForegroundColor Cyan
Write-Host ''

$failed = @($results.ToArray() | Where-Object { $_.Status -ne 'OK' })
if ($failed.Count -gt 0) {
    Write-Host "  Investigate failures before sysprep /generalize /oobe /shutdown." -ForegroundColor Yellow
    exit 1
}
Write-Host "  Next: sysprep /generalize /oobe /shutdown, then capture the VHDX with DISM /Capture-Image." -ForegroundColor Yellow
