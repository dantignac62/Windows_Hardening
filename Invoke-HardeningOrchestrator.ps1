#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the full Windows 11 25H2 hardening pipeline in order and emits
    a HITRUST-friendly evidence artifact. Intended use: single command
    before sysprep+capture of an audit-mode VM.

.DESCRIPTION
    Executes, in order:
      1. Invoke-Win11Debloat.ps1
      2. Set-CISL1Hardening.ps1
      3. Set-CipherSuiteHardening.ps1
      4. Set-BitLockerConfig.ps1

    A failure in one script is logged and the next still runs (failures
    do not abort the pipeline) - each area lands independently. Each
    child script writes its own CMTrace log under .\Logs\; this wrapper
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

.PARAMETER EnableEncryption
    Passed through to Set-BitLockerConfig. Enables BitLocker encryption
    (Phase 2+3); requires a TPM.

.PARAMETER SkipRecoveryBackup
    Passed through to Set-BitLockerConfig. Skip Entra backup requirement
    for disconnected builds.

.PARAMETER Quiet
    Suppress child-script console output. Log files still written.

.PARAMETER EvidencePath
    Override for the evidence root. Default: .\Evidence

.NOTES
    Version : 1.2.0 | Date: 2026-04-19
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Changes :
      1.2.0 - Added PreRunState (mirror of PostRunState taken before the
              pipeline runs), StateDelta (dotted-path diff between pre
              and post), and ChangeLedger (per-setting records read from
              each script's .changes.jsonl). Library's Write-ChangeEvent
              emits APPLIED/VERIFIED events from Set-HardenedRegistry.
      1.1.0 - Initial HITRUST artifact with host identity, pipeline
              results, and post-run state.
      1.0.0 - Pipeline runner without artifact.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$EnableEncryption,
    [switch]$SkipRecoveryBackup,
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
        $bj = $bv | ConvertTo-Json -Compress
        $aj = $av | ConvertTo-Json -Compress
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

# ---------- Pipeline -------------------------------------------------------

$pipeline = @(
    @{ Name = 'Invoke-Win11Debloat.ps1';      Args = @{} }
    @{ Name = 'Set-CISL1Hardening.ps1';       Args = @{} }
    @{ Name = 'Set-CipherSuiteHardening.ps1'; Args = @{} }
    @{ Name = 'Set-BitLockerConfig.ps1'      ; Args = @{ EnableEncryption = $EnableEncryption; SkipRecoveryBackup = $SkipRecoveryBackup } }
)

$common = @{ Quiet = $Quiet }
if ($WhatIfPreference) { $common['WhatIf'] = $true }

$results    = New-Object System.Collections.Generic.List[object]
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

$artifact = [ordered]@{
    GeneratedUtc        = $runEnd.ToString('o')
    OrchestratorVersion = '1.2.0'
    Baseline            = 'CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1'
    HitrustCsfRefs      = @(
        '01.x Access Control',
        '09.x Communications and Operations Management',
        '10.x Information Systems Acquisition, Development, and Maintenance'
    )
    RunStartUtc         = $runStart.ToString('o')
    RunEndUtc           = $runEnd.ToString('o')
    RunDurationSec      = [math]::Round(($runEnd - $runStart).TotalSeconds, 2)
    Host                = $preHost
    Pipeline            = @($results)
    PreRunState         = $preState
    PostRunState        = $postState
    StateDelta          = $stateDelta
}

$jsonPath = Join-Path $evidenceDir 'report.json'
$mdPath   = Join-Path $evidenceDir 'report.md'

$artifact | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

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
        $o = if ($null -eq $d.OldValue) { '_null_' } else { ($d.OldValue | ConvertTo-Json -Compress) }
        $n = if ($null -eq $d.NewValue) { '_null_' } else { ($d.NewValue | ConvertTo-Json -Compress) }
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
    $color = switch ($r.Status) { 'OK' { 'Green' } 'Failed' { 'Red' } 'Missing' { 'Red' } default { 'Yellow' } }
    Write-Host ("  {0,-40} {1}" -f $r.Script, $r.Status) -ForegroundColor $color
}
Write-Host ''
Write-Host "  Evidence: $jsonPath"                 -ForegroundColor Cyan
Write-Host "  Evidence: $mdPath"                   -ForegroundColor Cyan
Write-Host ''

$failed = @($results | Where-Object { $_.Status -ne 'OK' })
if ($failed.Count -gt 0) {
    Write-Host "  Investigate failures before sysprep /generalize /oobe /shutdown." -ForegroundColor Yellow
    exit 1
}
Write-Host "  Next: sysprep /generalize /oobe /shutdown, then capture the VHDX with DISM /Capture-Image." -ForegroundColor Yellow
