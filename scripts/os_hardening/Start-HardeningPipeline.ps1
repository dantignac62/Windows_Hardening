#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Lifecycle wrapper for the hardening pipeline. Runs the orchestrator,
    survives a reboot, and resumes automatically.

.DESCRIPTION
    First run:
      1. Registers a Scheduled Task that fires at logon (runs as SYSTEM
         with highest privileges).
      2. Writes a state file (pipeline.state.json) to track progress.
      3. Runs Invoke-HardeningOrchestrator.ps1.
      4. If the orchestrator exits with code 2 (reboot required after
         patching), the state file is updated and the machine reboots
         automatically (unless -NoAutoReboot is set).

    After reboot:
      1. The Scheduled Task fires, launching this script again.
      2. This script detects the state file, sees Phase=Hardening, and
         re-runs the orchestrator with -SkipPatching.
      3. On success (exit 0) or non-reboot failure (exit 1), the task
         and state file are cleaned up.

    The Scheduled Task is named 'HardeningPipelineResume' and is
    auto-removed on completion. The state file lives next to this script.

.PARAMETER EnableEncryption
    Passed through to the orchestrator / Set-BitLockerConfig.

.PARAMETER SkipRecoveryBackup
    Passed through to the orchestrator / Set-BitLockerConfig.

.PARAMETER MsuSourcePath
    Passed through to the orchestrator / Install-PendingUpdates.

.PARAMETER MinBuildUbr
    Passed through to the orchestrator / Install-PendingUpdates.

.PARAMETER UpdateCategory
    Passed through to the orchestrator. Default: SecurityAndCritical.

.PARAMETER IncludePreview
    Passed through to the orchestrator / Install-PendingUpdates.

.PARAMETER NoAutoReboot
    Do not reboot automatically after patching. The script will still
    register the resume task so a manual reboot triggers the resume.

.PARAMETER RebootDelaySec
    Seconds to wait before rebooting. Default: 15. Gives time to read
    the console output.

.PARAMETER Quiet
    Suppress child-script console output.

.PARAMETER Cleanup
    Remove the Scheduled Task and state file without running anything.
    Use after a failed or aborted run to reset state.

.NOTES
    Version : 1.1 | Date: 2026-04-20
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Requires: Invoke-HardeningOrchestrator.ps1 in the same directory.
#>

[CmdletBinding()]
param(
    [switch]$EnableEncryption,
    [switch]$SkipRecoveryBackup,
    [string]$MsuSourcePath,
    [string]$MinBuildUbr,
    [ValidateSet('Security','Critical','SecurityAndCritical','All')]
    [string]$UpdateCategory = 'SecurityAndCritical',
    [switch]$IncludePreview,
    [switch]$NoAutoReboot,
    [int]$RebootDelaySec = 15,
    [switch]$Quiet,
    [switch]$Cleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Constants ------------------------------------------------------

$TaskName   = 'HardeningPipelineResume'
$StateFile  = Join-Path $PSScriptRoot 'pipeline.state.json'
$Orchestrator = Join-Path $PSScriptRoot 'Invoke-HardeningOrchestrator.ps1'

# ---------- Helpers --------------------------------------------------------

function Write-Status {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "  [Pipeline] $Message" -ForegroundColor $Color
}

function Get-PipelineState {
    if (-not (Test-Path -LiteralPath $StateFile)) { return $null }
    try { return (Get-Content -LiteralPath $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json) }
    catch { return $null }
}

function Set-PipelineState {
    param([string]$Phase, [hashtable]$Extra = @{})
    $state = [ordered]@{
        Phase       = $Phase
        UpdatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        ScriptPath  = $PSCommandPath
        ScriptRoot  = $PSScriptRoot
    }
    foreach ($k in $Extra.Keys) { $state[$k] = $Extra[$k] }
    ConvertTo-Json -InputObject $state -Depth 4 |
        Set-Content -LiteralPath $StateFile -Encoding UTF8 -Force
}

function Remove-PipelineState {
    if (Test-Path -LiteralPath $StateFile) {
        Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
        Write-Status 'State file removed.'
    }
}

function Register-ResumeTask {
    # Creates a Scheduled Task that runs this wrapper script at logon.
    # Runs as SYSTEM so it works even if the logon user changes between
    # reboots (e.g. audit-mode auto-logon vs. manual logon).
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Status 'Resume task already registered.' 'DarkGray'
        return
    }

    # Build the argument string. Pass through all params that matter for
    # the resume run. The resume path always hits the Hardening phase
    # (patching is skipped), so only BitLocker-related params matter.
    # The wrapper detects the state file and acts accordingly.
    $argParts = @("-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"")
    if ($EnableEncryption)    { $argParts += '-EnableEncryption' }
    if ($SkipRecoveryBackup)  { $argParts += '-SkipRecoveryBackup' }
    if ($Quiet)               { $argParts += '-Quiet' }
    $arguments = $argParts -join ' '

    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 4)

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Resumes Windows hardening pipeline after reboot' `
        -Force | Out-Null

    Write-Status "Registered Scheduled Task: $TaskName"
}

function Unregister-ResumeTask {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Status "Unregistered Scheduled Task: $TaskName"
    }
}

# ---------- Cleanup mode --------------------------------------------------

if ($Cleanup) {
    Write-Status 'Cleanup mode: removing task and state file.'
    Unregister-ResumeTask
    Remove-PipelineState
    Write-Status 'Done.' 'Green'
    exit 0
}

# ---------- Pre-flight -----------------------------------------------------

if (-not (Test-Path -LiteralPath $Orchestrator)) {
    Write-Status "Orchestrator not found: $Orchestrator" 'Red'
    exit 1
}

# ---------- Determine phase ------------------------------------------------

$state = Get-PipelineState

if ($null -eq $state) {
    # Fresh run: Patching + Hardening
    $phase = 'Patching'
    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor Cyan
    Write-Host '  Windows 11 Hardening Pipeline - Full Run' -ForegroundColor Cyan
    Write-Host '  ================================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Status 'Phase: Patching + Hardening (full pipeline)'
} else {
    $phase = [string]$state.Phase
    Write-Host ''
    Write-Host '  ================================================================' -ForegroundColor Yellow
    Write-Host '  Windows 11 Hardening Pipeline - Resuming' -ForegroundColor Yellow
    Write-Host '  ================================================================' -ForegroundColor Yellow
    Write-Host ''
    Write-Status "Resuming from state: Phase=$phase (updated $($state.UpdatedUtc))"
}

# ---------- Execute --------------------------------------------------------

switch ($phase) {

    'Patching' {
        # First run: register the resume task BEFORE running the orchestrator.
        # If the orchestrator installs updates and reboots, the task is ready.
        Register-ResumeTask
        Set-PipelineState -Phase 'Patching' -Extra @{
            EnableEncryption   = [bool]$EnableEncryption
            SkipRecoveryBackup = [bool]$SkipRecoveryBackup
        }

        # Build orchestrator arguments
        $orchArgs = @{}
        if ($EnableEncryption)    { $orchArgs['EnableEncryption']    = $true }
        if ($SkipRecoveryBackup)  { $orchArgs['SkipRecoveryBackup']  = $true }
        if ($MsuSourcePath)       { $orchArgs['MsuSourcePath']       = $MsuSourcePath }
        if ($MinBuildUbr)         { $orchArgs['MinBuildUbr']         = $MinBuildUbr }
        if ($UpdateCategory)      { $orchArgs['UpdateCategory']      = $UpdateCategory }
        if ($IncludePreview)      { $orchArgs['IncludePreview']      = $true }
        if ($Quiet)               { $orchArgs['Quiet']               = $true }

        Write-Status "Running orchestrator (full pipeline)..."
        & $Orchestrator @orchArgs
        $exitCode = $LASTEXITCODE

        switch ($exitCode) {
            0 {
                # All stages completed successfully. No reboot needed.
                Write-Status 'Pipeline completed successfully.' 'Green'
                Unregister-ResumeTask
                Remove-PipelineState
                Write-Host ''
                Write-Status 'Next: sysprep /generalize /oobe /shutdown' 'Yellow'
                exit 0
            }
            2 {
                # Reboot required after patching. Update state and reboot.
                Set-PipelineState -Phase 'Hardening' -Extra @{
                    EnableEncryption   = [bool]$EnableEncryption
                    SkipRecoveryBackup = [bool]$SkipRecoveryBackup
                    PatchingCompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
                }
                Write-Host ''
                Write-Status 'Patching requires a reboot to continue.' 'Yellow'
                Write-Status "Hardening will resume automatically after logon via Scheduled Task '$TaskName'."
                if (-not $NoAutoReboot) {
                    Write-Status "Rebooting in $RebootDelaySec seconds... (Ctrl+C to cancel)" 'Yellow'
                    Start-Sleep -Seconds $RebootDelaySec
                    Restart-Computer -Force
                } else {
                    Write-Status 'Auto-reboot disabled. Reboot manually to continue.' 'Yellow'
                    exit 2
                }
            }
            default {
                # Non-reboot failure. Clean up and report.
                Write-Status "Orchestrator exited with code $exitCode. Investigate before re-running." 'Red'
                Unregister-ResumeTask
                Remove-PipelineState
                exit $exitCode
            }
        }
    }

    'Hardening' {
        # Resume after reboot: run orchestrator with -SkipPatching.
        Write-Status 'Patching was completed before reboot. Running hardening stages...'

        $orchArgs = @{ SkipPatching = $true }
        if ($state.PSObject.Properties.Name -contains 'EnableEncryption'   -and [bool]$state.EnableEncryption)   { $orchArgs['EnableEncryption']   = $true }
        if ($state.PSObject.Properties.Name -contains 'SkipRecoveryBackup' -and [bool]$state.SkipRecoveryBackup) { $orchArgs['SkipRecoveryBackup'] = $true }
        if ($Quiet) { $orchArgs['Quiet'] = $true }

        & $Orchestrator @orchArgs
        $exitCode = $LASTEXITCODE

        switch ($exitCode) {
            0 {
                Write-Status 'Pipeline completed successfully.' 'Green'
                Unregister-ResumeTask
                Remove-PipelineState
                Write-Host ''
                Write-Status 'Next: sysprep /generalize /oobe /shutdown' 'Yellow'
                exit 0
            }
            default {
                Write-Status "Orchestrator exited with code $exitCode on resume. Investigate." 'Red'
                Unregister-ResumeTask
                Remove-PipelineState
                exit $exitCode
            }
        }
    }

    default {
        Write-Status "Unknown phase in state file: '$phase'. Run -Cleanup and start over." 'Red'
        exit 1
    }
}
