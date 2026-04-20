#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Configures BitLocker policy and optionally enables encryption.
    Runs online against the live OS (intended use: audit-mode VM reference image).

.DESCRIPTION
    Phase 1: FVE registry policy — TPM-only, XTS-AES 256, auto-unlock,
    Entra escrow, full disk encryption.
    Phase 2 (-EnableEncryption): Enables BitLocker, adds recovery keys.
    Phase 3 (-EnableEncryption): Configures auto-unlock on fixed drives.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER EnableEncryption
    Enables BitLocker on drives (Phase 2+3). Requires a TPM.

.PARAMETER SkipRecoveryBackup
    Skip Entra ID backup requirement for disconnected builds. Key escrow
    must still be arranged post-deploy.

.NOTES
    Version : 4.0.0 | Date: 2026-04-19 | Log Format: CMTrace
    Changes :
      4.0.0 - Dropped offline (mounted-WIM) support. Script now runs only
              against the live OS, intended for execution inside an
              audit-mode VM before sysprep+capture. -OfflinePath removed;
              -EnableEncryption no longer force-disabled.
      3.0.0 - Initial consolidated release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$EnableEncryption,
    [switch]$SkipRecoveryBackup,
    [switch]$Quiet,
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs\Set-BitLockerConfig.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-BitLockerConfig'

Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

# TPM pre-flight
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if (-not $tpm.TpmPresent) { Write-Log 'TPM NOT present - required for TPM-only mode.' -Level ERROR; return }
    if (-not $tpm.TpmReady) { Write-Log 'TPM present but NOT ready.' -Level WARN }
    $ver = (Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
    Write-Log "TPM: Present, Ready=$($tpm.TpmReady), Version=$ver"
}
catch [System.Management.Automation.CommandNotFoundException] { Write-Log 'Get-Tpm unavailable' -Level WARN }
catch { Write-Log "TPM check: $($_.Exception.Message)" -Level WARN }

$FVE = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'

# ===========================================================================
# PHASE 1: Policy
# ===========================================================================
Write-LogSection 'Phase 1: BitLocker Policy'

# Encryption methods
Set-HardenedRegistry -Path $FVE -Name 'EncryptionMethodWithXtsOs'  -Value 7 -Description 'OS: XTS-AES 256'
Set-HardenedRegistry -Path $FVE -Name 'EncryptionMethodWithXtsFdv' -Value 7 -Description 'Fixed: XTS-AES 256'
Set-HardenedRegistry -Path $FVE -Name 'EncryptionMethodWithXtsRdv' -Value 4 -Description 'Removable: AES-CBC 256'

# TPM-only startup
Set-HardenedRegistry -Path $FVE -Name 'UseAdvancedStartup' -Value 1 -Description 'Advanced startup config'
Set-HardenedRegistry -Path $FVE -Name 'EnableBDEWithNoTPM' -Value 0 -Description 'Disallow without TPM'
Set-HardenedRegistry -Path $FVE -Name 'UseTPM'             -Value 1 -Description 'Require TPM'
Set-HardenedRegistry -Path $FVE -Name 'UseTPMPIN'          -Value 0 -Description 'No TPM+PIN'
Set-HardenedRegistry -Path $FVE -Name 'UseTPMKey'          -Value 0 -Description 'No TPM+startup key'
Set-HardenedRegistry -Path $FVE -Name 'UseTPMKeyPIN'       -Value 0 -Description 'No TPM+PIN+key'
Set-HardenedRegistry -Path $FVE -Name 'UseEnhancedPin'     -Value 0 -Description 'No enhanced PIN'

# OS recovery
Set-HardenedRegistry -Path $FVE -Name 'OSRecovery'                   -Value 1 -Description 'OS: Recovery enabled'
Set-HardenedRegistry -Path $FVE -Name 'OSRecoveryPassword'           -Value 2 -Description 'OS: Allow recovery password'
Set-HardenedRegistry -Path $FVE -Name 'OSRecoveryKey'                -Value 2 -Description 'OS: Allow recovery key'
Set-HardenedRegistry -Path $FVE -Name 'OSManageDRA'                  -Value 0 -Description 'OS: No DRA'
Set-HardenedRegistry -Path $FVE -Name 'OSActiveDirectoryBackup'      -Value 1 -Description 'OS: Backup to Entra/AD'
Set-HardenedRegistry -Path $FVE -Name 'OSActiveDirectoryInfoToStore' -Value 1 -Description 'OS: Store passwords+packages'
Set-HardenedRegistry -Path $FVE -Name 'OSHideRecoveryPage'           -Value 1 -Description 'OS: Hide recovery page'
Set-HardenedRegistry -Path $FVE -Name 'OSRequireActiveDirectoryBackup' -Value $(if($SkipRecoveryBackup){0}else{1}) `
    -Description "OS: $(if($SkipRecoveryBackup){'Skip'}else{'Require'}) Entra backup"

# Fixed data recovery + auto-unlock
Set-HardenedRegistry -Path $FVE -Name 'FDVRecovery'                   -Value 1 -Description 'Fixed: Recovery enabled'
Set-HardenedRegistry -Path $FVE -Name 'FDVRecoveryPassword'           -Value 2 -Description 'Fixed: Allow recovery password'
Set-HardenedRegistry -Path $FVE -Name 'FDVRecoveryKey'                -Value 2 -Description 'Fixed: Allow recovery key'
Set-HardenedRegistry -Path $FVE -Name 'FDVManageDRA'                  -Value 0 -Description 'Fixed: No DRA'
Set-HardenedRegistry -Path $FVE -Name 'FDVActiveDirectoryBackup'      -Value 1 -Description 'Fixed: Backup to Entra/AD'
Set-HardenedRegistry -Path $FVE -Name 'FDVActiveDirectoryInfoToStore' -Value 1 -Description 'Fixed: Store passwords+packages'
if (-not $SkipRecoveryBackup) {
    Set-HardenedRegistry -Path $FVE -Name 'FDVRequireActiveDirectoryBackup' -Value 1 -Description 'Fixed: Require Entra backup'
}
Set-HardenedRegistry -Path $FVE -Name 'FDVAllowUserCert'        -Value 1 -Description 'Fixed: Cert-based auto-unlock'
Set-HardenedRegistry -Path $FVE -Name 'FDVNoBitLockerToGoReader' -Value 1 -Description 'Fixed: No BL To Go reader'
Set-HardenedRegistry -Path $FVE -Name 'FDVDenyWriteAccess'      -Value 1 -Description 'Fixed: Deny write unprotected'

# Removable
Set-HardenedRegistry -Path $FVE -Name 'RDVDenyWriteAccess' -Value 1 -Description 'Removable: Deny write unprotected'
Set-HardenedRegistry -Path $FVE -Name 'RDVDenyCrossOrg'    -Value 0 -Description 'Removable: Allow cross-org'

# Encryption type
Set-HardenedRegistry -Path $FVE -Name 'OSEncryptionType'  -Value 1 -Description 'OS: Full disk'
Set-HardenedRegistry -Path $FVE -Name 'FDVEncryptionType' -Value 1 -Description 'Fixed: Full disk'
Set-HardenedRegistry -Path $FVE -Name 'RDVEncryptionType' -Value 2 -Description 'Removable: Used space only'

if ($SkipRecoveryBackup) { Write-Log 'Entra backup requirement skipped - ensure key escrow post-deploy' -Level WARN }
Write-Log '-- Phase 1 complete --'

# ===========================================================================
# PHASE 2+3: Encryption + Auto-Unlock
# ===========================================================================
if (-not $EnableEncryption) {
    Write-Log 'Phase 2+3 skipped: -EnableEncryption not specified'
}
else {
    Write-LogSection 'Phase 2: Enable Encryption'
    $osDrive = $env:SystemDrive

    try {
        $blv = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction Stop
        if ($blv.ProtectionStatus -eq 'On') {
            Write-Log "OS drive already encrypted" -Level SKIP
            if ($blv.EncryptionMethod -ne 'XtsAes256') { Write-Log "Method: $($blv.EncryptionMethod) - not XTS-AES 256" -Level WARN }
        }
        elseif ($blv.VolumeStatus -eq 'EncryptionInProgress') { Write-Log 'Encryption in progress' -Level SKIP }
        else {
            if ($PSCmdlet.ShouldProcess($osDrive, 'Enable-BitLocker TPM XTS-AES 256')) {
                Enable-BitLocker -MountPoint $osDrive -EncryptionMethod XtsAes256 -TpmProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
                Write-Log "BitLocker enabled on $osDrive" -Level APPLIED
                $rp = (Add-BitLockerKeyProtector -MountPoint $osDrive -RecoveryPasswordProtector -ErrorAction Stop).KeyProtector |
                    Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -Last 1
                if ($rp.RecoveryPassword) {
                    Write-Log "RECOVERY PASSWORD ($osDrive): $($rp.RecoveryPassword)" -Level APPLIED
                    Write-Host "`n  *** SAVE THIS KEY: $($rp.RecoveryPassword) ***`n" -ForegroundColor Red
                }
                try { BackupToAAD-BitLockerKeyProtector -MountPoint $osDrive -KeyProtectorId $rp.KeyProtectorId -ErrorAction Stop; Write-Log 'Entra backup: OK' -Level APPLIED }
                catch { Write-Log "Entra backup failed: $($_.Exception.Message)" -Level WARN }
            }
        }
    }
    catch { Write-Log "OS drive error: $($_.Exception.Message)" -Level ERROR }

    # Fixed data drives
    $fixedVols = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and "$($_.DriveLetter):" -ne $osDrive -and $_.FileSystemType -in @('NTFS','ReFS') }
    if ($fixedVols.Count -eq 0) { Write-Log 'No additional fixed drives' -Level SKIP }
    foreach ($vol in $fixedVols) {
        $mp = "$($vol.DriveLetter):"
        try {
            $fd = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop
            if ($fd.ProtectionStatus -eq 'On') { Write-Log "$mp already encrypted" -Level SKIP; continue }
            if ($PSCmdlet.ShouldProcess($mp, 'Enable-BitLocker')) {
                Enable-BitLocker -MountPoint $mp -EncryptionMethod XtsAes256 -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
                Write-Log "Encrypted $mp" -Level APPLIED
                $fdRP = ((Get-BitLockerVolume -MountPoint $mp).KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -Last 1).RecoveryPassword
                if ($fdRP) { Write-Log "RECOVERY ($mp): $fdRP" -Level APPLIED }
                try { $fdP = (Get-BitLockerVolume -MountPoint $mp).KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -Last 1
                    BackupToAAD-BitLockerKeyProtector -MountPoint $mp -KeyProtectorId $fdP.KeyProtectorId -ErrorAction SilentlyContinue } catch {}
            }
        }
        catch { Write-Log "Failed $mp - $($_.Exception.Message)" -Level WARN }
    }

    # Phase 3: Auto-unlock
    Write-LogSection 'Phase 3: Auto-Unlock'
    $osCheck = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction SilentlyContinue
    if ($null -eq $osCheck -or $osCheck.ProtectionStatus -ne 'On') {
        Write-Log 'OS not fully encrypted - auto-unlock deferred' -Level WARN
        foreach ($v in $fixedVols) { Write-Log "  Run later: Enable-BitLockerAutoUnlock -MountPoint `"$($v.DriveLetter):`"" }
    }
    else {
        foreach ($vol in $fixedVols) {
            $mp = "$($vol.DriveLetter):"
            try {
                $fd = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop
                if ($fd.ProtectionStatus -ne 'On' -and $fd.VolumeStatus -ne 'EncryptionInProgress') { Write-Log "$mp not encrypted" -Level SKIP; continue }
                if ($fd.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'ExternalKey' }) { Write-Log "$mp auto-unlock exists" -Level SKIP; continue }
                if ($PSCmdlet.ShouldProcess($mp, 'Enable-BitLockerAutoUnlock')) {
                    Enable-BitLockerAutoUnlock -MountPoint $mp -ErrorAction Stop
                    Write-Log "Auto-unlock enabled: $mp" -Level APPLIED
                }
            }
            catch { Write-Log "Auto-unlock $mp - $($_.Exception.Message)" -Level WARN }
        }
    }
}

Write-LogSummary -ScriptName 'Set-BitLockerConfig'
if ($EnableEncryption) { Write-Host '  Monitor: manage-bde -status' -ForegroundColor Cyan }
