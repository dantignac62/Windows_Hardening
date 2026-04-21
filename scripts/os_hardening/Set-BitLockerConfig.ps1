#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Configures BitLocker FVE registry policy for XTS-AES 256.
    Policy only — does NOT enable encryption. Encryption is handled
    post-deploy by Intune/SCCM/Autopilot.

.DESCRIPTION
    Sets the FVE Group Policy registry keys so that when BitLocker IS
    enabled (by whatever deployment method), it uses XTS-AES 256 for OS
    and fixed drives, AES-CBC 256 for removable, TPM-only protector,
    full-disk encryption, Entra escrow required.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Set-BitLockerConfig.log

.NOTES
    Version : 5.0.1 | Date: 2026-04-21 | Log Format: CMTrace
    Changes :
      5.0.0 - Policy-only. Removed -EnableEncryption, -SkipRecoveryBackup,
              Phase 2 (encryption), Phase 3 (auto-unlock). Encryption is
              handled post-deploy by the deployment platform. Entra backup
              requirement hardcoded to required (1).
      4.0.0 - Dropped offline support. Added -EnableEncryption.
      3.0.0 - Initial consolidated release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs\Set-BitLockerConfig.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-BitLockerConfig'

Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

# TPM pre-flight (informational; policy is set regardless)
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if (-not $tpm.TpmPresent) { Write-Log 'TPM NOT present. Policy will still be written.' -Level WARN }
    elseif (-not $tpm.TpmReady) { Write-Log 'TPM present but NOT ready.' -Level WARN }
    else {
        $ver = (Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
        Write-Log "TPM: Present, Ready=$($tpm.TpmReady), Version=$ver"
    }
}
catch [System.Management.Automation.CommandNotFoundException] { Write-Log 'Get-Tpm unavailable' -Level WARN }
catch { Write-Log "TPM check: $($_.Exception.Message)" -Level WARN }

$FVE = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'

# ===========================================================================
# Encryption Methods
# ===========================================================================
Write-LogSection 'BitLocker FVE Policy'

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
Set-HardenedRegistry -Path $FVE -Name 'OSRecovery'                    -Value 1 -Description 'OS: Recovery enabled'
Set-HardenedRegistry -Path $FVE -Name 'OSRecoveryPassword'            -Value 2 -Description 'OS: Allow recovery password'
Set-HardenedRegistry -Path $FVE -Name 'OSRecoveryKey'                 -Value 2 -Description 'OS: Allow recovery key'
Set-HardenedRegistry -Path $FVE -Name 'OSManageDRA'                   -Value 0 -Description 'OS: No DRA'
Set-HardenedRegistry -Path $FVE -Name 'OSActiveDirectoryBackup'       -Value 1 -Description 'OS: Backup to Entra/AD'
Set-HardenedRegistry -Path $FVE -Name 'OSActiveDirectoryInfoToStore'  -Value 1 -Description 'OS: Store passwords+packages'
Set-HardenedRegistry -Path $FVE -Name 'OSHideRecoveryPage'            -Value 1 -Description 'OS: Hide recovery page'
Set-HardenedRegistry -Path $FVE -Name 'OSRequireActiveDirectoryBackup' -Value 1 -Description 'OS: Require Entra backup'

# Fixed data recovery + auto-unlock
Set-HardenedRegistry -Path $FVE -Name 'FDVRecovery'                    -Value 1 -Description 'Fixed: Recovery enabled'
Set-HardenedRegistry -Path $FVE -Name 'FDVRecoveryPassword'            -Value 2 -Description 'Fixed: Allow recovery password'
Set-HardenedRegistry -Path $FVE -Name 'FDVRecoveryKey'                 -Value 2 -Description 'Fixed: Allow recovery key'
Set-HardenedRegistry -Path $FVE -Name 'FDVManageDRA'                   -Value 0 -Description 'Fixed: No DRA'
Set-HardenedRegistry -Path $FVE -Name 'FDVActiveDirectoryBackup'       -Value 1 -Description 'Fixed: Backup to Entra/AD'
Set-HardenedRegistry -Path $FVE -Name 'FDVActiveDirectoryInfoToStore'  -Value 1 -Description 'Fixed: Store passwords+packages'
Set-HardenedRegistry -Path $FVE -Name 'FDVRequireActiveDirectoryBackup' -Value 1 -Description 'Fixed: Require Entra backup'
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

Write-LogSummary -ScriptName 'Set-BitLockerConfig'
Write-Host '  BitLocker policy set. Encryption will be enabled by deployment platform.' -ForegroundColor Cyan
