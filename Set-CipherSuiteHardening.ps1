#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    SCHANNEL protocol, cipher, and hash hardening for Windows 11 25H2 Enterprise.
    Runs online against the live OS (intended use: audit-mode VM reference image).

.DESCRIPTION
    Disables weak SSL/TLS protocols (PCT 1.0, Multi-Protocol Unified Hello,
    SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) and enforces TLS 1.2 and TLS 1.3.
    Disables weak ciphers (NULL, DES, 3DES, RC2, RC4) and weak hashes (MD5).
    Preserves SHA-1 (Hashes\SHA) to avoid cert-chain breakage; remove separately
    after a certificate inventory.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Set-CipherSuiteHardening.log

.NOTES
    Version : 2.0.0 | Date: 2026-04-19
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Log Format: CMTrace-compatible
    Changes :
      2.0.0 - Dropped offline (mounted-WIM) support. Script now runs only
              against the live OS, intended for execution inside an
              audit-mode VM before sysprep+capture. -OfflinePath removed;
              ControlSet selector pinned to CurrentControlSet.
      1.0.3 - Use $CS for ControlSet selection so SCHANNEL writes land in
              ControlSet001 offline instead of a phantom CurrentControlSet
              tree. Corrected header build target (26100 -> 26200).
      1.0.2 - Replaced [uint32]0xFFFFFFFF with [uint32]::MaxValue.
      1.0.1 - Fixed parser errors (InvalidVariableReferenceWithDrive).
              Variable refs before ':' in "" strings now use ${var} form.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs\Set-CipherSuiteHardening.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Load shared infrastructure --
. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-CipherSuiteHardening'

Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

$SchannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

# SCHANNEL cipher/hash 'enable' DWORD = 0xFFFFFFFF. Use [uint32]::MaxValue
# because the literal 0xFFFFFFFF parses as Int32 -1 in both PS 5.1 and 7.x.
$EnableSentinel = [uint32]::MaxValue

# ===========================================================================
# PHASE 1: SSL/TLS Protocols
# ===========================================================================
Write-LogSection 'Phase 1: SSL/TLS Protocol Enforcement'

$ProtocolsDisable = @(
    'PCT 1.0'; 'Multi-Protocol Unified Hello'
    'SSL 2.0'; 'SSL 3.0'
    'TLS 1.0'; 'TLS 1.1'
)
$ProtocolsEnable = @('TLS 1.2'; 'TLS 1.3')
$Sides = @('Client', 'Server')

foreach ($p in $ProtocolsDisable) {
    foreach ($s in $Sides) {
        Set-HardenedRegistry -Path "$SchannelBase\Protocols\$p\$s" -Name 'Enabled'           -Value 0 -Description "${p} ${s}: Disabled"
        Set-HardenedRegistry -Path "$SchannelBase\Protocols\$p\$s" -Name 'DisabledByDefault' -Value 1 -Description "${p} ${s}: DisabledByDefault"
    }
}
foreach ($p in $ProtocolsEnable) {
    foreach ($s in $Sides) {
        Set-HardenedRegistry -Path "$SchannelBase\Protocols\$p\$s" -Name 'Enabled'           -Value 1 -Description "${p} ${s}: Enabled"
        Set-HardenedRegistry -Path "$SchannelBase\Protocols\$p\$s" -Name 'DisabledByDefault' -Value 0 -Description "${p} ${s}: EnabledByDefault"
    }
}

# ===========================================================================
# PHASE 2: Ciphers
# ===========================================================================
Write-LogSection 'Phase 2: Cipher Algorithm Enforcement'

$CiphersDisable = @(
    'NULL'
    'DES 56/56'
    'RC2 40/128'; 'RC2 56/128'; 'RC2 128/128'
    'RC4 40/128'; 'RC4 56/128'; 'RC4 64/128'; 'RC4 128/128'
    'Triple DES 168'
)
$CiphersEnable = @('AES 128/128', 'AES 256/256')

foreach ($c in $CiphersDisable) {
    Set-HardenedRegistry -Path "$SchannelBase\Ciphers\$c" -Name 'Enabled' -Value 0              -Description "Cipher ${c}: Disabled"
}
foreach ($c in $CiphersEnable) {
    Set-HardenedRegistry -Path "$SchannelBase\Ciphers\$c" -Name 'Enabled' -Value $EnableSentinel -Description "Cipher ${c}: Enabled"
}

# ===========================================================================
# PHASE 3: Hashes
# ===========================================================================
Write-LogSection 'Phase 3: Hash Algorithm Enforcement'

$HashesDisable = @('MD5')
$HashesEnable  = @('SHA256', 'SHA384', 'SHA512')

foreach ($h in $HashesDisable) {
    Set-HardenedRegistry -Path "$SchannelBase\Hashes\$h" -Name 'Enabled' -Value 0              -Description "Hash ${h}: Disabled"
}
foreach ($h in $HashesEnable) {
    Set-HardenedRegistry -Path "$SchannelBase\Hashes\$h" -Name 'Enabled' -Value $EnableSentinel -Description "Hash ${h}: Enabled"
}

Write-LogSummary -ScriptName 'Set-CipherSuiteHardening'
Write-Host '  Reboot required for SCHANNEL changes to take effect.' -ForegroundColor Yellow