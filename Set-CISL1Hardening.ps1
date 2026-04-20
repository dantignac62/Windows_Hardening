#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    CIS Windows 11 Enterprise Benchmark v5.0.0 L1 hardening.
    Runs online against the live OS (intended use: audit-mode VM reference image).

.DESCRIPTION
    Registry-based CIS L1 settings: security options, SMB hardening, UAC,
    Kerberos, firewall, admin templates, PowerShell logging, RDP, WinRM,
    plus CVE-2013-3900 and Spectre/Meltdown mitigations.

    Requires ImageHardeningLib.ps1 in the same directory.

.NOTES
    Version  : 4.0.0 | Date: 2026-04-19 | Log Format: CMTrace
    Baseline : CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1
    Changes  :
      4.0.0 - Dropped offline (mounted-WIM) support. Script now runs only
              against the live OS, intended for execution inside an
              audit-mode VM before sysprep+capture. -OfflinePath removed;
              ControlSet selector pinned to CurrentControlSet.
      3.0.0 - Initial consolidated release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs\Set-CISL1Hardening.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-CISL1Hardening'

Write-Log 'Baseline: CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1'
Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

$CS = 'CurrentControlSet'

# ===========================================================================
# Section 2: Security Options
# ===========================================================================
Write-LogSection 'Section 2: Security Options'

$Lsa  = "HKLM:\SYSTEM\$CS\Control\Lsa"
$Pol  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Wks  = "HKLM:\SYSTEM\$CS\Services\LanmanWorkstation\Parameters"
$Srv  = "HKLM:\SYSTEM\$CS\Services\LanmanServer\Parameters"

# Accounts / Audit
Set-HardenedRegistry -Path $Pol  -Name 'NoConnectedUser'           -Value 3 -CISRef '2.3.1.1'  -Description 'Block Microsoft accounts'
Set-HardenedRegistry -Path $Lsa  -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -CISRef '2.3.2.1' -Description 'Force audit subcategory settings'

# Interactive logon
Set-HardenedRegistry -Path $Pol  -Name 'DontDisplayLastUserName'   -Value 1   -CISRef '2.3.7.1' -Description 'Do not display last user'
Set-HardenedRegistry -Path $Pol  -Name 'DisableCAD'                -Value 0   -CISRef '2.3.7.2' -Description 'Require CTRL+ALT+DEL'
Set-HardenedRegistry -Path $Pol  -Name 'InactivityTimeoutSecs'     -Value 900 -CISRef '2.3.7.3' -Description 'Inactivity timeout: 900s'

# SMB Client
Set-HardenedRegistry -Path $Wks  -Name 'RequireSecuritySignature'  -Value 1 -CISRef '2.3.8.1' -Description 'SMB client: Require signing'
Set-HardenedRegistry -Path $Wks  -Name 'EnableSecuritySignature'   -Value 1 -CISRef '2.3.8.2' -Description 'SMB client: Enable signing'
Set-HardenedRegistry -Path $Wks  -Name 'EnablePlainTextPassword'   -Value 0 -CISRef '2.3.8.3' -Description 'SMB client: No plaintext password'

# SMB Server
Set-HardenedRegistry -Path $Srv  -Name 'RequireSecuritySignature'  -Value 1   -CISRef '2.3.9.1'  -Description 'SMB server: Require signing'
Set-HardenedRegistry -Path $Srv  -Name 'EnableSecuritySignature'   -Value 1   -CISRef '2.3.9.2'  -Description 'SMB server: Enable signing'
Set-HardenedRegistry -Path $Srv  -Name 'EnableForcedLogOff'        -Value 1   -CISRef '2.3.9.3'  -Description 'Disconnect on logon hours expire'
Set-HardenedRegistry -Path $Srv  -Name 'RestrictNullSessAccess'    -Value 1   -CISRef '2.3.10.7' -Description 'Restrict anonymous pipe/share'
Set-HardenedRegistry -Path $Srv  -Name 'NullSessionShares' -Value @('') -Type MultiString -CISRef '2.3.10.11' -Description 'Clear anonymous shares'

# LSA / Network security
Set-HardenedRegistry -Path $Lsa           -Name 'RestrictAnonymousSAM'     -Value 1 -CISRef '2.3.10.2' -Description 'Restrict anon SAM enum'
Set-HardenedRegistry -Path $Lsa           -Name 'RestrictAnonymous'         -Value 1 -CISRef '2.3.10.3' -Description 'Restrict anon SAM+share'
Set-HardenedRegistry -Path $Lsa           -Name 'EveryoneIncludesAnonymous' -Value 0 -CISRef '2.3.10.5' -Description 'Everyone != anonymous'
Set-HardenedRegistry -Path "$Lsa\MSV1_0"  -Name 'AllowNullSessionFallback' -Value 0 -CISRef '2.3.11.1' -Description 'Disable NULL session fallback'
Set-HardenedRegistry -Path $Lsa           -Name 'UseMachineId'              -Value 1 -CISRef '2.3.11.2' -Description 'Computer identity for NTLM'
Set-HardenedRegistry -Path "$Lsa\pku2u"   -Name 'AllowOnlineID'             -Value 0 -CISRef '2.3.11.3' -Description 'Disable PKU2U'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
    -Name 'SupportedEncryptionTypes' -Value 2147483640 -CISRef '2.3.11.4' -Description 'Kerberos: AES only (no DES/RC4)'
Set-HardenedRegistry -Path $Lsa          -Name 'LmCompatibilityLevel' -Value 5         -CISRef '2.3.11.5' -Description 'NTLMv2 only; refuse LM/NTLM'
Set-HardenedRegistry -Path "HKLM:\SYSTEM\$CS\Services\LDAP" -Name 'LDAPClientIntegrity' -Value 2 -CISRef '2.3.11.6' -Description 'LDAP: Require signing'
Set-HardenedRegistry -Path "$Lsa\MSV1_0" -Name 'NTLMMinClientSec'     -Value 537395200 -CISRef '2.3.11.7' -Description 'NTLM client: NTLMv2+128-bit'
Set-HardenedRegistry -Path "$Lsa\MSV1_0" -Name 'NTLMMinServerSec'     -Value 537395200 -CISRef '2.3.11.8' -Description 'NTLM server: NTLMv2+128-bit'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' -Name 'ForceKeyProtection' -Value 2 -CISRef '2.3.14.1' -Description 'Force strong key protection'

# UAC
Set-HardenedRegistry -Path $Pol -Name 'FilterAdministratorToken'   -Value 1 -CISRef '2.3.17.1' -Description 'UAC: Admin Approval for built-in'
Set-HardenedRegistry -Path $Pol -Name 'ConsentPromptBehaviorAdmin' -Value 2 -CISRef '2.3.17.2' -Description 'UAC: Prompt consent secure desktop'
Set-HardenedRegistry -Path $Pol -Name 'ConsentPromptBehaviorUser'  -Value 0 -CISRef '2.3.17.3' -Description 'UAC: Auto deny standard users'
Set-HardenedRegistry -Path $Pol -Name 'EnableInstallerDetection'   -Value 1 -CISRef '2.3.17.4' -Description 'UAC: Detect app installs'
Set-HardenedRegistry -Path $Pol -Name 'EnableSecureUIAPaths'       -Value 1 -CISRef '2.3.17.5' -Description 'UAC: Secure locations only'
Set-HardenedRegistry -Path $Pol -Name 'EnableLUA'                  -Value 1 -CISRef '2.3.17.6' -Description 'UAC: Admin Approval Mode'
Set-HardenedRegistry -Path $Pol -Name 'PromptOnSecureDesktop'      -Value 1 -CISRef '2.3.17.7' -Description 'UAC: Secure desktop'
Set-HardenedRegistry -Path $Pol -Name 'EnableVirtualization'       -Value 1 -CISRef '2.3.17.8' -Description 'UAC: Virtualize write failures'

# ===========================================================================
# Section 5: Services
# ===========================================================================
Write-LogSection 'Section 5: Services'

$CISServices = @(
    @{N='IISADMIN';CIS='5.1';D='IIS Admin'}; @{N='irmon';CIS='5.2';D='Infrared'}
    @{N='LxssManager';CIS='5.3';D='WSL'}; @{N='FTPSVC';CIS='5.4';D='FTP'}
    @{N='sshd';CIS='5.5';D='OpenSSH Server'}; @{N='RpcLocator';CIS='5.6';D='RPC Locator'}
    @{N='RemoteAccess';CIS='5.7';D='RRAS'}; @{N='simptcp';CIS='5.8';D='Simple TCP/IP'}
    @{N='SSDPSRV';CIS='5.9';D='SSDP'}; @{N='upnphost';CIS='5.10';D='UPnP'}
    @{N='W3SVC';CIS='5.11';D='WWW'}; @{N='WMSvc';CIS='5.12';D='Web Mgmt'}
    @{N='WMPNetworkSvc';CIS='5.13';D='WMP Net'}; @{N='icssvc';CIS='5.14';D='Hotspot'}
    @{N='WpnService';CIS='5.15';D='Push Notifications'}; @{N='PushToInstall';CIS='5.16';D='PushToInstall'}
    @{N='RemoteRegistry';CIS='5.17';D='Remote Registry'}; @{N='lfsvc';CIS='5.18';D='Geolocation'}
)

foreach ($s in $CISServices) {
    $svc = Get-Service -Name $s.N -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Write-Log "[$($s.CIS)] Not present: $($s.N)" -Level SKIP; continue }
    if ($svc.StartType -eq 'Disabled') { Write-Log "[$($s.CIS)] Already disabled: $($s.N)" -Level SKIP; continue }
    if ($PSCmdlet.ShouldProcess($s.N,'Disable')) {
        try {
            if ($svc.Status -eq 'Running') { Stop-Service -Name $s.N -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $s.N -StartupType Disabled; Write-Log "[$($s.CIS)] Disabled: $($s.N) ($($s.D))" -Level APPLIED
        } catch { Write-Log "[$($s.CIS)] Failed: $($s.N) - $($_.Exception.Message)" -Level WARN }
    }
}

# ===========================================================================
# Section 9: Firewall
# ===========================================================================
Write-LogSection 'Section 9: Firewall'
$fw = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
foreach ($pr in @(@{P='DomainProfile';C='9.1'},@{P='PrivateProfile';C='9.2'},@{P='PublicProfile';C='9.3'})) {
    Set-HardenedRegistry -Path "$fw\$($pr.P)" -Name 'EnableFirewall'       -Value 1 -CISRef "$($pr.C).1" -Description "$($pr.P): ON"
    Set-HardenedRegistry -Path "$fw\$($pr.P)" -Name 'DefaultInboundAction' -Value 1 -CISRef "$($pr.C).2" -Description "$($pr.P) inbound: Block"
    Set-HardenedRegistry -Path "$fw\$($pr.P)" -Name 'DefaultOutboundAction' -Value 0 -CISRef "$($pr.C).3" -Description "$($pr.P) outbound: Allow"
    Set-HardenedRegistry -Path "$fw\$($pr.P)\Logging" -Name 'LogDroppedPackets'        -Value 1     -CISRef "$($pr.C).7" -Description "$($pr.P): Log drops"
    Set-HardenedRegistry -Path "$fw\$($pr.P)\Logging" -Name 'LogSuccessfulConnections' -Value 1     -CISRef "$($pr.C).8" -Description "$($pr.P): Log success"
    Set-HardenedRegistry -Path "$fw\$($pr.P)\Logging" -Name 'LogFileSize'              -Value 16384 -CISRef "$($pr.C).9" -Description "$($pr.P): 16 MB log"
    Set-HardenedRegistry -Path "$fw\$($pr.P)\Logging" -Name 'LogFilePath' -Value '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' -Type String -CISRef "$($pr.C).6" -Description "$($pr.P): Log path"
}

# ===========================================================================
# Section 18: Administrative Templates
# ===========================================================================
Write-LogSection 'Section 18: Admin Templates'

# Personalization
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera'    -Value 1 -CISRef '18.1.1.1' -Description 'No lock screen camera'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value 1 -CISRef '18.1.1.2' -Description 'No lock screen slideshow'

# Network
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'     -Name 'EnableMulticast'       -Value 0 -CISRef '18.4.1' -Description 'Disable LLMNR'
Set-HardenedRegistry -Path "HKLM:\SYSTEM\$CS\Services\Tcpip6\Parameters"                 -Name 'DisableIPSourceRouting' -Value 2 -CISRef '18.4.2' -Description 'IPv6: No source routing'
Set-HardenedRegistry -Path "HKLM:\SYSTEM\$CS\Services\Tcpip\Parameters"                  -Name 'DisableIPSourceRouting' -Value 2 -CISRef '18.4.3' -Description 'IPv4: No source routing'
Set-HardenedRegistry -Path "HKLM:\SYSTEM\$CS\Services\Tcpip\Parameters"                  -Name 'EnableICMPRedirect'     -Value 0 -CISRef '18.4.4' -Description 'Disable ICMP redirects'
Set-HardenedRegistry -Path "HKLM:\SYSTEM\$CS\Services\NetBT\Parameters"                  -Name 'NodeType'               -Value 2 -CISRef '18.4.5' -Description 'NetBT: P-node'

# Printers
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' -Name 'RpcUseNamedPipeProtocol' -Value 0 -CISRef '18.5.1' -Description 'Printers: RPC over TCP'

# System
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -CISRef '18.6.1' -Description 'Audit: Command line in 4688'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name 'AllowEncryptionOracle' -Value 0 -CISRef '18.6.2' -Description 'CredSSP: Force updated clients'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Value 1 -CISRef '18.6.3' -Description 'Non-exportable creds only'

# VBS / Credential Guard
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Value 1 -CISRef '18.6.4'   -Description 'VBS: Enabled'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'RequirePlatformSecurityFeatures'  -Value 3 -CISRef '18.6.4.1' -Description 'VBS: Secure Boot + DMA'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags'                     -Value 1 -CISRef '18.6.4.2' -Description 'Credential Guard: UEFI lock'

# AutoPlay
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'                      -Name 'NoAutoplayfornonVolume' -Value 1   -CISRef '18.9.3.1' -Description 'AutoPlay: No non-volume'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'       -Name 'NoAutorun'              -Value 1   -CISRef '18.9.3.2' -Description 'AutoPlay: Do not execute'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'       -Name 'NoDriveTypeAutoRun'     -Value 255 -CISRef '18.9.3.3' -Description 'AutoPlay: All drives off'

# BitLocker (policy only)
$FVE = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
Set-HardenedRegistry -Path $FVE -Name 'EncryptionMethodWithXtsOs'  -Value 7 -CISRef '18.9.5.1' -Description 'BitLocker OS: XTS-AES 256'
Set-HardenedRegistry -Path $FVE -Name 'EncryptionMethodWithXtsFdv' -Value 7 -CISRef '18.9.5.2' -Description 'BitLocker fixed: XTS-AES 256'
Set-HardenedRegistry -Path $FVE -Name 'EncryptionMethodWithXtsRdv' -Value 4 -CISRef '18.9.5.3' -Description 'BitLocker removable: AES-CBC 256'

# Telemetry
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry'              -Value 0 -CISRef '18.9.14.1' -Description 'Diagnostic data: Off'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DisableOneSettingsDownloads' -Value 1 -CISRef '18.9.14.2' -Description 'Disable OneSettings'

# SmartScreen
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen'     -Value 1       -CISRef '18.9.26.1' -Description 'SmartScreen: Enabled'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Value 'Block' -Type String -CISRef '18.9.26.1' -Description 'SmartScreen: Block'

# PowerShell logging
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -CISRef '18.9.33.1' -Description 'PS: Script Block Logging'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'      -Name 'EnableModuleLogging'      -Value 1 -CISRef '18.9.33.2' -Description 'PS: Module Logging'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -Type String -CISRef '18.9.33.2' -Description 'PS: Log all modules'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'      -Name 'EnableTranscripting'      -Value 1 -CISRef '18.9.33.3' -Description 'PS: Transcription'

# RDP
$TS = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
Set-HardenedRegistry -Path $TS -Name 'fDisableCdm'       -Value 1 -CISRef '18.9.45.1' -Description 'RDP: No drive redirect'
Set-HardenedRegistry -Path $TS -Name 'fPromptForPassword' -Value 1 -CISRef '18.9.45.2' -Description 'RDP: Prompt for password'
Set-HardenedRegistry -Path $TS -Name 'fEncryptRPCTraffic' -Value 1 -CISRef '18.9.45.3' -Description 'RDP: Secure RPC'
Set-HardenedRegistry -Path $TS -Name 'MinEncryptionLevel' -Value 3 -CISRef '18.9.45.4' -Description 'RDP: High encryption'
Set-HardenedRegistry -Path $TS -Name 'UserAuthentication' -Value 1 -CISRef '18.9.45.5' -Description 'RDP: Require NLA'

# WinRM
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'  -Name 'AllowUnencryptedTraffic' -Value 0 -CISRef '18.9.52.1' -Description 'WinRM Client: No unencrypted'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'  -Name 'AllowDigest'             -Value 0 -CISRef '18.9.52.2' -Description 'WinRM Client: No Digest'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Value 0 -CISRef '18.9.53.1' -Description 'WinRM Service: No unencrypted'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs'            -Value 1 -CISRef '18.9.53.2' -Description 'WinRM Service: No RunAs'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS' -Name 'AllowRemoteShellAccess' -Value 0 -CISRef '18.9.54.1' -Description 'Disable Remote Shell'

# Windows Update
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1 -CISRef '18.9.56.1' -Description 'WU: No auto-restart'

# ===========================================================================
# Additional Hardening
# ===========================================================================
Write-LogSection 'Additional Hardening'

# CVE-2013-3900
foreach ($cp in @('HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Wintrust\Config')) {
    Set-HardenedRegistry -Path $cp -Name 'EnableCertPaddingCheck' -Value 1 -CISRef 'CVE-2013-3900' -Description 'WinVerifyTrust cert padding'
}

# Spectre / Meltdown
$mm = "HKLM:\SYSTEM\$CS\Control\Session Manager\Memory Management"
Set-HardenedRegistry -Path $mm -Name 'FeatureSettingsOverride'     -Value 0 -CISRef 'ADV180002' -Description 'Spectre/Meltdown: Enabled'
Set-HardenedRegistry -Path $mm -Name 'FeatureSettingsOverrideMask' -Value 3 -CISRef 'ADV180002' -Description 'Spectre/Meltdown: Mask'

# Misc
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride' -Value 1 -Description 'Disable WPAD'
Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'      -Name 'HideFileExt'  -Value 0 -Description 'Show file extensions'

# GPO-only items
Write-Log '-- GPO/Intune required (not applied by this script) --'
foreach ($g in @(
    'Section 1 - Account Policies -> secedit / Intune'
    'Section 2.2 - User Rights Assignment -> LGPO / Intune'
    'Section 17 - Advanced Audit Policy -> auditpol / GPO'
    'Section 18.9.7 - Defender ASR rules -> Intune Endpoint Security'
    'Section 19 - User Config -> User GPO / Intune'
)) { Write-Log "[GPO] $g" }

Write-LogSummary -ScriptName 'Set-CISL1Hardening'
Write-Host '  Run CIS-CAT Pro to validate gaps.' -ForegroundColor Yellow
Write-Host '  Reboot recommended.' -ForegroundColor Yellow
