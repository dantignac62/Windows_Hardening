#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Configuration ----------
$TargetUser = 'KioskUser'  # your autologin account
$BlockList  = @('*')
$AllowList  = @(
    'example.com'
    'login.microsoftonline.com'
    '*.microsoft.com'
)

# ---------- Resolve SID ----------
$userObj = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$TargetUser'"
if (-not $userObj) { throw "User '$TargetUser' not found" }
$sid = $userObj.SID

# Verify hive is loaded
if (-not (Test-Path "Registry::HKEY_USERS\$sid")) {
    throw "Hive for $TargetUser ($sid) is not loaded — is the user logged in?"
}

# ---------- Helper ----------
function Set-EdgeUrlPolicy {
    [CmdletBinding()]
    param(
        [string]$SID,
        [string]$PolicyName,
        [string[]]$Urls
    )

    $regPath = "Registry::HKEY_USERS\$SID\SOFTWARE\Policies\Microsoft\Edge\$PolicyName"

    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force
    }
    New-Item -Path $regPath -Force | Out-Null

    for ($i = 0; $i -lt $Urls.Count; $i++) {
        New-ItemProperty -Path $regPath -Name ($i + 1) -Value $Urls[$i] -PropertyType String -Force | Out-Null
    }

    Write-Output "  $PolicyName : $($Urls.Count) entries"
}

# ---------- Apply ----------
Write-Output "Applying Edge URL policies for $TargetUser ($sid)..."
Set-EdgeUrlPolicy -SID $sid -PolicyName 'URLBlocklist' -Urls $BlockList
Set-EdgeUrlPolicy -SID $sid -PolicyName 'URLAllowlist' -Urls $AllowList
Write-Output 'Done.'