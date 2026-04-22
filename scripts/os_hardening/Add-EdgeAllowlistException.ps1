#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
    [Parameter(Mandatory)]
    [string]$Url,

    [string]$TargetUser = 'KioskUser'
)

# Resolve SID
$userObj = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$TargetUser'"
if (-not $userObj) { throw "User '$TargetUser' not found" }

$regPath = "Registry::HKEY_USERS\$($userObj.SID)\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist"

if (-not (Test-Path $regPath)) {
    throw "URLAllowlist key does not exist — run the base policy script first."
}

# Find the next available index
$existing = Get-ItemProperty -Path $regPath
$nextIndex = 1
while ($null -ne $existing.PSObject.Properties[$nextIndex.ToString()]) {
    $nextIndex++
}

# Check for duplicates
$currentUrls = $existing.PSObject.Properties |
    Where-Object { $_.Name -match '^\d+$' } |
    Select-Object -ExpandProperty Value

if ($Url -in $currentUrls) {
    Write-Output "'$Url' is already in the allowlist."
    return
}

New-ItemProperty -Path $regPath -Name $nextIndex -Value $Url -PropertyType String -Force | Out-Null
Write-Output "Added '$Url' as entry $nextIndex in URLAllowlist."