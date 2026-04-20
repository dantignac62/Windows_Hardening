#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Mounts install.wim and slipstreams monthly cumulative updates into it.
    Composable: leaves the image mounted by default; call again with
    -Cleanup / -Commit or -Discard to finalize.

.DESCRIPTION
    Pure DISM-based servicing. Does NOT use Mount-OfflineHives or
    Resolve-RegPath from ImageHardeningLib — registry hive access is not
    needed for package slipstreaming.

    Three package source modes (evaluated in priority order):

      1. -UpdatesPath set  : apply .msu/.cab files from that folder.
      2. -FetchOnline      : fetch the newest non-preview monthly CU
                             from the Microsoft Update Catalog using the
                             MSCatalogLTS or MSCatalog PSGallery module
                             (whichever is installed; identical surface).
                             See: https://www.powershellgallery.com/packages/MSCatalogLTS
      3. Neither set       : skip package application (useful for Cleanup/Commit
                             only runs or to pre-position the mount).

    Catalog search notes:
      - Build 26200 (25H2) shares the Germanium binary tree with 26100
        (24H2). The monthly CU for a 26200 image is typically labeled
        "Version 25H2" in the catalog, but the fallback tag "24H2" is
        tried if no results are returned for "25H2".
      - Preview and Dynamic Update catalog entries are always excluded.
      - Results are sorted newest-first by LastUpdated and the top entry
        is downloaded.

    Execution phases (all optional; controlled by switches):
      Mount   : -WimPath/-MountPath
      Apply   : -UpdatesPath / -FetchOnline / -IncludeDotNet
      Cleanup : -Cleanup (DISM /StartComponentCleanup /ResetBase)
      Commit  : -Commit
      Discard : -Discard

    Mount reuse: if $MountPath already has an image mounted (detected via
    Get-WindowsImage -Mounted), the mount step is skipped and the existing
    mount is used. This enables the composable pattern documented in CLAUDE.md:
      .\Update-Win11Image.ps1 -WimPath ... -FetchOnline -IncludeDotNet
      .\Invoke-Win11Debloat.ps1     -OfflinePath .\Mount
      .\Set-CISL1Hardening.ps1      -OfflinePath .\Mount
      .\Set-CipherSuiteHardening.ps1 -OfflinePath .\Mount
      .\Update-Win11Image.ps1 -Cleanup -Commit

.PARAMETER WimPath
    Path to the install.wim to service. Defaults to the value of
    $DefaultWimPath in ImageHardeningLib.ps1.

.PARAMETER MountPath
    Directory to mount the image under. Created if missing. Defaults to
    $DefaultMountPath in ImageHardeningLib.ps1.

.PARAMETER WimIndex
    WIM image index to mount. Default: 1.

.PARAMETER UpdatesPath
    Folder of pre-downloaded .msu/.cab files. Applied via Add-WindowsPackage
    with DISM handling SSU+LCU dependency ordering automatically.

.PARAMETER FetchOnline
    Query the Microsoft Update Catalog and download the latest non-preview
    monthly CU. Requires MSCatalogLTS or MSCatalog module.

.PARAMETER IncludeDotNet
    Also fetch and apply the latest .NET Framework cumulative update for
    the image's OS build. Only used with -FetchOnline.

.PARAMETER DownloadPath
    Destination for catalog-fetched MSUs. Created if missing.
    Default: .\Downloads

.PARAMETER Cleanup
    Run DISM /StartComponentCleanup /ResetBase on the mounted image
    before committing. Reduces WIM size; cannot be undone.

.PARAMETER Commit
    Commit and unmount the image after all operations complete.

.PARAMETER Discard
    Discard changes and unmount. Mutually exclusive with -Commit.

.PARAMETER Quiet
    Suppress console output. Log file still written.

.PARAMETER LogPath
    CMTrace log path. Default: .\Logs\Update-Win11Image.log

.NOTES
    Version : 1.0.0 | Date: 2026-04-20
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Deps    : MSCatalogLTS or MSCatalog (PSGallery) when using -FetchOnline.
              Install: Install-Module MSCatalogLTS -Scope CurrentUser
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$WimPath,
    [string]$MountPath,
    [int]$WimIndex = 1,
    [string]$UpdatesPath,
    [switch]$FetchOnline,
    [switch]$IncludeDotNet,
    [string]$DownloadPath = (Join-Path $PSScriptRoot 'Downloads'),
    [switch]$Cleanup,
    [switch]$Commit,
    [switch]$Discard,
    [switch]$Quiet,
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs\Update-Win11Image.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Parameter validation ------------------------------------------

if ($Commit -and $Discard) {
    throw '-Commit and -Discard are mutually exclusive.'
}
if ($UpdatesPath -and $FetchOnline) {
    throw '-UpdatesPath and -FetchOnline are mutually exclusive. Choose one package source.'
}

# ---------- Library setup (logging only) ----------------------------------

. "$PSScriptRoot\ImageHardeningLib.ps1"
# Apply defaults from lib if caller didn't override.
if (-not $WimPath)   { $WimPath   = $script:DefaultWimPath }
if (-not $MountPath) { $MountPath = $script:DefaultMountPath }

Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Update-Win11Image'
Write-Log "WimPath   : $WimPath"
Write-Log "MountPath : $MountPath"
Write-Log "WimIndex  : $WimIndex"

# ---------- Catalog module detection (FetchOnline only) ------------------

$catalogModule = $null
if ($FetchOnline) {
    foreach ($modName in @('MSCatalogLTS', 'MSCatalog')) {
        if (Get-Module -Name $modName -ListAvailable -ErrorAction SilentlyContinue) {
            $catalogModule = $modName
            try { Import-Module $modName -ErrorAction Stop }
            catch { throw "Found module $modName but import failed: $($_.Exception.Message)" }
            Write-Log "Catalog module: $modName"
            break
        }
    }
    if (-not $catalogModule) {
        throw '-FetchOnline requires MSCatalogLTS or MSCatalog from PSGallery. ' +
              'Run: Install-Module MSCatalogLTS -Scope CurrentUser'
    }
}

# ---------- Helpers -------------------------------------------------------

function Get-Win11VersionTags {
    # Returns catalog version tag candidates newest-first for a given build.
    # 26200 (25H2) is built on the same Germanium binary as 26100 (24H2);
    # the CU may be cataloged under either tag. Try newest first.
    param([int]$Build)
    if ($Build -ge 26200) { return @('25H2', '24H2') }
    if ($Build -ge 26100) { return @('24H2') }
    if ($Build -ge 22631) { return @('23H2') }
    if ($Build -ge 22621) { return @('22H2') }
    return @()
}

function Invoke-CatalogFetch {
    # Downloads the latest non-preview monthly CU for the given version tags.
    # Returns the full path of the downloaded MSU, or $null if not found.
    param(
        [Parameter(Mandatory)][string[]]$VersionTags,
        [Parameter(Mandatory)][string]$DownloadDir,
        [string]$ArchString = 'x64'   # as it appears in catalog titles
    )

    if (-not (Test-Path -LiteralPath $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    foreach ($tag in $VersionTags) {
        $query = "Cumulative Update for Windows 11 Version $tag"
        Write-Log "Catalog search: '$query'"
        try {
            $results = @(Get-MSCatalogUpdate -Search $query -ErrorAction Stop)
        }
        catch {
            Write-Log "Catalog query failed for '$query': $($_.Exception.Message)" -Level WARN
            continue
        }

        # Filter: must match architecture, exclude Preview, Dynamic Update.
        $filtered = $results | Where-Object {
            $t = $_.Title
            $t -match $ArchString -and
            $t -notmatch '(?i)\bPreview\b' -and
            $t -notmatch '(?i)\bDynamic Update\b'
        }

        if (-not $filtered) {
            Write-Log "No results for tag '$tag' after filtering." -Level WARN
            continue
        }

        # Sort newest-first. LastUpdated is typically a [datetime] or parseable string.
        $selected = $filtered | Sort-Object -Property LastUpdated -Descending | Select-Object -First 1
        Write-Log "Selected: $($selected.Title)"

        if (-not $PSCmdlet.ShouldProcess($DownloadDir, "Download $($selected.Title)")) {
            Write-Log "WhatIf: would download $($selected.Title)" -Level SKIP
            return $null
        }

        try {
            Save-MSCatalogUpdate -Update $selected -Destination $DownloadDir -ErrorAction Stop
            # Find the MSU just written (newest by LastWriteTime).
            $msu = Get-ChildItem -LiteralPath $DownloadDir -Filter '*.msu' |
                   Sort-Object LastWriteTime -Descending |
                   Select-Object -First 1
            if ($msu) {
                Write-Log "Downloaded: $($msu.FullName)" -Level APPLIED
                return $msu.FullName
            }
        }
        catch {
            Write-Log "Download failed for '$($selected.Title)': $($_.Exception.Message)" -Level WARN
        }
    }

    Write-Log 'No CU downloaded after trying all version tags.' -Level WARN
    return $null
}

function Invoke-DotNetCatalogFetch {
    # Downloads the latest .NET Framework CU for the image's build.
    # Uses the same filter/sort pattern as Invoke-CatalogFetch.
    param(
        [Parameter(Mandatory)][string[]]$VersionTags,
        [Parameter(Mandatory)][string]$DownloadDir,
        [string]$ArchString = 'x64'
    )

    if (-not (Test-Path -LiteralPath $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    foreach ($tag in $VersionTags) {
        $query = ".NET Framework Windows 11 Version $tag"
        Write-Log "Catalog search (.NET): '$query'"
        try {
            $results = @(Get-MSCatalogUpdate -Search $query -ErrorAction Stop)
        }
        catch {
            Write-Log "Catalog query (.NET) failed for '$query': $($_.Exception.Message)" -Level WARN
            continue
        }

        $filtered = $results | Where-Object {
            $t = $_.Title
            $t -match $ArchString -and
            $t -notmatch '(?i)\bPreview\b' -and
            $t -notmatch '(?i)\bDynamic Update\b'
        }
        if (-not $filtered) { continue }

        $selected = $filtered | Sort-Object -Property LastUpdated -Descending | Select-Object -First 1
        Write-Log "Selected (.NET): $($selected.Title)"

        if (-not $PSCmdlet.ShouldProcess($DownloadDir, "Download .NET $($selected.Title)")) {
            Write-Log "WhatIf: would download .NET $($selected.Title)" -Level SKIP
            return $null
        }

        try {
            Save-MSCatalogUpdate -Update $selected -Destination $DownloadDir -ErrorAction Stop
            $msu = Get-ChildItem -LiteralPath $DownloadDir -Filter '*.msu' |
                   Sort-Object LastWriteTime -Descending |
                   Select-Object -First 1
            if ($msu) {
                Write-Log "Downloaded (.NET): $($msu.FullName)" -Level APPLIED
                return $msu.FullName
            }
        }
        catch {
            Write-Log "Download failed for .NET '$($selected.Title)': $($_.Exception.Message)" -Level WARN
        }
    }

    Write-Log 'No .NET CU downloaded.' -Level WARN
    return $null
}

# ---------- Phase 1: Mount ------------------------------------------------
Write-LogSection 'Phase 1: Mount'

# Check for existing mount at $MountPath.
$existingMount = $null
try {
    $existingMount = Get-WindowsImage -Mounted -ErrorAction Stop |
                     Where-Object { $_.MountPath -eq $MountPath }
}
catch { Write-Log "Get-WindowsImage -Mounted failed: $($_.Exception.Message)" -Level WARN }

if ($existingMount) {
    Write-Log "Reusing existing mount: $MountPath (WIM=$($existingMount.ImagePath) Index=$($existingMount.ImageIndex) Status=$($existingMount.MountStatus))" -Level SKIP
    if ($existingMount.MountStatus -ne 'Ok') {
        Write-Log "Mount status is '$($existingMount.MountStatus)'. Run DISM /Remount-WIM before continuing." -Level ERROR
        Write-LogSummary -ScriptName 'Update-Win11Image'
        exit 1
    }
} else {
    if (-not (Test-Path -LiteralPath $WimPath)) {
        Write-Log "WIM not found: $WimPath" -Level ERROR
        Write-LogSummary -ScriptName 'Update-Win11Image'
        exit 1
    }
    if (-not (Test-Path -LiteralPath $MountPath)) {
        New-Item -ItemType Directory -Path $MountPath -Force | Out-Null
        Write-Log "Created mount directory: $MountPath"
    }

    Write-Log "Mounting $WimPath (Index $WimIndex) -> $MountPath"
    if ($PSCmdlet.ShouldProcess($MountPath, "Mount-WindowsImage Index $WimIndex")) {
        try {
            Mount-WindowsImage -ImagePath $WimPath -Index $WimIndex -Path $MountPath -ErrorAction Stop | Out-Null
            Write-Log "Mounted successfully." -Level APPLIED
        }
        catch {
            Write-Log "Mount-WindowsImage failed: $($_.Exception.Message)" -Level ERROR
            Write-LogSummary -ScriptName 'Update-Win11Image'
            exit 1
        }
    } else {
        Write-Log "WhatIf: would mount $WimPath" -Level SKIP
    }
}

# Read the image's build number for catalog queries.
$imageInfo = $null
try { $imageInfo = Get-WindowsImage -Mounted -ErrorAction Stop | Where-Object { $_.MountPath -eq $MountPath } }
catch { }
$imageBuild = 0
if ($imageInfo -and $imageInfo.Version) {
    try { $imageBuild = [int]([version]$imageInfo.Version).Build } catch { }
}
Write-Log "Image build: $imageBuild"
$versionTags = Get-Win11VersionTags -Build $imageBuild

# ---------- Phase 2: Fetch packages (FetchOnline) -------------------------

$fetchedPaths = New-Object System.Collections.Generic.List[string]
if ($FetchOnline) {
    Write-LogSection 'Phase 2: Fetch from Catalog'

    $cuPath = Invoke-CatalogFetch -VersionTags $versionTags -DownloadDir $DownloadPath
    if ($cuPath) { $fetchedPaths.Add($cuPath) }

    if ($IncludeDotNet) {
        $dotNetPath = Invoke-DotNetCatalogFetch -VersionTags $versionTags -DownloadDir $DownloadPath
        if ($dotNetPath) { $fetchedPaths.Add($dotNetPath) }
    }
} else {
    Write-LogSection 'Phase 2: Package Source'
    Write-Log '-FetchOnline not set; skipping catalog fetch.' -Level SKIP
}

# ---------- Phase 3: Apply packages ---------------------------------------
Write-LogSection 'Phase 3: Apply Packages'

# Build the list of source paths. MsuSourcePath (single folder containing
# multiple MSUs) or FetchOnline-downloaded individual MSUs both route through
# Add-WindowsPackage. Passing a folder lets DISM order SSU+LCU correctly.

if ($UpdatesPath) {
    if (-not (Test-Path -LiteralPath $UpdatesPath)) {
        Write-Log "UpdatesPath not found: $UpdatesPath" -Level ERROR
    } else {
        $pkgCount = @(Get-ChildItem -LiteralPath $UpdatesPath -File -Recurse -Include '*.msu','*.cab').Count
        Write-Log "Applying folder: $UpdatesPath ($pkgCount package(s))"
        if ($PSCmdlet.ShouldProcess($MountPath, "Add-WindowsPackage from $UpdatesPath")) {
            try {
                Add-WindowsPackage -Path $MountPath -PackagePath $UpdatesPath `
                                   -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                Write-Log "Applied packages from $UpdatesPath." -Level APPLIED
            }
            catch { Write-Log "Add-WindowsPackage failed: $($_.Exception.Message)" -Level ERROR }
        } else { Write-Log "WhatIf: would apply packages from $UpdatesPath" -Level SKIP }
    }
}
elseif ($fetchedPaths.Count -gt 0) {
    foreach ($pkg in $fetchedPaths) {
        Write-Log "Applying: $pkg"
        if ($PSCmdlet.ShouldProcess($MountPath, "Add-WindowsPackage $pkg")) {
            try {
                Add-WindowsPackage -Path $MountPath -PackagePath $pkg `
                                   -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                Write-Log "Applied: $(Split-Path $pkg -Leaf)" -Level APPLIED
            }
            catch { Write-Log "Add-WindowsPackage failed for ${pkg}: $($_.Exception.Message)" -Level ERROR }
        } else { Write-Log "WhatIf: would apply $pkg" -Level SKIP }
    }
} else {
    Write-Log 'No packages to apply.' -Level SKIP
}

# ---------- Phase 4: Cleanup (optional) -----------------------------------

if ($Cleanup) {
    Write-LogSection 'Phase 4: Component Cleanup'
    Write-Log 'Running DISM /StartComponentCleanup /ResetBase (irreversible).'
    if ($PSCmdlet.ShouldProcess($MountPath, 'Repair-WindowsImage -StartComponentCleanup -ResetBase')) {
        try {
            Repair-WindowsImage -Path $MountPath -StartComponentCleanup -ResetBase -ErrorAction Stop | Out-Null
            Write-Log 'Component cleanup complete.' -Level APPLIED
        }
        catch { Write-Log "Component cleanup failed: $($_.Exception.Message)" -Level ERROR }
    } else { Write-Log 'WhatIf: would run StartComponentCleanup /ResetBase' -Level SKIP }
} else {
    Write-LogSection 'Phase 4: Component Cleanup'
    Write-Log '-Cleanup not set; skipping.' -Level SKIP
}

# ---------- Phase 5: Unmount (optional) -----------------------------------

Write-LogSection 'Phase 5: Unmount'
if ($Commit) {
    Write-Log "Committing and unmounting: $MountPath"
    if ($PSCmdlet.ShouldProcess($MountPath, 'Dismount-WindowsImage -Save')) {
        try {
            Dismount-WindowsImage -Path $MountPath -Save -ErrorAction Stop | Out-Null
            Write-Log 'Image committed and unmounted.' -Level APPLIED
        }
        catch { Write-Log "Dismount (commit) failed: $($_.Exception.Message)" -Level ERROR }
    } else { Write-Log 'WhatIf: would dismount with /Commit' -Level SKIP }
}
elseif ($Discard) {
    Write-Log "Discarding changes and unmounting: $MountPath"
    if ($PSCmdlet.ShouldProcess($MountPath, 'Dismount-WindowsImage -Discard')) {
        try {
            Dismount-WindowsImage -Path $MountPath -Discard -ErrorAction Stop | Out-Null
            Write-Log 'Image discarded and unmounted.' -Level APPLIED
        }
        catch { Write-Log "Dismount (discard) failed: $($_.Exception.Message)" -Level ERROR }
    } else { Write-Log 'WhatIf: would dismount with /Discard' -Level SKIP }
}
else {
    Write-Log "Image remains mounted at $MountPath. Call -Commit or -Discard to finalize." -Level SKIP
}

Write-LogSummary -ScriptName 'Update-Win11Image'

if ($script:Counters.Errors -gt 0) { exit 1 }
exit 0
