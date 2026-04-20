# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

PowerShell scripts that harden a Windows 11 25H2 Enterprise image either **online** (against the running OS) or **offline** (against a mounted WIM/VHDX). Target build: 26200.x+. Baseline reference: CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1.

Four hardening scripts, one slipstream helper, one read-only pre-flight, one shared library:

- `ImageHardeningLib.ps1` — dot-sourced infrastructure. Do not run directly.
- `Invoke-Win11Debloat.ps1` — AppX/feature/service/task removal + consumer-experience registry.
- `Set-CISL1Hardening.ps1` — CIS L1 registry settings (security options, SMB, UAC, firewall, RDP, WinRM, etc.).
- `Set-BitLockerConfig.ps1` — FVE policy + optional encryption enable.
- `Set-CipherSuiteHardening.ps1` — SCHANNEL protocols/ciphers/hashes.
- `Update-Win11Image.ps1` — mounts `install.wim` (or reuses an existing mount) and slipstreams `.msu`/`.cab` packages from `-UpdatesPath` via `Add-WindowsPackage`. With `-FetchOnline` it pulls the newest non-preview monthly CU from the Microsoft Update Catalog using either `MSCatalog` or its maintained fork `MSCatalogLTS` (script auto-detects whichever is installed — both expose `Get-MSCatalogUpdate`/`Save-MSCatalogUpdate` with identical signatures). `-IncludeDotNet` adds the .NET Framework CU. Composable with the hardening pipeline: default leaves image mounted; `-Commit`/`-Discard` to finalize; `-Cleanup` runs `/StartComponentCleanup /ResetBase`. Pure DISM — doesn't use `Mount-OfflineHives`.
- `Get-PreDebloatManifest.ps1` — read-only dry-run reporter for the debloat script against a mounted image. Loads SYSTEM/SOFTWARE hives itself (not via the shared lib) and reports per-phase what would be removed/changed vs. what's already set. Writes no changes.

## Running

All scripts require `#Requires -RunAsAdministrator` and PowerShell 5.1+. They support `-WhatIf` (via `[CmdletBinding(SupportsShouldProcess)]`), `-Quiet`, and `-LogPath`.

```powershell
# Online (against running OS)
.\Set-CISL1Hardening.ps1
.\Set-CISL1Hardening.ps1 -WhatIf          # dry run
.\Invoke-Win11Debloat.ps1 -Quiet

# Offline (against a mounted image)
dism /Mount-WIM /WimFile:install.wim /Index:1 /MountDir:C:\Windows_Hardening\Mount
.\Set-CISL1Hardening.ps1     -OfflinePath C:\Windows_Hardening\Mount
.\Invoke-Win11Debloat.ps1    -OfflinePath C:\Windows_Hardening\Mount
.\Set-BitLockerConfig.ps1    -OfflinePath C:\Windows_Hardening\Mount   # policy only
.\Set-CipherSuiteHardening.ps1 -OfflinePath C:\Windows_Hardening\Mount
dism /Unmount-WIM /MountDir:C:\Windows_Hardening\Mount /Commit

# Full chained pipeline: slipstream CU + .NET, harden, cleanup, commit.
# Update-Win11Image.ps1 leaves the image mounted by default; later calls reuse it.
.\Update-Win11Image.ps1 -WimPath '.\...\sources\install.wim' -FetchOnline -IncludeDotNet
.\Invoke-Win11Debloat.ps1      -OfflinePath .\Mount
.\Set-CISL1Hardening.ps1       -OfflinePath .\Mount
.\Set-CipherSuiteHardening.ps1 -OfflinePath .\Mount
.\Update-Win11Image.ps1 -Cleanup -Commit

# BitLocker actually encrypts (online only); needs TPM
.\Set-BitLockerConfig.ps1 -EnableEncryption
.\Set-BitLockerConfig.ps1 -EnableEncryption -SkipRecoveryBackup   # disconnected builds
```

Logs land in `.\Logs\<ScriptName>.log` by default in CMTrace format.

## Architecture

Every hardening script follows the same skeleton — internalize this before editing one:

```powershell
. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-OfflineMode -OfflinePath $OfflinePath
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component '<ScriptName>'

$CS = if ($script:IsOffline) { 'ControlSet001' } else { 'CurrentControlSet' }

try {
    Mount-OfflineHives -Hives Both          # no-op when online
    # ... call Set-HardenedRegistry / Write-Log / Write-LogSection ...
}
finally { Dismount-OfflineHives }            # must run even on throw

Write-LogSummary -ScriptName '<ScriptName>'
```

### Online/offline abstraction

`ImageHardeningLib.ps1` makes the same registry-write code work in both modes:

- `Mount-OfflineHives` loads `Windows\System32\config\SOFTWARE` to `HKU\YOURIMG_SOFTWARE` and `SYSTEM` to `HKU\YOURIMG_SYSTEM` via `reg load`. Online: no-op.
- `Resolve-RegPath` rewrites `HKLM:\SOFTWARE\...` → `Registry::HKEY_USERS\YOURIMG_SOFTWARE\...` (and same for SYSTEM) when offline. Online: returns input unchanged.
- `Set-HardenedRegistry` calls `Resolve-RegPath` internally, so callers always write `HKLM:\...` paths regardless of mode. It is idempotent — reads existing value first, logs `SKIP` if unchanged, `APPLIED` if written.
- `Dismount-OfflineHives` does `[GC]::Collect()` + retry-with-backoff because lingering registry handles cause `reg unload` to fail.

The `$CS` pattern is the one thing scripts must handle themselves: online registry uses `CurrentControlSet`, offline hives only have `ControlSet001`. Always compute `$CS` after `Initialize-OfflineMode` and interpolate it into `HKLM:\SYSTEM\$CS\...` paths. A hardcoded `CurrentControlSet` will *silently* create a phantom subtree offline because `Resolve-RegPath` only rewrites the `HKLM:\SYSTEM` prefix — the literal `CurrentControlSet` segment is carried straight into the loaded hive, which only contains `ControlSet001`.

### Logging

`Write-Log` writes a CMTrace-compatible line to file and a colored line to console. Levels: `INFO`, `WARN`, `ERROR`, `SKIP`, `APPLIED`. Each level bumps a counter that `Write-LogSummary` prints at the end. Use `Write-LogSection 'Title'` for phase headers. Log files >5 MB are auto-rotated on init.

## Mode-specific gotchas

- **DISM vs. loaded hives.** `Remove-AppxProvisionedPackage`, `Disable-WindowsOptionalFeature`, `Get-AppxProvisionedPackage`, etc. open `SOFTWARE`/`SYSTEM` internally and fail with "being used by another process" if `Mount-OfflineHives` has `reg load`'ed those same files. In `Invoke-Win11Debloat.ps1`, the phase order is: Phase 1 (provisioned AppX removal, DISM) → Phase 1b (per-user `Get-AppxPackage -AllUsers`, **online-only**; skipped with a warn offline) → Phase 2 (optional features, DISM) — all three run *before* `Mount-OfflineHives`. Phases 3 (services) and 5 (registry) need the hives loaded. Any new offline script using DISM cmdlets must follow the same split — deviate from the CLAUDE.md skeleton.
- **Scheduled tasks have no offline API.** `Invoke-Win11Debloat.ps1` skips Phase 4 with a `WARN` when `-OfflinePath` is set. Do the same for any new task work — apply in audit mode instead.
- **AppX per-user cleanup is online-only** (`Get-AppxPackage -AllUsers` needs a running OS). Provisioned-package removal works in both modes via DISM.
- **`Set-BitLockerConfig.ps1 -EnableEncryption` is forced off when offline** (cannot run `Enable-BitLocker` against a mounted WIM). Phase 1 (FVE policy registry) still applies.
- **Per-user `HKCU` writes do not work offline** via this library — `Resolve-RegPath` only maps `HKLM:\SOFTWARE` and `HKLM:\SYSTEM`. Anything else falls through with a `WARN` and is written as-is (which means it goes to the *host's* registry when offline — be careful).

## Update-Win11Image — version-tag mapping

Microsoft's Update Catalog titles use "Version XXhY" based on the **base binary**, not the marketed release. 25H2 and 23H2 were shipped as enablement packages on top of 24H2 and 22H2 (same Germanium/Nickel kernels), so the monthly CU for a build 26200 image may be labeled "Version 24H2" in the catalog. `Get-Win11VersionTags` in the script returns tag candidates newest-first and `Invoke-CatalogFetch` tries each in turn. When MS ships a new enablement package (e.g. 26H1 built on 26100), extend the mapping.

Catalog results are filtered to drop `Preview` and `Dynamic Update` entries (setup-time only, not servicing). Keep this filter if you add new query paths.

## Pre-debloat manifest — list duplication

`Get-PreDebloatManifest.ps1` duplicates the target lists (`$AppxProtectList`, `$AppxAllowList`, `$FeaturesToDisable`, `$ServicesToDisable`, `$TasksToDisable`, `$RegistryTargets`) from `Invoke-Win11Debloat.ps1`. When editing any of those lists in the debloat script, update the manifest in lockstep or the dry-run report drifts silently. The manifest also re-implements `Test-AppxPatternMatch` — keep its semantics identical.

The manifest loads hives under *distinct* key names (`YOURIMG_MANIFEST_SYSTEM` / `YOURIMG_MANIFEST_SOFTWARE`) from the shared lib's `YOURIMG_SYSTEM` / `YOURIMG_SOFTWARE`. That isolation is deliberate — the manifest can run against the same mounted image concurrently with (or before) the hardening scripts without hive-handle collisions on `reg load`/`reg unload`.

## AppX removal — protect list precedence

`Invoke-Win11Debloat.ps1` evaluates `$AppxProtectList` **before** `$AppxAllowList` for both provisioned and per-user paths. Protect-list matches are absolute and skip the removal call entirely. This list exists because Windows guards certain platform packages with `0x80070032` on Build 26200 (shell, OOBE, credential UI, SmartScreen, framework runtimes, obfuscated `MicrosoftWindows.<digits>.<token>` Copilot/AI packages). When adding a package to the protect list, prefer to also drop it from the allow list — duplication is harmless but the protect list is what actually saves you if MS relaxes OS-level protection.

Pattern matching is `Test-AppxPatternMatch`: trailing `*` in a pattern is stripped and the result is matched as `*$pattern*` (substring), so wildcards in the middle of a pattern are not literal — they just become part of the substring.

## SCHANNEL gotcha

`Set-CipherSuiteHardening.ps1` uses `[uint32]::MaxValue` for the cipher/hash "enabled" sentinel, **not** the literal `0xFFFFFFFF`. In both PS 5.1 and 7.x, the literal parses as `Int32 -1` (high bit = sign bit) and `[uint32](-1)` throws. Don't "simplify" it.

When interpolating a variable immediately before a `:` inside a double-quoted string, use `${var}` form (e.g., `"${p} ${s}: Disabled"`) — bare `$p:` is parsed as a drive reference and errors with `InvalidVariableReferenceWithDrive`.

Cipher key names contain `/` (`DES 56/56`, `AES 128/128`, `RC2 40/128`, etc.), which the PowerShell registry provider cannot traverse — `New-Item`/`Set-ItemProperty` fail with "Cannot find path". `Set-HardenedRegistry` detects `/` in the leaf segment and transparently falls back to `Set-HardenedRegistryNet`, which uses the `[Microsoft.Win32.Registry]` .NET API. The fallback handles DWord uint32↔int32 round-tripping via `BitConverter` so `[uint32]::MaxValue` is stored as the correct `0xFFFFFFFF` bit pattern and idempotency-compared correctly. Don't call `Set-HardenedRegistryNet` directly; it's an internal fallback.

## Editing conventions

- Scripts run with `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`. New code must handle `$null` explicitly and wrap external calls (`Get-Service`, `Get-AppxPackage`, DISM cmdlets, etc.) in `try/catch` that downgrades expected failures to `Write-Log -Level WARN` rather than throwing.
- Every registry write should go through `Set-HardenedRegistry` so the offline-path rewrite, idempotency check, and CIS-ref logging work uniformly. Pass `-CISRef` for CIS-mapped settings, `-Description` always.
- The `Mount-OfflineHives` / `Dismount-OfflineHives` pair must always be inside `try { } finally { }` — orphaned hive loads block subsequent runs.
- Default `LogPath` is computed from `$PSScriptRoot`, so scripts work when invoked from any CWD. Preserve that pattern when adding new scripts.
