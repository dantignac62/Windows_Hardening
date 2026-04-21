Repository Structure
.
├── README.md
├── ImageHardeningLib.ps1      # Shared library module (logging, registry helpers, offline mount support)
├── 01-BaselineRegistry.ps1    # <!-- brief description -->
├── 02-ServiceHardening.ps1    # <!-- brief description -->
├── 03-AuditPolicy.ps1         # <!-- brief description -->
└── 04-FirewallBaseline.ps1    # <!-- brief description -->
<!-- Update filenames and descriptions to match your actual scripts -->
Prerequisites

Target OS: Windows 11 25H2 Enterprise (x64)
PowerShell: 7.x recommended; 5.1 compatible <!-- adjust if not dual-target -->
Execution context: Run as SYSTEM or local Administrator
Offline imaging: Requires a mounted WIM (DISM) with the mount path passed as a parameter

Usage
Live OS (running system)
powershellSet-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\01-BaselineRegistry.ps1
.\02-ServiceHardening.ps1
.\03-AuditPolicy.ps1
.\04-FirewallBaseline.ps1

Idempotency
All scripts are safe to re-run. Existing settings that already match the target state are skipped.
What Gets Hardened
CategoryExamples
Registry policy<!-- e.g., credential caching, SMBv1 disabled, NTLMv2 enforced -->
Services<!-- e.g., unnecessary services disabled, startup types set -->
Audit policy<!-- e.g., advanced audit subcategories configured -->
Firewall<!-- e.g., inbound deny default, baseline allow rules -->
