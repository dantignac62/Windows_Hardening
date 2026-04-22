#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Ensure Application Identity service is running (required for AppLocker) ----
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc

# ---- AppLocker Policy ----
# Default-deny model: only explicitly allowed paths run for non-admins.
# Admins get unrestricted execution. Non-admins can only execute from
# %WINDIR% and %PROGRAMFILES%, which naturally blocks %APPDATA%,
# %LOCALAPPDATA%, %TEMP%, Downloads, Desktop, etc.

$policyXml = @'
<AppLockerPolicy Version="1">

  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="Admins: all executables"
                  Description="Allow Administrators to run all executables."
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51"
                  Name="Everyone: Windows directory"
                  Description="Allow Everyone to run executables in the Windows directory."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="Everyone: Program Files"
                  Description="Allow Everyone to run executables in Program Files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473"
                  Name="Admins: all MSI files"
                  Description="Allow Administrators to run all MSI files."
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54"
                  Name="Everyone: Windows Installer directory"
                  Description="Allow Everyone to run MSI files from the Windows Installer directory."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\Installer\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d"
                  Name="Admins: all scripts"
                  Description="Allow Administrators to run all scripts."
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c"
                  Name="Everyone: Windows directory scripts"
                  Description="Allow Everyone to run scripts in the Windows directory."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="d2ec3484-4045-4241-8300-4a31b4c3acf4"
                  Name="Everyone: Program Files scripts"
                  Description="Allow Everyone to run scripts in Program Files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Appx" EnforcementMode="Enabled">
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
                       Name="Everyone: all signed packaged apps"
                       Description="Allow all signed packaged apps."
                       UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>

</AppLockerPolicy>
'@

# ---- Apply ----
Set-AppLockerPolicy -XmlPolicy $policyXml
Write-Output 'AppLocker policy applied.'

# ---- Verify ----
$effective = Get-AppLockerPolicy -Effective
foreach ($collection in $effective.RuleCollections) {
    Write-Output "`n$($collection.RuleCollectionType): $($collection.Count) rules (Enforcement: $($collection.EnforcementMode))"
}