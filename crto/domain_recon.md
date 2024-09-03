# Domain Reconnaissance Notes

**Powerview**

Commands to look into

```
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
powershell Get-Domain
powershell Get-DomainController | select Forest, Name, OSVersion | fl
powershell Get-ForestDomain
powershell Get-DomainPolicyData | select -expand SystemAccess
powershell Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl
powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName
powershell Get-DomainOU -Properties Name | sort -Property Name
powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName
powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName
powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName
powershell Get-DomainGPOLocalGroup | select GPODisplayName, GroupName
powershell Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select
powershell Get-DomainTrust
```

**SharpView**

A C# port of PowerView
```
execute-assembly C:\Tools\SharpView\SharpView\bin\Release\SharpView.exe Get-Domain
```

**ADSearch**

Additionally, the --json parameter can be used to format the output in JSON.

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user"
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))"
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member
```

