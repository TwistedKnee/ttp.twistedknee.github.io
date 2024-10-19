# Live Windows Examination with PowerShell

In PowerShell:

setup:

```
cd C:\Tools\LiveInvestigation\
.\live-investigation-setup.ps1
```

Process Enumeration:

```
Get-Process
Get-Process lsass
Get-Process lsass | Select-Object -Property *
Get-Process |Select-Object -Property Path, Name, Id
Get-Process |Select-Object -Property Path, Name, Id | Where-Object -Property Name -eq explorer
Get-Process |Select-Object -Property Path, Name, Id | Where-Object -Property Path -Like "*temp*"
```

Network Enumeration

```
Get-NetTCPConnection
Get-NetTCPConnection |Select-Object -Property localaddress, localport, state, owningprocess
Get-Process | Select-Object -Property Path,name,id | Where-Object -Property id -eq <PID>
Get-Process | Select-Object -Property Path,name,id | Where-Object -Property id -eq 5440 | Stop-Process
Get-Process calcache
```

Registry Startup Keys

```
Get-ChildItem HKCU:
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Calcache"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Calcache"
Remove-Item $env:temp\calcache.exe
Get-ChildItem $env:temp\calcache.exe
```

## Differential Analysis
```
Get-ChildItem baseline
Get-Service |Select-Object -ExpandProperty name |Out-File services.txt
Get-ScheduledTask |Select-Object -ExpandProperty name |Out-File localusers.txt
Get-LocalUser |Select-Object -ExpandProperty name |Out-File scheduledtasks.txt\
```

### Services differential analysis

```
Get-Content .\services.txt -First 10
$servicesnow = Get-Content .\services.txt
$servicesbaseline = Get-Content .\baseline\services.txt
Compare-Object $servicesbaseline $servicesnow
```

### Users differential analysis

```
$usersnow = Get-Content .\localusers.txt
$usersbaseline = Get-Content .\baseline\localusers.txt
Compare-Object $usersbaseline $usersnow
```

### Scheduled tasks differential analysis

```
Get-ScheduledTask
$scheduledtasksnow = Get-Content .\scheduledtasks.txt
$scheduledtasksbaseline = Get-Content .\baseline\scheduledtasks.txt
Compare-Object $scheduledtasksbaseline $scheduledtasksnow
```

## Scheduled task detail

```
Export-ScheduledTask -TaskName "Microsoft eDynamics"
### Removal
Stop-Service -Name Dynamics
Get-Process dynamics |Stop-Process
Remove-Item C:\Windows\Dynamics.exe
sc.exe delete dynamics
Unregister-ScheduledTask -TaskName "Microsoft eDynamics"
Remove-LocalUser -Name dynamics
.\live-investigation-teardown.ps1
```

## Bonus

```
Get-NetTCPConnection -State Listen | Out-File tcpports-baseline.txt
Get-NetTCPConnection -State Listen >tcpports-current.txt
$baseline = Get-Content .\tcpports-baseline.txt
$current = Get-Content .\tcpports-current.txt
Compare-Object $baseline $current
Get-NetTCPConnection -State Listen | Where-Object -Property LocalPort -eq <port> | Select-Object -Property OwningProcess
Get-CimInstance -Class Win32_process | Where-Object -Property ProcessId -eq <PID>
Get-CimInstance -Class Win32_process | Where-Object -Property ProcessId -eq 3584 | Select-Object -Property ParentProcessId
nc 127.0.0.1 <port>
Get-NetTCPConnection -State Listen | Where-Object -Property OwningProcess -eq 3584 | Select-Object LocalPort
Get-Process |Where-Object -Property id -eq <parentprocesPID>
Get-Process -id 6676
Get-Process -id 6676 |Stop-Process
Get-Process -name powershell
Get-Process -name powershell | Select-Object id, starttime
Get-CimInstance -Class Win32_Process | Where-Object -Property ProcessId -eq <PID> | Select-Object -ExpandProperty CommandLine

```




