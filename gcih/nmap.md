# NMAP Notes

```
sudo nmap --reason 127.0.0.1
sudo nmap --reason -p 1-1024 127.0.0.1
sudo nmap --reason -p- 127.0.0.1
sudo nmap -sV --reason -p 5433,5443,9001,9002 127.0.0.1
```

scripts

```
nmap --script-help "http-*"
nmap --script-help "http*" | grep "^http-"
nmap --script-help http-git
sudo nmap -p 9001 --script http-git 127.0.0.1
sudo nmap -sV -p 9001 --script http-git 127.0.0.1
```

aggressive scanning
```
sudo nmap -A -p 5433,5443,9001,9002 127.0.0.1
```

bonus

```
nmap 127.0.0.1 -oX baseline.xml
sudo service ssh start
nmap 127.0.0.1 -oX newscan.xml
ndiff baseline.xml newscan.xml
sudo service ssh stop
```
