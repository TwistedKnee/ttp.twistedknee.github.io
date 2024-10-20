# DNS Interrogation Notes

with DIG

```
dig @172.30.0.254 A www.falsimentis.com
dig +short @172.30.0.254 A www.falsimentis.com
dig +short @172.30.0.254 AXFR falsimentis.com
dig +short @172.30.0.254 MX falsimentis.com
```

brute forcing dns names

```
sudo nmap --dns-servers 172.30.0.254 --script dns-brute --script-args dns-brute.domain=falsimentis.com
sudo nmap --dns-servers 172.30.0.254 --script dns-brute --script-args dns-brute.domain=falsimentis.com,dns-brute.hostlist=/home/sec504/labs/dns/namelist.txt
```

using a custom list

```
awk '{print "fm-"$1}' labs/dns/namelist.txt | head
awk '{print "fm-"$1}' labs/dns/namelist.txt > falsimentis-namelist.txt
sudo nmap --dns-servers 172.30.0.254 --script dns-brute --script-args dns-brute.domain=falsimentis.com,dns-brute.hostlist=falsimentix-namelist.txt
```

DNS Log analysis

```
head queries
awk '/172.30.0.1/ {print $2}' queries | cut -d: -f1-2 | uniq -c 
```
