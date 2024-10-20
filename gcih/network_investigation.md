# Network Investigation Notes

reviewing access.log

```
grep midnitemeerkats access.log
awk '/midnitemeerkats/ {print $1, $3, $7}' access.log
TZ=America/Los_Angeles awk '/midnitemeerkats/ {print strftime("%T", $1), $3, $7}' access.log
./findbeacons.py  -i 5 -c 10 172.16.42.107 access.log
awk '/www1-google-analytics.com/ {print $3}' access.log | sort -u
grep www1-google-analytics.com access.log | head -n 1
tcpdump -nr falsimentis.pcap dst host 167.172.201.123 | cut -d ' ' -f 3 | cut -d '.' -f 1-4 | sort -u
for octet in 2 3 103 105 107 108 109; do TZ=PST7PDT tcpdump -tttt -n -r falsimentis.pcap -c 1 "src host 172.16.42.$octet and dst host 167.172.201.123" 2>/dev/null; done

```




