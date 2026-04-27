So on one challenge where we use analyze and tcpdump to get data we had to extract just source IP's, solution I created was:

```
analyze -s "2019/05/01 10:00:00" -e "2019/05/01 15:00:00" backbone | tcpdump -r - -n | awk '/ IP / {print $3 }' | cut -f 1,2,3,4 -d '.' | sort -rn | uniq | wc -l
```

see how many ipv6 addresses are in the packet captures: 
`
```
analyze -s "2019/05/01 10:00:00" -e "2019/05/01 14:00:00" backbone | tcpdump -r - -n ip6 | wc -l
```

checking for destination hosts over udp:

```
analyze -s "2019/05/01 10:00:00" -e "2019/05/01 14:00:00" backbone | tcpdump -r - -n udp | awk '/ IP / {print $5 }' | cut -f 1,2,3,4 -d '.' | sort -rn | uniq | wc -l
```

getting the highest udp destination port number:

```
analyze -s "2019/05/01 10:00:00" -e "2019/05/01 14:00:00" backbone | tcpdump -r - -n udp | awk '/ IP / {print $5 }' | cut -f 5 -d '.' | sort -rn | uniq -c
```

only search for SYN packets and nothing else:

```
analyze -s "2019/05/01 10:00:00" -e "2019/05/01 14:00:00" backbone | tcpdump -r - 'tcp[13] = 0x02' | wc -l
```

How many TCP packets with only the SYN bit set and which are destined to external hosts are seen by the backbone sensor between 10:00:00 and 14:00:00 on May 1, 2019

```
analyze -s "2019/05/01 10:00:00" -e "2019/05/01 14:00:00" backbone | tcpdump -r - 'tcp[13] = 0x02' | wc -l
```

get SYN packets not going to internal hosts:
```
analyze -s "2019/05/01 10:00:00" -e "2019/05/01 14:00:00" backbone | tcpdump -r - 'tcp[13] = 0x02 and (dst net not 192.168)' | wc -l
```

do the same for dmz backbone:
```
analyze -s "2019/05/01 00:00:00" -e "2019/05/04 00:00:00" dmz | tcpdump -r - 'tcp[13] = 0x02 and (dst net not 10.200.200.0/24 and dst net not 192.168/16 and dst net not 172.16.0.0/12)' | wc -l
```

find all perimeter packets with SYN without caring for ECN: 
```
analyze -s "2019/05/01 00:00:00" -e "2019/05/04 00:00:00" perimeter | tcpdump -r - 'tcp[13] &0x3f = 0x02' | wc -l
```

find all SYN packets with ECN:
```
analyze -s "2019/05/01 00:00:00" -e "2019/05/04 00:00:00" perimeter | tcpdump -r - 'tcp[13] = 0x02' | wc -l
```

find how many unique TCP service ports there are without ECN in consideration:
```
analyze -s "2019/05/01 10:00:00" -e "2019/05/01 14:00:00" backbone | tcpdump -nr - 'tcp[13] &0x3f = 0x02' | awk '/ IP / {print $5}' | cut -f 5 -d '.' | sort -rn | uniq | wc -l
```

get all services that are listening from the external IP range, this means search only for SYN/ACK packets:
```
analyze -s "2019/05/01 00:00:00" -e "2019/05/04 00:00:00" external | tcpdump -nr - 'tcp[13] &0x3f = 0x12 and src net 170.129.0.0/16' | awk '/ IP / {print $3}' | cut -f 5 -d '.' | sort -rn | uniq
```

Examine the backbone data for the time period from May 1, 2019 at 00:00:00 to May 4, 2019 at 00:00:00. How many internal hosts have responding TCP services that indicate that the service is available?
```
analyze -s "2019/05/01 00:00:00" -e "2019/05/04 00:00:00" backbone | tcpdump -n -r - 'tcp[13] &0x3f=0x12 and src host 192.168' | cut -f 3 -d " " | sort -rn | uniq | cut -f 1,2,3,4 -d "." | sort -rn | uniq
```

Examine the backbone data for the time period from May 1, 2019 at 00:00:00 to May 4, 2019 at 00:00:00. How many TCP ports have responding services from internal hosts?
```
analyze -s "2019/05/01 00:00:00" -e "2019/05/04 00:00:00" backbone | tcpdump -n -r - 'tcp[13] &0x3f=0x12 and src host 192.168' | cut -f 3 -d " " | sort -rn | uniq | cut -f 5 -d "." | sort -rn | uniq | wc -l
```

How many different SYN ACK responses originate in the 192.168.0.0/16 from TCP port 111 as seen by the backbone sensor between 00:00:00 on May 1, 2019 and 00:00:00 on May 4, 2019?
```
analyze -s "2019/05/01 00:00:00" -e "2019/05/04 00:00:00" backbone | tcpdump -n -r - 'tcp[13] &0x3f=0x12 and src host 192.168 and src port 111' | wc -l
```

you must extract all of the TCP port 111 packets that involve any host on the 192.168.0.0/16 network from the backbone sensor between May 1 and May 4 of 2019. After you have done so, determine the length of this file in bytes according to the ls -l command.

What is the size in bytes of the file containing all of the TCP port 111 packets that you have extracted?
```
analyze -s "2019/05/01 00:00:00" -e "2019/05/04 00:00:00" backbone | tcpdump -n -r - 'net 192.168 and port 111' -w port111stuff.pcap
```