## Day 1 

1. `tcpdump -r concepts.pcap`
2. don't resolve IP addresses: `tcpdump -r concepts.pcap -n`
3. Run tcpdump and read the first two records of the input file concepts.pcap `tcpdump -r concepts.pcap -ntc 2`
4. read the first record of the input file concepts.pcap, and display it in hexadecimal `tcpdump -r concepts.pcap -ntxc 1`
5. The IP protocol field is 0x01, it is in the 9th byte offset from the beginning of the IP header, the TTL is at the 8th byte offset, you can use the `-v` in tcpdump to display this information
6. run tcpdump and display MAC addresses of the first record: `tcpdump -r concepts.pcap -ntec 1`
7. run tcpdump to display all records in the file, what is the protocol name that follows proto in the output of the IP header for the last record: `tcpdump -nvt -r concepts.pcap` it is decimal value of 17 which means UDP
8. what is the hex value associated with the protocol identified for UDP: `0x11`
9. describe the type of activity/data the above packet contains `DNS query and response for giac.org`

## Day 2

tcpdump filters:

1. search for TCP SYN packets `tcpdump -nt -r int-server.pcap 'tcp[13] = 0x02'`
2. search where a server responds that is listening on the requested port, where are the server ports that responded? `tcpdump -r int-server.pcap 'tcp[13] = 0x12' -nt` 
3. display any record with a termination flag set: `tcpdump -r int-server.pcap 'tcp[13] & 0x05 != 0' -nt`
4. display first five records with destincation port 143 and both the PUSH and ACK flags set, and any other flag may be set: `tcpdump -r int-server.pcap -nt -c 5 'tcp dst port 143 and tcp[13] & 0x18 = 0x18'`
## Day 3

1. According to the backbone alert file, how many unique rules have generated at least one alert in that file? `cat backbone | cut -f 4 -d ' ' | sort -rn | uniq | wc -l`
2. what is the most common sid: `cat backbone | cut -f 4 -d ' ' | sort -rn | uniq -c`
3. 