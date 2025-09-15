seeing all the custom rules
```
ls -lah /etc/suricata/rules/
```

configuration file:
```
/etc/suricata/suricata.yaml
```

offline reading input:
```
suricata -r /home/suspicious.pcap
```

bypass checksums
```
suricata -r /home/susipicious.pcap -k none -l .
```

for live input:
```
sudo suricata --pcap=<network interface> -vv
```

Inline (NFQ) mode
```
sudo iptables -I FORWARD -j NFQUEUE
#then run
sudo suricata -q 0
#try suricata in IDS mode with AF_PACKET input, try one of the following
sudo suricata -i <network thing>
sudo suricata --af-packet=<network interface>
```

### Suricata outputs

- eve.json: recommended output and contains JSON objects, with data like timestamps, flow_id, and event_type. Utilize jq to filter data like: `cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "alert")'`
- fast.log: text based log format that records alerts only and is enabled by default
- stats.log: human readable statistics log

### File extraction

Edit the suricata.yaml configuration file with:
```
file-store:
	version: 2
	enabled: yes
	force-filestore: yes
```

Also define the location to place files in the same file-store object

We need to define a rule to trigger the file extraction like so in local.rules:
```
alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)
```

