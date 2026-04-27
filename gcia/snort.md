read in files:

```
snort -r file.pcap
```

read in files with configuraiton:
```
snort -r file.pcap -c config.lua
```

read in files with fast alert, there are other alerts we can add here:
```
snort -r file.pcap -c config.lua -A alert_fast
```
