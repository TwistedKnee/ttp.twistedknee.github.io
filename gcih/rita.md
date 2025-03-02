# Real Intelligence Threat Analytics Notes

## Importing logs with rita

```
rita import ~/labs/RITA/VSAgent_Logs/ vsagent
rita import ~/labs/RITA/DNSCat_Logs/ dnscat2
```

## generate reports

```
rita html-report
```

now we are going to review the logs

### Beacon Analysis

- Goto vsagent
![image](https://github.com/user-attachments/assets/7deec300-687e-46f7-b8ce-aacaeccf42c3)
- select beacons
![image](https://github.com/user-attachments/assets/4f50cc7b-b3e2-4384-9fe7-6a86fd7061b2)

### User Agent analysis

- goto user agents
![image](https://github.com/user-attachments/assets/b930d3e1-0893-4208-a6b5-acc1548bd8bb)

## DNSCat2 analysis

- select dnscat2
![image](https://github.com/user-attachments/assets/3340c755-beb1-432e-9dde-e51f1a05af13)
- select dns analysis
![image](https://github.com/user-attachments/assets/f57599df-3217-4bd4-b29d-a5983ee66049)

## Searching zeek logs

now we go back to the terminal and review the logs

```
cd ~/labs/RITA/DNSCat_Logs/
ls -l dns*
zgrep nanobotninjas dns*
```
