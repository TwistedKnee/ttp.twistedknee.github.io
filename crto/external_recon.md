**External Reconaissance Notes**

If no assumed breach, you need an initial entry into the network. This can be low hanging vulnerabilities exposed externally, or more likely from phishing or something else entirely. In either case we will use recon to gain information about the target to help us find the entrypoint. 

Two types of recon: organisational and technical.

**DNS Records**
Checking DNS can give information for attackers

dig, there's a lot you can use with dig such as finding their own NS servers and using the @ flag to use that, which my allow more information but for now let's just focus on A records. 
```
dig <A record>
```

Whois
```
whois <IP>
```

Subdomains are another important thing to check, we could use something like ffuf with a fuzz on the Host header, or just use a tool like dnscan [dnscan](https://github.com/rbsec/dnscan). There's other tools to like [Sublist3r](https://github.com/aboul3la/Sublist3r)

dnscan
```
./dnscan.py -d <domain> -w subdomains-100.txt
```

if we find email in the name it might be an email service and we can enumerate that security with a tool like [Spoofy](https://github.com/MattKeeley/Spoofy)
```
python3 spoofy.py -d <domain> -o stdout
```
