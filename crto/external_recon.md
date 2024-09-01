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

Subdomains are another important thing to check, we could use something like ffuf with a fuzz on the Host header, or just use a tool like dnscan [https://github.com/rbsec/dnscan](https://github.com/rbsec/dnscan). There's other tools to like [Sublist3r](https://github.com/aboul3la/Sublist3r)

