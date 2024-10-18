# Information Gathering - Web Edition

## WHOIS

a tool with registration data for domains, you can reveal the following:

- Registration Date
- Registrant
- Name Servers
- Location
- Registrar
- Takedown History

install
```
sudo apt update
sudo apt install whois -y
```

usage
```
whois <domain>
```

## DNS

resolution for domain names to IP's

### Concepts
|DNS Concept |	Description |	Example|
|:--------|:------------|:--------|
|Domain Name 	|A human-readable label for a website or other internet resource. 	|www.example.com|
|IP Address 	|A unique numerical identifier assigned to each device connected to the internet. 	|192.0.2.1|
|DNS Resolver 	|A server that translates domain names into IP addresses. 	|Your ISP's DNS server or public resolvers like Google DNS (8.8.8.8)|
|Root Name Server 	|The top-level servers in the DNS hierarchy. 	|There are 13 root servers worldwide, named A-M: a.root-servers.net|
|TLD Name Server |	Servers responsible for specific top-level domains (e.g., .com, .org).| 	Verisign for .com, PIR for .org|
|Authoritative Name Server| 	The server that holds the actual IP address for a domain. 	|Often managed by hosting providers or domain registrars.|
|DNS Record Types 	|Different types of information stored in DNS. |	A, AAAA, CNAME, MX, NS, TXT, etc.

### Records
|Record Type 	|Full Name 	|Description 	|Zone File Example|
|:--------|:------------|:--------|:--------|
|A |	Address Record |	Maps a hostname to its IPv4 address. |	www.example.com. IN A 192.0.2.1|
|AAAA 	|IPv6 Address Record 	|Maps a hostname to its IPv6 address. 	|www.example.com. IN AAAA 2001:db8:85a3::8a2e:370:7334|
|CNAME |	Canonical Name Record 	|Creates an alias for a hostname, pointing it to another hostname. 	|blog.example.com. IN CNAME webserver.example.net.|
|MX 	|Mail Exchange Record| 	Specifies the mail server(s) responsible for handling email for the domain. 	|example.com. IN MX 10 mail.example.com.|
|NS 	|Name Server Record 	|Delegates a DNS zone to a specific authoritative name server. |	example.com. IN NS ns1.example.com.|
|TXT 	|Text Record 	|Stores arbitrary text information, often used for domain verification or security policies. 	|example.com. IN TXT "v=spf1 mx -all" (SPF record)|
|SOA 	|Start of Authority Record 	|Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. 	|example.com. IN SOA ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400|
|SRV 	|Service Record 	|Defines the hostname and port number for specific services. 	|_sip._udp.example.com. IN SRV 10 5 5060 sipserver.example.com.|
|PTR 	|Pointer Record 	|Used for reverse DNS lookups, mapping an IP address to a hostname. 	|1.2.0.192.in-addr.arpa. IN PTR www.example.com.|


Tools:
- dig
- nslookup
- host
- dnsenum
- fierce
- dnsrecon
- theHarvester

Common dig commands
|Command 	|Description|
|:--------|:------------|
|dig domain.com 	|Performs a default A record lookup for the domain.|
|dig domain.com A 	|Retrieves the IPv4 address (A record) associated with the domain.|
|dig domain.com AAAA 	|Retrieves the IPv6 address (AAAA record) associated with the domain.|
|dig domain.com MX| 	Finds the mail servers (MX records) responsible for the domain.|
|dig domain.com NS 	|Identifies the authoritative name servers for the domain.|
|dig domain.com TXT 	|Retrieves any TXT records associated with the domain.|
|dig domain.com CNAME 	|Retrieves the canonical name (CNAME) record for the domain.|
|dig domain.com SOA |	Retrieves the start of authority (SOA) record for the domain.|
|dig @1.1.1.1 domain.com |	Specifies a specific name server to query; in this case 1.1.1.1|
|dig +trace domain.com |	Shows the full path of DNS resolution.|
|dig -x 192.168.1.1 	|Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.|
|dig +short domain.com| 	Provides a short, concise answer to the query.|
|dig +noall +answer domain.com |	Displays only the answer section of the query output.|
|dig domain.com ANY 	|Retrieves all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482).|
