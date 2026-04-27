sudo nmap -p- -A -T4 -oA initial 10.129.109.243

22/tcp    open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
13037/tcp filtered unknown
31399/tcp filtered unknown
35128/tcp filtered unknown
42175/tcp filtered unknown
47017/tcp filtered unknown
62969/tcp filtered unknown
62992/tcp filtered unknown

So one of the above worked, decided to run a vhost run for subdomains:
`ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://soulmate.htb -H 'Host: FUZZ.soulmate.htb' -fs 154`

found: ftp, adding to /etc/hosts along with soulmate.htb