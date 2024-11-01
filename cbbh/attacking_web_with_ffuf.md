# Attacking Web Applications with FUFF

Automating the fuzzing of a web application with ffuf to identify resources. 

## Cheatsheets
### FFUF cheatsheet
|Command 	|Description|
|:--------|:------------|
|ffuf -h| 	ffuf help|
|ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ 	|Directory Fuzzing|
|ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ |	Extension Fuzzing|
|ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php |	Page Fuzzing|
|ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v 	|Recursive Fuzzing|
|ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/ 	Sub-domain Fuzzing
|ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx |	VHost Fuzzing|
|ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx 	|Parameter Fuzzing - GET|
|ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx 	|Parameter Fuzzing - POST|
|ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx 	|Value Fuzzing|

### Wordlists cheatsheet

|Command |	Description|
|:--------|:------------|
|/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt 	|Directory/Page Wordlist|
|/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt 	|Extensions Wordlist|
|/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 	|Domain Wordlist|
|/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt 	|Parameters Wordlist|

### Misc Cheatsheet

|Command 	|Description|
|:--------|:------------|
|sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts' 	|Add DNS entry|
|for i in $(seq 1 1000); do echo $i >> ids.txt; done 	|Create Sequence Wordlist|
|curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded' 	|curl w/ POST|

## Web Fuzzing

Fuzzing is a testing technique that sends various types of user input to a certain interface to study how it would react. In our use case it will be sending file and folder names on the web application and determining if they exist or not. 

### Directory fuzzing

Install
```
apt install ffuf -y
```

Use
```
ffuf -w /opt/userful/seclists/Discovery/Web-Content/direcotry-list-2.3-small.txt:FUZZ
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```








