# Attacking Web Applications with FUFF

Automating the fuzzing of a web application with ffuf to identify resources. 

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
