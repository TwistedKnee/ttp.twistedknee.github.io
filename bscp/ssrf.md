# SSRF Notes

[Portswigger](https://portswigger.net/web-security/ssrf)

[URL validation bypass cheat sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)

Awesome video about testing blind ssrf with timing is here: [KettleGod](https://www.youtube.com/watch?v=zOPjz-sPyQM) 

The above video goes over more then that, but essentially there does exist a possibility in determining blind ssrf with timing based detection on ther response time of the messages. If the first message does a scoped ssrf on an internal network for a DNS record, caching would proceed it, meaning the first message will be longer while subsequent will be shorter and consistently the same. (Note this requires the usage of HTTP/2 to avoid Jitter messing with response times).

## Methodology

### Initial

View any requests that include full URL's as parameters, like checking for stock. If so change the URL to one of your own to test if interaction does occur.

Other injection points would be the http headers like the `referer` one

Common URLs to test as

- `127.0.0.1`
- `localhost`

### against backend systems

Attempt to change the URL to another IP or domain that might exist internally to retrieve it's contents

### Circumventing defenses

- Use alternative IP representation of `127.0.0.1` and `localhost`
  - `2130706433`
  - `017700000001`
  - `127.1`

- Register your own domain name that resolves to `127.0.0.1`, `spoofed.burpcollaborator.net` can be used for this
- Obfuscate blocked strings with URL encoding or case variation
- provide a URL that you control, which redirects to the target URL
  - try other redirect codes too when doing this, switching from `http:` to `https:` can bypass some filters

## Labs walkthrough

### Basic SSRF against the local server

- attempt to get /admin but you see you're blocked
- use check stock and notice the `stockApi` parameter to `http://localhost/admin` and send and you get access to the administration interface
- read html to identify the URL to delete the target user, enter this in the stockApi and send: `http://localhost/admin/delete?username=carlos`

### Basic SSRF against another back-end system

- again use the check stock functionality, send it to intruder
- change parameter to `http://192.168.0.1:8080/admin` then highlight the last IP octet in intruder
- use numbers 1-255 as the payload and run it until you receive a `200` response, send this request to repeater
- no change the URI to `/admin/delete?username=carlos` and send and you complete the lab 

### Blind SSRF with out of band detection

- visit product and intercept with burp and send it to repeater
- select referer header and replace with collaborator with `right-click->insert collaborator payload`

### SSRF with blacklist-based input filter



- Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
- Change the URL in the stockApi parameter to `http://127.0.0.1/` and observe that the request is blocked.
- Bypass the block by changing the URL to: `http://127.1/`
- Change the URL to `http://127.1/admin` and observe that the URL is blocked again.
- Obfuscate the "a" as `http://127.1/%2561min`

### SSRF with filter bypass via open redirection vulnerability

Change the stock check URL to access the admin interface at http://192.168.0.12:8080/admin and delete the user carlos

- visit a product and send the check stock call to repeater
- when attempting to tamper with the stockApi as we have before but it doesn't work
- click `next product` and notice the path parameter is placed in the location header of a redirection response
- create a URL that exploits the open redirect vuln `/product/nextProduct?path=http://192.168.0.12:8080/admin`
- amend to delete `/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`

