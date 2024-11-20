# SSRF Notes

[Portswigger](https://portswigger.net/web-security/ssrf)

[URL validation bypass cheat sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)

## Methodology

### Initial

View any requests that include full URL's as parameters, like checking for stock. If so change the URL to one of your own to test if interaction does occur.

Common URLs to test as

- `127.0.0.1`
- `localhost`

### against backend systems

attempt to change the URL to another IP or domain that might exist internally to retrieve it's contents

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







