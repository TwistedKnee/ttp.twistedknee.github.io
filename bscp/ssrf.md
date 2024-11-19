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
-- `2130706433`
-- `017700000001`
-- `127.1`

- Register your own domain name that resolves to `127.0.0.1`, `spoofed.burpcollaborator.net` can be used for this
- Obfuscate blocked strings with URL encoding or case variation
- provide a URL that you control, which redirects to the target URL
-- try other redirect codes too when doing this, switching from `http:` to `https:` can bypass some filters

## Labs walkthrough
