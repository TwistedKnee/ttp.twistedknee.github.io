# HTTP Host Header Attacks

[Portswigger](https://portswigger.net/web-security/host-header)

## Methodology

- supply an arbitrary host header
- check for flawed host validation
  - if the request is blocked
  - attempt to understand how it parses the host header with steps like
    - use an arbitrary port `vulnerable-website.com:bad-stuff-here`
    - matching logic, attempt to submit an arbitrary subdomain `notvulnerable-website.com`
    - or use a subdomain that you already have compromised `hacked-subdomain.vulnerable-website.com`
- send ambiguous requests
  - inject duplicate Host headers
    - ```
      Host: vulnerable-website.com
      Host: bad-stuff-here
      ```
      
  -  supply an absolute URL
    - ```
      GET https://vulnerable-website.com/ HTTP/1.1
      Host: bad-stuff-here
      ```


## Labs Walkthrough
