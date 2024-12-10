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
    ```
    GET /example HTTP/1.1
    Host: vulnerable-website.com
    Host: bad-stuff-here
    ```
      
  -  supply an absolute URL
    ```
    GET https://vulnerable-website.com/ HTTP/1.1
    Host: bad-stuff-here
    ```
  - add line wrapping, indenting the header with tab
    ```
    GET /example HTTP/1.1
      Host: bad-stuff-here
    Host: vulnerable-website.com
    ```
- inject host override headers
  - adding `X-Forwarded-Host`
    ```
    GET /example HTTP/1.1
    Host: vulnerable-website.com
    X-Forwarded-Host: bad-stuff-here
    ```
  - other headers to look into:
  ```
    X-Host
    X-Forwarded-Server
    X-HTTP-Host-Override
    Forwarded
  ```
- you can use param miners `guess headers` function to automatically probe for supported headers

### Password reset poisoning

Normal password reset flow
    
    The user enters their username or email address and submits a password reset request.
    The website checks that this user exists and then generates a temporary, unique, high-entropy token, which it associates with the user's account on the back-end.
    The website sends an email to the user that contains a link for resetting their password. The user's unique reset token is included as a query parameter in the corresponding URL:
    https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j
    When the user visits this URL, the website checks whether the provided token is valid and uses it to determine which account is being reset. If everything is as expected, the user is given the option to enter a new password. Finally, the token is destroyed.


## Labs Walkthrough
