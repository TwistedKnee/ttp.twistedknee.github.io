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
    
1. The user enters their username or email address and submits a password reset request.
2. The website checks that this user exists and then generates a temporary, unique, high-entropy token, which it associates with the user's account on the back-end.
3. The website sends an email to the user that contains a link for resetting their password. The user's unique reset token is included as a query parameter in the corresponding URL: `https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j`
4. When the user visits this URL, the website checks whether the provided token is valid and uses it to determine which account is being reset. If everything is as expected, the user is given the option to enter a new password. Finally, the token is destroyed.

Password reset poisoning is a method of stealing this token in order to change another user's password

Steps to perform

1. The attacker obtains the victim's email address or username, as required, and submits a password reset request on their behalf. When submitting the form, they intercept the resulting HTTP request and modify the Host header so that it points to a domain that they control. For this example, we'll use `evil-user.net`
2. The victim receives a genuine password reset email directly from the website. This seems to contain an ordinary link to reset their password and, crucially, contains a valid password reset token that is associated with their account. However, the domain name in the URL points to the attacker's server: `https://evil-user.net/reset?token=0a1b2c3d4e5f6g7h8i9j`
3. If the victim clicks this link (or it is fetched in some other way, for example, by an antivirus scanner) the password reset token will be delivered to the attacker's server
4. The attacker can now visit the real URL for the vulnerable website and supply the victim's stolen token via the corresponding parameter. They will then be able to reset the user's password to whatever they like and subsequently log in to their account

**Web cache poisoning**
You can abuse host header attacks that have XSS by poisoning a web cache as well

**accessing restrict functionality**

can avoid access control features that are poorly configured on the host header

**Routing based SSRF**

[Link to research](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)

If you supply the domain of your Collaborator server in the Host header, and subsequently receive a DNS lookup from the target server or another in-path system, this indicates that you may be able to route requests to arbitrary domains

**Connection state attacks**



## Labs Walkthrough
