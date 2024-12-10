# HTTP Host Header Attacks

[Portswigger](https://portswigger.net/web-security/host-header)

[Research](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)

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

For example, you may occasionally encounter servers that only perform thorough validation on the first request they receive over a new connection. In this case, you can potentially bypass this validation by sending an innocent-looking initial request then following up with your malicious one down the same connection. 

Many reverse proxies use the Host header to route requests to the correct back-end. If they assume that all requests on the connection are intended for the same host as the initial request, this can provide a useful vector for a number of Host header attacks, including routing-based SSRF, password reset poisoning, and cache poisoning. 

**SSRF Via a malformed request line**

proxies sometimes fail to validate the request line properly. such as using an @ sign in the request to fool the server in processing the prefix as a username instead of the server like so:

```
GET @private-intranet/example HTTP/1.1
```

which will have it reach out to `http://backend-server@private-intranet/example` and assume the `backend-server` is the username and `private-intranet` is the host

## Labs Walkthrough

### Basic password reset poisoning

Background: 

```
 This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account.

You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server
```

- go to the login page and use the `forget your password?` functionality
- go to the exploit server and open the email client an notice the email contains a link to reset your password, notice that the URL contains the query parameter `temp-forgot-password-token`
- click the link and observe that you are prompted to enter a new password, reset it to whatever you want
- now study the HTTP history and notice that the `POST /forgot-password` request is used to trigger the password reset email, this contains the username as a body parameter, send this to repeater
- now change the host header to an arbitrary value and see that it still works for the password reset request, go back to the email server and look at the new email that you've received, notice that the URL in the email contains your arbitrary Host header instead of the usual domain name
- back in repeater change the host header to your exploit servers domain name, and change the username to carlos, send the request
- go to the exploit server and open the access log, you will see a request for `GET /forgot-password` with the token parameter for carlos' account, save this token
- go to your email client and copy the genuine password reset URL from your first email, but replace the reset token with carlos' and change his password
- then log in as carlos

### Host header authentication bypass

Background: 

```
This lab makes an assumption about the privilege level of the user based on the HTTP Host header
```

- send the `GET /` that received a 200 response to repeater
- change the host header to an arbitrary one and notice that it still successfully accesses the home page
- browse to `/robots.txt` and observe the `/admin` page
- try and browse to `/admin` but notice you get blocked, but notice the error message which reveals that the panel can be accessed by local users
- send the `GET /admin` request to repeater
- change the host header in repeater to `localhost` and see you can access the page now
- change the request to `GET /admin/delete?username=carlos` and send the request to delete carlos to solve the lab

### Web cache poisoning via ambiguous requests

Background: 

```
This lab is vulnerable to web cache poisoning due to discrepancies in how the cache and the back-end application handle ambiguous requests. An unsuspecting user regularly visits the site's home page.

To solve the lab, poison the cache so the home page executes alert(document.cookie) in the victim's browser.
```

- open the lab and click `Home` to refresh the page, send the `GET /` to repeater
- study the labs behavior and notice that the website validate the host header, if you modify the host header you can no longer access the home page
- notice in the original response that verbose caching headers, which tell you when you get a cache hit, add an arbitrary query parameter to your requests to serve as a cache buster: `GET /?cb=123`
- if you add a second Host header with an arbitrary value it appears to be ignored when validating and routing your request, crucially notice that the arbitrary value of your second Host header is reflected in an absolute URL used to import a script form `/resources/js/tracking.js`
- remove the second host header and send the request again using the same cache buste, notice that you still receive the same cached response containing you injected value
- in exploit server create a file at `/resources/js/tracking.js` containing the payload `alert(document.cookie)` store the exploit and copy the domain for your exploit server
- in repeater add a second host header containing your exploit server domain name
- send the request a couple of times until you get a cache hit, once validating with the cache buster that it works remove the cache buster and resend and wait for the victim

### Routing-based SSRF

Background:

```
This lab is vulnerable to routing-based SSRF via the Host header. You can exploit this to access an insecure intranet admin panel located on an internal IP address.

To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete the user carlos. 
```

- send the `GET /` request to repeater
- insert a collaborator payload in the host header and send
- poll collaborator and see that a couple of network interactions happen in the table, including an HTTP request
- send the `GET /` to intruder, deselect `update host header to match target`
- delete the value of the host header and replace it with the following IP address, adding a payload position to the final octet: `Host: 192.168.0.§0§`
- in payloads side panel select the payload `Number` under `payload configuration` enter the following values:

```
From: 0
To: 255
Step: 1
``` 

- click `start attack` , a warning will appear just accept it
- when the attack finishes click `status` column to sort the results, notice that a single request received a `302` response redirecting you to `/admin` send this to repeater
- in repeater change the request line to `GET /admin` and send it, you will now see you have access to the admin panel
- study the form for deleting users, notice this will generate a POST request to `/admin/delete` with both a CSRF token and `username` parameter, you need to manually craft an equivalent request to delete carlos
- change the path in your request to `/admin/delete`, copy the CSRF token from the displayed response and add it as a query parameter to your request, also add a username parameter containing `carlos` it should look somehting like: `GET /admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos`
- copy the session cookie from the `Set-Cookie` header in the displayed response and add it to your request
- right click on your request and select `change request method`, burp will convert it to a POST request, send it to delete carlos' account

### SSRF via flawed request parsing

Background: 

```
This lab is vulnerable to routing-based SSRF due to its flawed parsing of the request's intended host. You can exploit this to access an insecure intranet admin panel located at an internal IP address.

To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete the user carlos
```

- send the `GET /` request to repeater
- observe that you can also access the home page by supplying an absolute URL in the request line as follows: `GET https://YOUR-LAB-ID.web-security-academy.net/`
- now when modifying the host header your request isn't blocked anymore, this suggests that the URL is being validated rather then the host header
- put a burp collaborator domain in the host header and send

```
GET https://YOUR-LAB-ID.web-security-academy.net/
Host: BURP-COLLABORATOR-SUBDOMAIN
```

- send this request with the absolute URL to intruder, deselect `Update Host header to match target`
- put this in the host header but with a payload delimeter in the last octet like above: `192.168.0.0/24`, and start the attack, then send the request that responds to repeater
- append the /admin to the absolute URL in the request line and send the request, and now you can access the admin panel
- change the absolute URL to point to `/admin/delete`, copy the CSRF token from the displayed response and add it as a query param and a username param with the value equaling carlos like so: `GET https://YOUR-LAB-ID.web-security-academy.net/admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos`
- copy the session cookie from the `Set-Cookie` header in the displayed response and add it to your request
- right click on your request and change the method type to POST
- send to delete carlos

### Host validation bypass via connection state attack

Background:

```
This lab is vulnerable to routing-based SSRF via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.

To solve the lab, exploit this behavior to access an internal admin panel located at 192.168.0.1/admin, then delete the user carlos

Hint: Solving this lab requires features first released in Burp Suite 2022.8.1.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling](https://portswigger.net/research/browser-powered-desync-attacks#state). 
```

- 










