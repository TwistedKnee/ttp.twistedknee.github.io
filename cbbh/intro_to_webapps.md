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






