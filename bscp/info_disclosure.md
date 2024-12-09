# Information Disclosure Notes

[Portswigger](https://portswigger.net/web-security/information-disclosure)

## Methodology

high level tools and techniques
- Fuzzing
- burp scanner
- burp engagement tools
- engineering informative responses

### Fuzzing notes

- add payload positions to parameters and use prebuilt wordlists of fuzz strings to test a high volume of different inputs in quick succession
- easily identify differences in responses by comparing HTTp status codes, response times, lengths, etc.
- use grep matching rules to quickly identify occurrences of keywords such as `error`, `invalid`, `SELECT`, `SQL`, etc.
- apply grep extraction rules to extract and compare the content of interesting items within responses

### Burp scanner

with burp pro you can use the scanner to test for many things

### Burp engagement tools

can access with right clicking on any HTTP message, burp proxy entry or item in the site map and go to `engagement tools`
- Search, can be used to look for any expression within the selected item
- find comments, tool to quickly extract any developer comments found in the selected item
- discover content, tool to identify additional content and functionality that is not linked from the websites visible content

### Engineering informative responses

when passing in values try to attempt an error message by placing in invalid values or unexpected ones to get detailed error messages that may lead to additional vulnerabilities

### Common sources for information disclosure

- files for web crawlers, `robots.txt` or `sitemap.xml`
- direcotry listings
- developer comments
- error messages
- debugging data
- user account pages
- backup files
- insecure configuration
- version control history, look for `/.git` for possible file repos

## Labs Walkthrough

### Information disclosure in error messages

- open the product pages
- in burp review the `GET` request for product pages, and see that it uses a `productID` param, send the `GET /product?productId=1` to repeater
- change the productId to a string like so `GET /product?productId=example`
- this causes a stack trace error and gives us the apache struts version

### Information disclosure on debug page

- browse to the home page
- go the the `target > site map`, right click on the top level entry for the lab and select `engagement tools > find comments` this will show a comment with a link called `Debug` that points to `/cgi-bin/phpinfo.php`
- in the site map, right click the `/cgi-bin/phpinfo.php` and send it to repeater
- send the request and notice there is the `SECRET_KEY` variable in the response

### Source code disclosure via backup files

- browse to `robots.txt` and notice the `/backup` direcotry, browse to this to find the file `ProductTemplate.java.bak`, we can also find this with the `Discover content` part of the `egnagement tools`, then launch a scan on `/backup`
- browse to `/backup/ProductTemplate.java.bak` to access the source code
- in the source code, notice the connection builder containing the hard-coded password for a postgres db
- submit the password to finish the lab

### Authentication bypass via information disclosure

Background: 

```
This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.
To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete the user carlos.
You can log in to your own account using the following credentials: wiener:peter 
```

- in repeater browse to `GET /admin` this shows that it is only accessible if logged in as an administrator or if requested by a local IP
- send the request again but this time use the `TRACE` method
- study the response notice the `X-Custom-IP-Authorization` header containing your IP address was automatically appended to your request
- Go to `Proxy > Match and replace`
- under `HTTP match and replace rules` click `Add`
- Leave the `Match` field empty
- under `Type`make sure that `Request header` is selected
- in the replace field enter the following `X-Custom-IP-Authorization: 127.0.0.1`
- click `Test`
- under `Auto-modified request` notice that burp has added the `X-Custom-IP-Authorization` header to the modified request
- click OK, proxy now adds the `X-Custom-IP-Authorization` header to every request you send
- browse to the home page, notice that we can now access the admin panel where we can delete `carlos`

### Information disclosure in version control history

- open the lab and browse to `/.git` to reveal the labs git version control data
- download a copy of this entire directory for linux users you can do this: `wget -r https://YOUR-LAB-ID.web-security-academy.net/.git/`
- explore the downloaded direcotry using your local Git installation, notice that there is a commit with the message `Remove admin password from config`
- look closer at the diff for the changed `admin.conf` file, notice the commit replaced the hard-coded admin password with an environment variable `ADMIN_PASSWORD` instead
- use the hardcoded password to log in as an administrator and delete the carlos user
