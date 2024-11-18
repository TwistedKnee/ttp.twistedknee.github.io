# DOM Based vulnerabilities notes

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

### 






