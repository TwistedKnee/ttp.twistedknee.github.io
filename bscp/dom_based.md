# DOM Based vulnerabilities notes

## Methodology

So simple easy start to DOM inspection would be to both manually search for sinks, or to use DOM Invader.

To start DOM Invader load the extension in the burp browser:
![image](https://github.com/user-attachments/assets/68eda86b-2662-4683-a644-8c7a93167357)

You can open DOM Invader in a tab in the developer tools in the browser:
![image](https://github.com/user-attachments/assets/ff1f2f18-fd9d-4b07-b6c1-03c832d5e8e8)

Within here you can copy the canary to inject into parameters you have user input to, see current sinks and sources when your canary has been inputted, as well as other things. We will go over this more in details in the lab walkthroughs

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

Further lists exists on [Hacktricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-xss)

## Labs Walkthrough

### DOM XSS using web messages


