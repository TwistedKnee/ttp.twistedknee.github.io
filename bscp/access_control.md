# Access Control Notes

[Portswigger](https://portswigger.net/web-security/access-control)

## Methodology

### Vertical privesc:

- Attempt access to URLs for administrative function like `/admin` or checking `robots.txt` for possible URLs
- - Brute force and attempt access as well
- - Review Javascript and files for references to administrative URLs to gain access
- Check URLs that take parameter based fuctions to enforce access control, like `/home.jsp?role=1` or `/home.jsp?admin=true`
- If denied to delete based on denial on methods, try overwriting with `X-Original-URL` or `X-Rewrite-URL` like so where POST on /admin/deleteUser is denied:

```
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

-  Check for bypassing URL-matches with all capatization like `/ADMIN/DELETEUSER`
-  - in Spring you can add an arbitrary extension and it still resolves: `/admin/deleteUser.anything`
-  - Or add another `/` to the end like so `/admin/deleteUser/` 

### Horizontal privesc

- Check IDORs to access users info: `/myaccount?id=123` change the id parameter
- If GUIDs are used, attempt to find exposure such as where in the application a users info is referenced such as messages or reviews
- - check if user has admin privs when you do get it from something like IDOR
- in a multi step process there might not be restrictions for the last step as the application thinks it already was approved to get to that point
- Referer based, check and put possible paths that might be validated to allow access. In an example: for `/admin/deleteUser` put `/admin` in the referer header to bypass
- location based: change using a VPN, web proxy, or manipulate client side geolocation mechanisms

## Labs Walkthrough












