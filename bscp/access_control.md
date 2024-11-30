# Access Control Notes

[Portswigger](https://portswigger.net/web-security/access-control)

## Methodology

### Vertical privesc:

- Attempt access to URLs for administrative function like `/admin` or checking `robots.txt` for possible URLs
  - Brute force and attempt access as well
  - Review Javascript and files for references to administrative URLs to gain access
- Check URLs that take parameter based fuctions to enforce access control, like `/home.jsp?role=1` or `/home.jsp?admin=true`
- If denied to delete based on denial on methods, try overwriting with `X-Original-URL` or `X-Rewrite-URL` like so where POST on /admin/deleteUser is denied:

```
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

-  Check for bypassing URL-matches with all capatization like `/ADMIN/DELETEUSER`
   - in Spring you can add an arbitrary extension and it still resolves: `/admin/deleteUser.anything`
   - Or add another `/` to the end like so `/admin/deleteUser/` 

### Horizontal privesc

- Check IDORs to access users info: `/myaccount?id=123` change the id parameter
- If GUIDs are used, attempt to find exposure such as where in the application a users info is referenced such as messages or reviews
  - check if user has admin privs when you do get it from something like IDOR
- in a multi step process there might not be restrictions for the last step as the application thinks it already was approved to get to that point
- Referer based, check and put possible paths that might be validated to allow access. In an example: for `/admin/deleteUser` put `/admin` in the referer header to bypass
- location based: change using a VPN, web proxy, or manipulate client side geolocation mechanisms

## Labs Walkthrough

### Unprotected admin functionality

- review robots.txt
- goto `/administrator-panel` to load the admin panel
- delete carlos user

### Unprotected admin functionality with unpredictable URL

- review the source code, with burp or dev tools
- see javascript showing the URL of the admin panel
- goto the panel and delete carlos user

### User role controlled by request parameter

Background: the admin panel is located at `/admin`

- sign in with user creds
- notice the response cookie sets `Admin=false` change it to true
- goto `/admin` and access the admin panel on your users account page to delete carlos user

### User role can be modified in user profile

Background: the admin panel is located at `/admin`, and it's only accessible to logged-in users with a roleid of 2

- sign in with user creds
- update your email and notice the response contains your role ID
- send email update to repeater and add the `"roleid":2` into the JSON in the request body and send
- now we see our roleid has changed to 2
- browse to `/admin` and delete carlos user

### User ID controlled by request parameter

Background: This lab has a horizontal privilege escalation vulnerability on the user account page. To solve the lab, obtain the API key for the user carlos and submit it as the solution. 

- sign in with user creds
- note the URL contains your username in the `id` param, send this to repeater
- change `id` to carlos and send
- inspect response and grab the API key

### User ID controlled by request parameter, with unpredictable user IDs

Background: This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs. 

- review blogs and find one by carlos
- click on carlos and observe the URL contains his user ID
- log in using your creds and access your account page
- change the `id` parameter with carlos
- retrieve carlos' API key

### User ID controlled by request parameter with data leakage in redirect 

Background: This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.

- log in with user creds, and access your account page, send this to repeater
- change the `id` param to carlos
- observe that although the response is now redirecting you to the home page, it has a body containing the API key belonging to carlos, submit this to complete lab

### User ID controlled by request parameter with password disclosure

Background: This lab has user account page that contains the current user's existing password, prefilled in a masked input. 

- log in with user creds
- change the `id` param in the URL to `administrator`
- view response in burp and notice administrators password is in the response
- log in to administrator account and delete carlos user

### Insecure direct object references

Background: This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs

- select the live chat tab
- send message and then select `View transcript`
- review the URL and observe that the transcripts are text files assigned a filename containing an incrementing number
- change the filename to `1.txt`, notice a password within the chat transcript
- log in with the stolen creds

### URL-based access control can be circumvented

Background: This website has an unauthenticated admin panel at /admin, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the X-Original-URL header

- try to load `/admin`
- send request to repeater and change the URL to `/`  and add the HTTP header `X-Original-URL: /invalid`, notice it returns a `not found` response indicating the back-end system is processing the `X-Original-URL` header
- change the value of the `X-Original-URL` to `/admin`
- delete user carlos by adding `?username=carlos` to the `X-Original-URL: /admin/delete` header to delete the user

### Method-based access control can be circumvented

Background: This lab implements access controls based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin

- log in with admin creds and promote carlos, send this to repeater
- log in with user creds in another session (incognito)
- attempt to re-promote carlos with the non-admin user by copying the users session cookie in to the existing repeater request, and observe that it says `Unauthorized`
- change method from `POST` to `POSTX` and resend, the error now says `missing parameter`
- change method to `GET` and send
- now change the request to promote your own user and send it

### Multi-step process with no access control on one step 

Background: This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin

- log in with admin creds
- browse to admin panel and promote carlos, then send to repeater
- log in with user creds in another session (incognito)
- copy the non-admin users session cookie into the repeater request, change the username to yours and send it

### Referer-based access control 

Background: This lab controls access to certain admin functionality based on the Referer header. You can familiarize yourself with the admin panel by logging in using the credentials administrator:admin

- log in with admin creds
- browse to admin panel and promote carlos, then send to repeater
- log in with user creds in another session (incognito)
- browse to `/admin-roles?username=carlos&action=upgrade` observe that the request is treated as unauthorized due to the absent referer header
- copy the non-admin users session cookie in to the repeater request, change the username to yours and send it


