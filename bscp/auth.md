# Authentication Notes 

[Portswigger](https://portswigger.net/web-security/authentication)

[user list](https://portswigger.net/web-security/authentication/auth-lab-usernames)
[password list](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Methodology

### Password based logins

Brute force usernames and passwords with burp intruder, watch for:
- Changes in status codes
- Changes in Error messages
- Changes in response times

Can bypass brute force protection by having a user controlled account sign in every couple attempts to avoid lockout by IP

### Mutli factor 

Attempt to login and if prompted for MFA just browse to another logged in required resource and see that your user is considered logged in or not.

If a cookie is being used in the verification step, using a verification step but changing your user value in the cookie can lead to access through broken verification steps in the MFA process.

### Other auth mechanisms

Keeping users logged in issue: review the cookie after using your own creds to see if you can brute force the cookie value and change it to forge another users cookie

If you can steal a users cookie, crack it to find the password

Resetting users password: 
- if sent by email abuse can be man-in-the-middled to grab and change the user before they do
- If resetting using a URL change the user variable if used like so: `http://vulnerable-website.com/reset-password?user=victim-user`
- If using a token instead can still be visit the reset form from their own account, delete the token, and leverage this page to reset an arbitrary user's password
- Changing user passwords: if access to change passwords is directly accessible without logging in an attacker can abuse to reset an arbitrary users password

## Labs walkthrough

### Username enumeration via different responses

