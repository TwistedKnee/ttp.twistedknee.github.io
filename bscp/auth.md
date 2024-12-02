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

using these lists:
- [user list](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [password list](https://portswigger.net/web-security/authentication/auth-lab-passwords)

Steps:

- send login request to intruder, highlight username and select payloads as the user list from above
- config intruder as sniper
- run and check responses to see difference other then invalid username, `Incorrect password` is returned so that req is the user to target
- replace name with that user, and highlight password with the above password list as the payload and run
- check for `302` response, this will be the login creds to sign in with

### 2FA simple bypass

Background: Given victims creds and your own creds to test

- log in with own creds
- click the `email client` button to access your emails
- log out of account
- log in with victims creds
- when prompted for verification code, manually change the URL to navigate to `/my-account`, this bypasses the 2FA steps

### Password reset broken logic

Background: Given victims username and your own creds to test

- click `forgot your password?` and enter your own username
- click the `Email client` button to view the password reset email that was sent, click the link and follow the full process
- study the requests for resetting your password in burp, notice the `POST /forgot-password?temp-forgot-password-token` contains the username as hidden input, send to repeater
- observe the password reset functionality still works even if you delete the value of the `temp-forgot-password-token` parameter in both the URL and request body
- in browser request a new password reset again, send the `POST /forgot-password?temp-forgot-password-token` to repeater
- delete the `temp-forgot-password-token` from the request in both the URL and body, change the username to carlos, set the new password to whatever you want and send the request
- sign in to carlos' account with your set password

### Username enumeration via subtly different responses

using these lists:
- [user list](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [password list](https://portswigger.net/web-security/authentication/auth-lab-passwords)

Steps:

- submit fake username and password to the login, send this to intruder
- highlight the username and set the user list above as the payload
- Click `Settings` in burp and got to `Grep - Extract` click `Add` scroll down through the response until you find the error message `Invalid username or password.`, highlight this with your mouse and click `Ok`
- run intruder
- when finished notice the column with the error message we extracted, filter and find the one value different, instead of a full stop/period it has a trailing space, this is the username to target
- now use that username and highlight the password now and use the above list and run until you get a 302
- sign in with the username and password found

### Username enumeration via response timing

Background: you have creds

using these lists:
- [user list](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [password list](https://portswigger.net/web-security/authentication/auth-lab-passwords)

Steps:

- send invalid login to `POST /login`
- Use the `X-Forwarded-For` header to bypass the IP based brute-force protection
- Attempt to login with usernames and passwords, notice that when using your own username with incorrect password the length of time takes longer if using a long password
- send this request to intruder and change the attack type to `Pitchfork`, add the `X-Forwarded-For` to the request
- make the value for `X-Forwarded-For` be `127.0.0.1`in payload, highlight the `1`, in the side panel select position 1 from the payload position and select `Numbers`, enter the range 1-100 and set the step to 1
- highlight the usernames section of the request and in it's payload add the user list from above
- when the attack finishes at the top of the dialog click columns and select the `Response received` and `Response completed` options
- notice that one response times was longer than others, this is our username to attempt brute force on
- now change intruder position 2 to password and use the password list and brute force until you receive the `302` response 
















