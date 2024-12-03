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

### Broken brute-force protection, IP block

using the [password list](https://portswigger.net/web-security/authentication/auth-lab-passwords)
victims username is given
creds provided

- investigate the login page, observe that IP is temporarily blocked if you submit 3 incorrect logins in a row
- notice this counter resets for the number of failed login attemps by logging in to your own account before this limit is reached
- send `POST /login` req to intruder, create a pitchfork attack with payload positions in both the username and password params
- click `Resource pool`, add the attack to a resource with `Maximum concurrent requests` set to 1 from the `Payload position` drop-down list, add a list of payloads that laternates between your username and carlos, set your username as first in the list and have carlos at least placed in 100 times
- edit the list of candidate passwords with your own password before each one, make sure this password is aligned with your username in the other list
- select position 2 from the `Payload position` drop down list and add the password list from above then run the attack
- find the 302 response, this should be your password for carlos

### Username enumeration via account lock

using these lists:
- [user list](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [password list](https://portswigger.net/web-security/authentication/auth-lab-passwords)

Steps:

- send `POST /login` req to burp intruder
- select `Cluster bomb attack` from the attack type menu, add a payload position to the `username` param, add a blank payload position to the end of the request body by clicking  `Add §` twice, should work: `username=§invalid-username§&password=example§§`
- in the payloads side panel add the list of usernames to the first payload, for the second paylod position select `Null payloads` and choose the option to generate 5 payloads
- In the results, notice that the responses for one of the usernames were longer than responses when using other usernames. Study the response more closely and notice that it contains a different error message: `You have made too many incorrect login attempts`
- now create a new intruder attack on the `POST /login`, select `Sniper attack`, set the `username` param to the username that you identified and add a payload position to the `password` param
- add the list of passwords to the payload set and create a grep extraction rule for the errur you found above
- in results look at the grep extraction column and notice there are a couple of different errors, but one of the responses did not contain any error message, this is our password
- wait for a minute for the lockout to finish and sign in

### 2FA broken logic

Background: you have creds, and the victims username

- login to your own account and investigate the 2FA verification process, notice the `POST /login2` request and the `verify` paramater that is being used to determine which user's account is being accessed
- log out
- send the `GET /login2` request to repeater and change the value of the `verify` param to `carlos` and send the request
- go to the login page and enter your username and password, then submit an invalid 2FA code
- send this `POST /login2` request to intruder
- set the `verify` parameter to carlos and add a payload position to the `mfa-code` param, brute force as a 4 number payload!
- [image](https://github.com/user-attachments/assets/695cadfa-5cc5-4d3b-9be1-298592936aa7)

- find the 302 response in intruder and load it in the browser
- click my account to finish lab

### Brute-forcing a stay-logged-in cookie

Background: you have creds, you have the victims username

this list 
- [password list](https://portswigger.net/web-security/authentication/auth-lab-passwords)

Steps:

- login with your own creds with the `Stay logged in` option selected, this sets a `stay-logged-in` cookie
- highlight cookie in burp and look at the insepctor panel which shows this as a base64 value, it should show the decoded value as something like: `wiener:51dc30ddc473d43a6011e9ebba6ca770`
- examining the end of this cookie shows it is an md5 hash, which means the cookie is formed like this: `base64(username:md5(password))`
- log out
- in the most recent `GET /my-account?id=wiener` req with the `stay-logged-in` cookie param send to inrtruder
- with the cookie value highlighted go to `payload processing` add the following rules in order
  - Hash: `MD5`
  - Add prefix: `wiener:`
  - Encode: `Base64-encode`
- we know `Update email` is only present after login so we will set a grep match rule to flag any response containing `Update email` in the response, now we will start the attack
- ![image](https://github.com/user-attachments/assets/72d623f7-8cb5-4995-b616-4eea97bcd0a6)
- 
- confirm this works, if it does continue
- remove your own password from the payload list
- change `GET /my-account?id=carlos`, add password list, change prefix to `carlos:` and run attack

### Offline password cracking

Background: you have creds, you have victims username obtain Carlos's stay-logged-in cookie and use it to crack his password. Then, log in as carlos and delete his account from the "My account" page. 
- 
























