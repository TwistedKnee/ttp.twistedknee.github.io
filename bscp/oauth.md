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

Vuln structure to look into:
- in client
  - improper implementation of the implicit grant type
  - flawed csrf protection
- vulns in the oauth service
  - leaking auth codes and access tokens
  - flawed scope validation
  - unverified user registration

## Labs walkthrough
