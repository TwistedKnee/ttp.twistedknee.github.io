# JWT Notes

[Portswigger](https://portswigger.net/web-security/jwt)

[video](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts)

install the jwt editor extension in burp

## Methodology

A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot. The header and payload parts of a JWT are just base64url-encoded JSON objects. The header contains metadata about the token itself, while the payload contains the actual "claims" about the user.

In most cases, this data can be easily read or modified by anyone with access to the token. Therefore, the security of any JWT-based mechanism is heavily reliant on the cryptographic signature.

Tip: From Burp Suite Professional 2022.5.1, Burp Scanner can automatically detect a number of vulnerabilities in JWT mechanisms on your behalf. For more information, see the related issue definitions on the Target > Issued definitions tab. 

**JWT signature**

If you want to gain a better understanding of how JWTs are constructed, you can use the debugger on jwt.io to experiment with arbitrary tokens.

The server that issues the token typically generates the signature by hashing the header and payload. In some cases, they also encrypt the resulting hash. Either way, this process involves a secret signing key. This mechanism provides a way for servers to verify that none of the data within the token has been tampered with since it was issued.

## Labs Walkthrough
