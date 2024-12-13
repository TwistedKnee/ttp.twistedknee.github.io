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

**Vulns testing**

```Note: Even if the token is unsigned, the payload part must still be terminated with a trailing dot.```

test with an unverified signature

Can change the algo to `none`, if filtering is happening can try encoding or mixed capitalizations

brute force secret keys: Some signing algorithms, such as HS256 (HMAC + SHA-256), use an arbitrary, standalone string as the secret key that can be brute-forced. You can do this with hashcat: `hashcat -a 0 -m 16500 <jwt> <wordlist>`

run hashcat `--show` to see the cracked values

Once you have identified the secret key, you can use it to generate a valid signature for any JWT header and payload that you like. For details on how to re-sign a modified JWT in Burp Suite, see [Editing JWTs](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts#editing-jwts) 

JWT header params to test for injection: 
- jwk (JSON Web Key) - Provides an embedded JSON object representing the key.
- jku (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.
- kid (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from

### Injecting self-signed JWTs via the jwk parameter

Misconfigured servers sometimes use any key that's embedded in the jwk parameter.

You can exploit this behavior by signing a modified JWT using your own RSA private key, then embedding the matching public key in the jwk header.

Although you can manually add or modify the jwk parameter in Burp, the JWT Editor extension provides a useful feature to help you test for this vulnerability

- with jwt editor installed and loaded go to the `jwt editor keys` tab
- generate a new RSA key
- send a request containing a JWT to repeater
- in the message editor switch to the extension-generated `JSON web token` tab within repeater and modify the token's payload however you like
- click attack, then select `embedded JWK`, when prompted select your newly generated RSA key
- send the request to test how the server responds

### Injecting self-signed JWTs via the jku parameter

Instead of embedding public keys directly using the jwk header parameter, some servers let you use the jku (JWK Set URL) header parameter to reference a JWK Set containing the key. When verifying the signature, the server fetches the relevant key from this URL.

JWK Sets like this are sometimes exposed publicly via a standard endpoint, such as /.well-known/jwks.json

### Injecting self-signed JWTs via the kid parameter

test abusing the `kid` value of the jwt, like using directory traversal:

```
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

This is especially dangerous if the server also supports JWTs signed using a symmetric algorithm. In this case, an attacker could potentially point the kid parameter to a predictable, static file, then sign the JWT using a secret that matches the contents of this file.

You could theoretically do this with any file, but one of the simplest methods is to use /dev/null, which is present on most Linux systems. As this is an empty file, reading it returns an empty string. Therefore, signing the token with a empty string will result in a valid signature. 


Note: If you're using the JWT Editor extension, note that this doesn't let you sign tokens using an empty string. However, due to a bug in the extension, you can get around this by using a Base64-encoded null byte.

If the server stores its verification keys in a database, the kid header parameter is also a potential vector for SQL injection attacks. 

### Other interesting JWT header parameters

other header params to look into:

- `cty` - Content-Type, If you have found a way to bypass signature verification, you can try injecting a cty header to change the content type to text/xml or application/x-java-serialized-object, which can potentially enable new vectors for XXE and deserialization attacks
- `x5c` - (X.509 Certificate Chain) - Sometimes used to pass the X.509 public key certificate or certificate chain of the key used to digitally sign the JWT, can be used to inject self-signed certificates, similar to the jwk header injection attacks discussed above

### Algorithm confusion attacks

When an attacker is able to force the server to verify the signature of a JSON web token (JWT) using a different algorithm than is intended by the website's developers.

Make sure to make note of the `alg` parameter in the token

High level steps:
- obtain the servers public key
- convert the public key to a suitable format
- create a malicious JWT with a modified payload and the `alg` header set to `HS256`
- sign the token with the `HS256` using the public key as the secret

Step 1 - obtain the servers public key
- look for JWK objects mapped to `/jwks.json` or `/.well-known/jwks.json`, These may be stored in an array of JWKs called keys. This is known as a JWK Set
- may even be able to extract it from a pair of existing JWT's, see below

Step 2 - Convert the public key to a suitable format
- with the jwt editor loaded, go to the `JWT editor keys` tab
- click `new rsa` key, and paste the JWK that you obtained earlier
- select the `PEM` radio button and copy the resulting PEM key
- go to the decoder tab and base64 encode the PEM
- go back to the `JWT editor keys` tab and click `New symmetric key`
- in the dialog, click `generate` to generate a new key in JWK format
- replace the generated value for the `k` param with a base64 encoded PEM key that you just copied
- save the key

Step 3 - Modify you JWT
- once you have the public key in a suitable format, you can modify the JWt however you like, just make sure the `alg` is set to `HS256`

Step 4 - Sign the JWT using the public key
- sign the token using the `HS256` algo with the RSA public key as the secret

### Deriving public keys from existing tokens

In cases where the public key isn't readily available, you may still be able to test for algorithm confusion by deriving the key from a pair of existing JWTs. This process is relatively simple using tools such as jwt_forgery.py. You can find this, along with several other useful scripts, on the rsa_sign2n GitHub repository.

We have also created a simplified version of this tool, which you can run as a single command: 
`docker run --rm -it portswigger/sig2n <token1> <token2> `

For each potential value, our script outputs:

- A Base64-encoded PEM key in both X.509 and PKCS1 format.
- A forged JWT signed using each of these keys.

To identify the correct key, use Burp Repeater to send a request containing each of the forged JWTs. Only one of these will be accepted by the server. You can then use the matching key to construct an algorithm confusion attack. 

## Labs Walkthrough

### JWT authentication bypass via unverified signature

Background:

```
This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```

- log into your own account
- in burp history send the `GET /my-account` with you signed in JWT to repeater
- in repeater, change the path to `/admin` and send the request and notice you are blocked
- select the payload of the JWT again, in the inspector panel change the value of the `sub` claim from `wiener` to `administrator` then click `apply changes`
- send the request again, observe that you have successfully accessed the admin panel
- in the response find the URL for deleting `carlos`: `/admin/delete?username=carlos` and send the request

### JWT authentication bypass via flawed signature verification

Background:

```
This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```

- log into your own account
- in burp history send the `GET /my-account` with you signed in JWT to repeater
- in repeater, change the path to `/admin` and send the request and notice you are blocked
- select the payload of the JWT again, in the inspector panel change the value of the `sub` claim from `wiener` to `administrator` and set `alg` to `none` then click `apply changes`
- in the message editor remove the signature from the JWT, but remember to leave the trailing dot after the payload
- send the request and observe that you have successfully accessed the admin panel
- in the response find the URL for deleting `carlos`: `/admin/delete?username=carlos` and send the request

### JWT authentication bypass via weak signing key

Background:

```
This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets.

To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```

Part 1 Brute-force the secret key: 
- load the JWt editor
- log into your account
- in burp history send the `GET /my-account` with you signed in JWT to repeater
- in repeater, change the path to `/admin` and send the request and notice you are blocked
-  Copy the JWT and brute-force the secret. You can do this using hashcat as follows: `hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list`
-  the secret is `secret1`

Part 2 Generate a forged signing key:
- Using Burp Decoder, Base64 encode the secret that you brute-forced in the previous section
- In Burp, go to the JWT Editor Keys tab and click New Symmetric Key. In the dialog, click Generate to generate a new key in JWK format
- replace the generated value for the `k` property with the base64 encoded secret
- select OK to save the key

Part 3 Modify and sign the JWT:
- Go back to the `GET /admin` request in repeater and switch to the extension-generated JSON Web Token message editor tab
- for the JWT, change the value of the sub claim to administrator
- At the bottom of the tab, click Sign, then select the key that you generated in the previous section
- make sure that the `Don't modify header` option is selected, then click OK
- send the request and observe that you have successfully accessed the admin panel
- in the response, find the URL for deleting carlos: `/admin/delete?username=carlos` change the repeater path to this and send

### JWT authentication bypass via jwk header injection

Background:

```
This lab uses a JWT-based mechanism for handling sessions. The server supports the jwk parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.

To solve the lab, modify and sign a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```

- load the JWT editor extension
- log into your account
- in burp history send the `GET /my-account` with you signed in JWT to repeater
- in repeater, change the path to `/admin` and send the request and notice you are blocked
- go to the `JWT editor keys` in burps main tab bar, click `new rsa key`
- in the dialog, click `generate` to automatically generate a new key pair, then click OK to save the key
- go back to the `GET /admin` request in repaeter, and switch to the extension generated `JSON Web Token` tab
- in the payload, change the value of the `sub` claim to `administrator`
- at the bottom of the `JSON Web Token` tab click `attack` then select `embedded jwk` when prompted, select your newly generated rsa key and click OK
- in the header of the JWT observe that a `jwk` param has been added containing your public key
- send the request, observe that you have successfully accessed the admin panel
- in the response, find the URL for deleting carlos: `/admin/delete?username=carlos` change the repeater path to this and send

### JWT authentication bypass via jku header injection

Background:

```
This lab uses a JWT-based mechanism for handling sessions. The server supports the jku parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.

To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```

Part 1 Upload a malicious JWK Set:
- load the jwt editor extension
- log into your own account
- in burp history send the `GET /my-account` with you signed in JWT to repeater
- in repeater, change the path to `/admin` and send the request and notice you are blocked
- go to the `JWT editor keys` in burps main tab bar, click `new rsa key`
- in the dialog, click `generate` to automatically generate a new key pair, then click OK to save the key
- in the browser go to the exploit server, replace the body section with an empty JWK set:

```
{
    "keys": [

    ]
}
```

- back on the `jwt editor keys` tab right click on the entry for the key that you just generated then select `Copy Public Key as JWK`
- paste the jwk in to the `keys` array on the exploit server like so and store it, example:

```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
            "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw"
        }
    ]
}
```

Part 2 Modify and sign the JWT:
- Go back to the `GET /admin` request in Repeater and switch to the extension-generated `JSON Web Token` tab
- in the JWT, replace the current value of the `kid` parameter with the `kid` of the JWK that you uploaded to the exploit server
- Add a new `jku` parameter to the header of the JWT. Set its value to the URL of your JWK Set on the exploit server
- in payload change the value of the `sub` claim to `administrator`
- at the bottom of the tab click `sign` then select the rsa key that you generated in the previous section
- make sure that the `don't modify header` is selected and click `OK`
- send the request, observe that you have successfully accessed the admin panel
- in the response, find the URL for deleting carlos: `/admin/delete?username=carlos` change the repeater path to this and send

### JWT authentication bypass via kid header path traversal

Background:

```
This lab uses a JWT-based mechanism for handling sessions. In order to verify the signature, the server uses the kid parameter in JWT header to fetch the relevant key from its filesystem.

To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```

Part 1 Generate a suitable signing key:
- load the jwt editor extension
- log into your own account
- in burp history send the `GET /my-account` with you signed in JWT to repeater
- in repeater, change the path to `/admin` and send the request and notice you are blocked
- go to the `jwt editor keys` tab in burps main tab bar
- click `new symmetric key`
- in the dialog click `generate`
- replace the generated value for the `k` property with a base64 encopded null byte: `AA==`
- click ok to save it

Part 2 Modify and sign the JWT:
- Go back to the `GET /admin` request in Repeater and switch to the extension-generated `JSON Web Token`
- in the header of the JWT change the value of the `kid` param to a path traversal sequence pointing to the `/dev/null` file: `../../../../../../../dev/null`
- in the jwt payload change the value of the `sub` claim to `administrator`
- at the bottom of the tab click `sign` then select the symmetric key that you generated in the previous section
- make sure that the `don't modify header` is selected and click `OK`
- send the request, observe that you have successfully accessed the admin panel
- in the response, find the URL for deleting carlos: `/admin/delete?username=carlos` change the repeater path to this and send
