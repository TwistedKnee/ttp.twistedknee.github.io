# Essential Skills Notes

[Portswigger](https://portswigger.net/web-security/essential-skills)

## Methodology

### Obfuscating attacks using encodings

[obfuscating portswigger](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)

### Context-specific decoding

Example, a query parameter is typically URL decoded server-side, while the text content of an HTML element may be HTML decoded client-side

### URL encoding

Occasionally, you may find that WAFs and suchlike fail to properly URL decode your input when checking it. In this case, you may be able to smuggle payloads to the back-end application simply by encoding any characters or words that are blacklisted. For example, in a SQL injection attack, you might encode the keywords, so `SELECT` becomes `%53%45%4C%45%43%54` and so on

### Obfuscation via double URL encoding

Let's say you're trying to inject a standard XSS PoC, such as `<img src=x onerror=alert(1)>`, via a query parameter. In this case, the URL might look something like this:

`[...]/?search=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E`

When checking the request, if a WAF performs the standard URL decoding, it will easily identify this well-known payload. The request is blocked from ever reaching the back-end. But what if you double-encode the injection? In practice, this means that the % characters themselves are then replaced with `%25`:

`[...]/?search=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E`

### Obfuscation via HTML encoding













## Labs walkthrough












