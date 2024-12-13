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

In HTML documents, certain characters need to be escaped or encoded to prevent the browser from incorrectly interpreting them as part of the markup. This is achieved by substituting the offending characters with a reference, prefixed with an ampersand and terminated with a semicolon. In many cases, a name can be used for the reference. For example, the sequence &colon; represents a colon character.

Alternatively, the reference may be provided using the character's decimal or hex code point, in this case, `&#58;` and `&#x3a;` respectively.

If you look closely at the XSS payload from our earlier example, notice that the payload is being injected inside an HTML attribute, namely the onerror event handler. If the server-side checks are looking for the alert() payload explicitly, they might not spot this if you HTML encode one or more of the characters: `<img src=x onerror="&#x61;lert(1)">`

**Leading zeros**

when using decimal or hex-style HTML encoding you can optionally include an arbitrary number of leading zeros in the code points, some wafs and other input filters fail to adequately account for this

if your payload still gets blocked after HTML encoding, you may find that you can evadet he filter just by prefixing the code points with a few zeros: `<a href="javascript&#00000000000058;alert(1)">Click me</a>`

### Obfuscation via XML encoding

XML is closely related to HTML and also supports character encoding using the same numeric escape sequences. This enables you to include special characters in the text content of elements without breaking the syntax, which can come in handy when testing for XSS via XML-based input, for example.

Even if you don't need to encode any special characters to avoid syntax errors, you can potentially take advantage of this behavior to obfuscate payloads in the same way as you do with HTML encoding. The difference is that your payload is decoded by the server itself, rather than client-side by a browser. This is useful for bypassing WAFs and other filters, which may block your requests if they detect certain keywords associated with SQL injection attacks. 

```
<stockCheck>
    <productId>
        123
    </productId>
    <storeId>
        999 &#x53;ELECT * FROM information_schema.tables
    </storeId>
</stockCheck>
```

### Obfuscation via unicode escaping

Unicode escape sequences consist of the prefix `\u` followed by the four digit hex code for the character, for example: `\u003a` represents a colon, ES6 alos supports new form of unicode escape using curly braces: `\u{3a}`

let's say you're trying to exploit DOM XSS where your input is passed to the eval() sink as a string. If your initial attempts are blocked, try escaping one of the characters as follows: `eval("\u0061lert(1)")`

Note: Inside a string, you can escape any characters like this. However, outside of a string, escaping some characters will result in a syntax error. This includes opening and closing parentheses, for example.

Worth noting that the ES6-style unicode escapes also allow optional leading zeros, so some WAFs may be easily fooled using the same technique we used for HTML encodings. For example: `<a href="javascript:\u{00000000061}alert(1)">Click me</a>`

### Obfuscation via hex escaping
Another option when injecting into a string context is to use hex escapes, which represent characters using their hexadecimal code point, prefixed with \x. example: `a` is represented as `\x61`

like so: `eval("\x61lert")`

note that you can sometimes also obfuscate SQL statements in a similar manner using the prefix: `0x` example: `0x53454c454354` is `SELECT`

### Obfuscation via octal escaping

Octal escaping works in pretty much the same way as hex escaping, except that the character references use a base-8 numbering system rather than base-16. These are prefixed with a standalone backslash, meaning that the lowercase letter `a` is represented by `\141`: `eval("\141lert(1)")`

### Obfuscation via multiple encodings

can combine multiple encodings together to avoid filters, like so: `<a href="javascript:&bsol;u0061lert(1)">Click me</a>`

which is HTML encoded the `&bsol;,` to a backslash, `u0061` are unicode escaped for the `a` value, which means the above gets treated as: `<a href="javascript:alert(1)">Click me</a>`

Clearly, to successfully inject a payload in this way, you need a solid understanding of which decoding is performed on your input and in what order.

### Obfuscation via the SQL CHAR() function

You may be able to obfuscate SQL injection attacks using the CHAR() function, which can take decimal or hex code and resolves them. So `CHAR(83)` and `CHAR(0x53)` both equal `S`, by concatenating these values you can bypass things: `CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)` is `SELECT`

When this is processed as SQL by the application, it will dynamically construct the SELECT keyword and execute the injected query

### Using Burp scanner during manual testing

**Scanning a specific request**

You can right click on a request and select `Do active scan` which will have burp use its default config to audit only this request

Even if you already use Burp Scanner to run a general crawl and audit of new targets, switching to this more targeted approach to auditing can massively reduce your overall scan time

**Scanning custom insertion points**

you can even highlight specific insertion points and select `scan selected insertion point` to scan a specific value, like a header or paramater

**scanning non-standard data structures**

When dealing with common formats, such as JSON, Burp Scanner is able to parse the data and place payloads in the correct positions without breaking the structure. However, consider a parameter that looks something like this:
`user=048857-carlos`

Using our intuition, we can take a guess that this will be treated as two distinct values by the back-end: an ID of some kind and what appears to be a username, separated by a hyphen. However, Burp Scanner will treat this all as a single value. As a result, it will just place payloads at the end of the parameter, or replace the value entirely.

To help scan non-standard data structures, you can scan a single part of a parameter. In this example you may want to target carlos. You can highlight carlos in the message editor, then right-click and select `Scan selected insertion point`


## Labs walkthrough

### Discovering vulnerabilities quickly with targeted scanning

Background:

```
This lab contains a vulnerability that enables you to read arbitrary files from the server. To solve the lab, retrieve the contents of /etc/passwd within 10 minutes.

Due to the tight time limit, we recommend using Burp Scanner to help you. You can obviously scan the entire site to identify the vulnerability, but this might not leave you enough time to solve the lab. Instead, use your intuition to identify endpoints that are likely to be vulnerable, then try running a targeted scan on a specific request. Once Burp Scanner has identified an attack vector, you can use your own expertise to find a way to exploit it. 
```

Hint: `If you get stuck, try looking up our Academy topic on the identified vulnerability class. `




















