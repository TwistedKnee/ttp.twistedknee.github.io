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

















## Labs walkthrough












