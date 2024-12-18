# NoSQL Injection Notes

[Portswigger](https://portswigger.net/web-security/nosql-injection)

## Methodology

Two types of NoSQL injection:
- syntax injection - when you break NoSQL query syntax, enabling you to inject your own paylod. similar to SQL injection
- operator injection - when you can use NoSQL query operators to manipulate queries

To detect NoSQL injection vulnerabilities by attempting to break the query syntax. To do this, systematically test each input by submitting fuzz strings and special characters that trigger a database error or some other detectable behavior if they're not adequately sanitized or filtered by the application. 

### Detecting syntax injection in MongoDB

If you have an app that is doing an API call like: `https://insecure-website.com/product/lookup?category=fizzy`

We can defer that it is doing a query like: `this.category == 'fizzy'`

Sample fuzz string test:

```
'"`{
;$Foo}
$Foo \xYZ
```

Attack will look like: `https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00`

In this example, we're injecting the fuzz string via the URL, so the string is URL-encoded. In some applications, you may need to inject your payload via a JSON property instead. In this case, this payload would become 

```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

## Labs walkthrough
