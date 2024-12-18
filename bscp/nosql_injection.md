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

### Determining which characters are processed

inject individual characters to determine if they are interpreted as syntax by the application, this is testing the `'` character: `this.category == '''`

can confirm by escaping the character with `\` in the query: `this.category == '\''`

if this doesn't cause a syntax error, this means you might have an injection attack possibility

### Confirming conditional behavior

next step is to determine whether you can influence boolean conditions using NoSQL syntax

send two requests, one with a false condition and one with a true condition. For example you could use the conditional statements `' && 0 && 'x` and `' && 1 && 'x`

Like:
```
https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x
https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x
```

### Overriding existing conditions

you can attempt to override existing conditions to exploit the vulnerability. For example, you can inject a JavaScript condition that always evaluates to true, such as `'||'1'=='1`

```
https://insecure-website.com/product/lookup?category=fizzy%27%7c%7c%27%31%27%3d%3d%27%31
```

This results in the following MongoDB query: 

```
this.category == 'fizzy'||'1'=='1'
```

As the injected condition is always true, the modified query returns all items. This enables you to view all the products in any category, including hidden or unknown categories. 

**Null character testing**

You can also add a null character after the category value, the DB may ignore all characters after a null character

```
https://insecure-website.com/product/lookup?category=fizzy'%00
```

### NoSQL operator injection
















## Labs walkthrough


































