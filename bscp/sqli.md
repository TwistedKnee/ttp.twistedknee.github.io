# SQL Injection Notes

This will be the start of the SQL injection notes from the portswigger web security academy. I will just be listing walkthroughs and methodologies from the labs. Read the material for background information or watch.

Tips for exam: If 'Advanced Search' is used privilege escalation will be easy. 

Cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet 

Injection points to consider:

- search parameters
- cookie values
- url parameters

## Labs walkthrough sections

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

Similar methodology steps as the above UNION for Oracle but with # as the comment

```
' UNION SELECT NULL#
' UNION SELECT NULL,NULL#
```
