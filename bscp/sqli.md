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


