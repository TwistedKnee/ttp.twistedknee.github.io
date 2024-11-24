# Path Traversal Notes

Path Traversal or Discovery Traversal

[Portswigger](https://portswigger.net/web-security/file-path-traversal)

## Methodology

When reviewing traffic look out for references to files, based on parameter name or seeing files referenced in parameters. 

### Common traversal techniques

- Use `../` or `..\` based on windows or linux. Use `.\` or `./` in between to bypass restrictions
- Direct call a file instead like `?filename=/etc/passwd`
- Use nested traversal sequences like `....//` or `....\/`
- Encode to bypass like: `%2e%2e%2f` or double encode like `%252e%252e%252f`
- Maybe include base folder then traversal like: `filename=/var/www/images/../../../etc/passwd`
- Validation of path, end with a null byte before filetype to bypass filetype restrictions: `filename=../../../etc/passwd%00.png`

## Labs Walkthrough

### File path traversal, simple case

- intercept and send to repeater a call that fetches a product image
- Modify the filename parameter, giving it the value: `../../../etc/passwd`

### File path traversal, traversal sequences blocked with absolute path bypass

- same as above, send image request and modify the filename to `/etc/passwd`

### File path traversal, traversal sequences stripped non-recursively

- again in same call that fetches a product image modify the filename to `....//....//....//etc/passwd`

### File path traversal, traversal sequences stripped with superfluous URL-decode

- again in same call that fetches a product image modify the filename to `..%252f..%252f..%252fetc/passwd`

### File path traversal, validation of start of path

- again in same call that fetches a product image modify the filename to `/var/www/images/../../../etc/passwd`

### File path traversal, validation of file extension with null byte bypass

- again in same call that fetches a product image modify the filename to `../../../etc/passwd%00.png`
