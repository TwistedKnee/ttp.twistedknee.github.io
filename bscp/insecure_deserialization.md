# Insecure Deserialization Notes

[Portswigger](https://portswigger.net/web-security/deserialization)

Tools: Hackvertor from BApp, and ysoserial for gadget chain exploitation

## Methodology

- burp scanner will flag if it identified possible serialized objects
- when serialized data is identified, attempt to find values you might want to change, like boolean values for isAdmin
- modify the data types itself
- use the hackvertor extension for useage of binary formats

### PHP serialization format

letters represent the data type and numbers representing the length of each entry, for example consider a `User` object with the attributes

```
$user->name = "carlos";
$user->isLoggedIn = true;
```

when serialized, thisobject may look something like this:

```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

This can be interpreted as follows:

    O:4:"User" - An object with the 4-character class name "User"
    2 - the object has 2 attributes
    s:4:"name" - The key of the first attribute is the 4-character string "name"
    s:6:"carlos" - The value of the first attribute is the 6-character string "carlos"
    s:10:"isLoggedIn" - The key of the second attribute is the 10-character string "isLoggedIn"
    b:1 - The value of the second attribute is the boolean value true

The native methods for PHP serialization are serialize() and unserialize(). If you have source code access, you should start by looking for unserialize() anywhere in the code and investigating further. 

### Java serialization format

Java, use binary serialization formats. This is more difficult to read, but you can still identify serialized data if you know how to recognize a few tell-tale signs. For example, serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `rO0` in Base64.

Any class that implements the interface java.io.Serializable can be serialized and deserialized. If you have source code access, take note of any code that uses the readObject() method, which is used to read and deserialize data from an InputStream

### Magic Methods

Magic methods are a special subset of methods that you do not have to explicitly invoke. Instead, they are invoked automatically whenever a particular event or scenario occurs


## Labs walkthrough

### Modifying serialized objects

Background:

```
This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user carlos.
```

you have creds

- log in with your own creds, notice the post-login `GET /my-account` request contains a session cookie that appears to be URL and base64-encoded
- using burps inspector panel to study the request in its decoded form notice that the cookie is a serialized PHP object, the admin attribute contains `b:0` indicating the boolean value `false` send this to repeater
- in burp repeater use the inspector to examine the cookie again and change the value of the `admin` attribute to `b:1`, click `apply changes` which will update it in the request and send the request
- notice we now see a link to the admin panel at `/admin`, change your path to this `/admin` and send it, in the response we see the delete functionality we can use to delete carlos
- chang endpoint to `/admin/delete?username=carlos` and send

### Modifying serialized data types

Background: 

```
This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result. To solve the lab, edit the serialized object in the session cookie to access the administrator account. Then, delete the user carlos.

Hint: To access another user's account, you will need to exploit a quirk in how PHP compares data of different types. Note that PHP's comparison behavior differs between versions. This lab assumes behavior consistent with PHP 7.x and earlier.
```
you have creds

- log in with your creds and open the post-login `GET /my-account` request and examine the session cookie using the inspector to reveal a serialized PHP object, send this to repeater
- in repeater use the inspector panel to modify the session cookie as follows, making it look like: `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`

```
Update the length of the username attribute to 13.
Change the username to administrator.
Change the access token to the integer 0. As this is no longer a string, you also need to remove the double-quotes surrounding the value.
Update the data type label for the access token by replacing s with i.
```

- click `apply changes` this will update the request
- send the request and notice we can see the `/admin` link in the response, change your path to this and send
- see the delete functionality path, update it as such: `/admin/delete?username=carlos`

### Using application functionality to exploit insecure deserialization

Background: 

```
This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the morale.txt file from Carlos's home directory.
You can log in to your own account using the following credentials: wiener:peter
You also have access to a backup account: gregg:rosebud 
```

- log into your own account, on the `my account` page notice the option to delete your account by sending a `POST` request to `/my-account/delete`
- send a request containing a session cookie to repeater
- in repeater study the cookie using the inspector panel, notice that the serialized object has an `avatar_link` attribute, which contains the file path to your avatar
- edit the serialized data so that the `avatar_link` points to `/home/carlos/morale.txt`, remember to update the length indicator, the modified attribute should look like this: `s:11:"avatar_link";s:23:"/home/carlos/morale.txt"`
- click `apply changes` this updates the request
- change the request line to `POST /my-account/delete` and send the request, this will delete your account and the morale.txt

### Arbitrary object injection in PHP

Background: 

```
This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the morale.txt file from Carlos's home directory. You will need to obtain source code access to solve this lab.

You can log in to your own account using the following credentials: wiener:peter
Hint: You can sometimes read source code by appending a tilde (~) to a filename to retrieve an editor-generated backup file. 
```

- log into your own account and notie the session cookie contains a serialized PHP object
- from the site map, notice that the website references the file `/libs/CustomTemplate.php` right clik on the file and select `send to repeater`
- in repeater notice that you can read the source code by appending a tilde `~` to the filename in the request line
- in the source code, notice the `CustomTemplate` class contains the `__destrict()` magic method, this will invoke the `unlink()` method on the `lock_file_path` attribute which will delete the file on this path
- in burp decoder use the correct syntax for serialized PHP data to create a `CustomTemplate` object with th `lock_file_path` attribute set to `/home/carlos/morale.txt`, make sure to use the correct data type labels and length indicators, looking like this: `O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}`
- base64 and url encode this object and save it to your clipboard
- send a request containing the cookie session to burp repeater
- in repeater replace the session cookie with the modified one in your clipboard
- send the request, this will cause the magic method to delete carlos' file

### Exploiting Java deserialization with Apache Commons

Background: 

```
This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains. To solve the lab, use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory.
You can log in to your own account using the following credentials: wiener:peter

Hint: 
In Java versions 16 and above, you need to set a series of command-line arguments for Java to run ysoserial. For example:
java -jar ysoserial-all.jar \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens=java.base/java.net=ALL-UNNAMED \
   --add-opens=java.base/java.util=ALL-UNNAMED \
   [payload] '[command]'

```

- log into your own account and observe the session cookie contains a serialized Java object, send a request containing your session cookie to repeater
- download the ysoserial tool and execute the following command: 

In Java versions 16 and above:
```
java -jar ysoserial-all.jar \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens=java.base/java.net=ALL-UNNAMED \
   --add-opens=java.base/java.util=ALL-UNNAMED \
   CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

java 15 and below:
```
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

- in repeater replace your session cookie with the malicious one you just created, select the entire cookie and URL encode it then send it

### Exploiting PHP deserialization with a pre-built gadget chain

Background:

```
This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's insecure deserialization using pre-built gadget chains.

To solve the lab, identify the target framework then use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, work out how to generate a valid signed cookie containing your malicious object. Finally, pass this into the website to delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials: wiener:peter 
```

- log in and send a request cointaining your session cookie to repeater, highlight the cookie and look at it in the inspector panel
- notice the cookie contains a base64 encoded token signed with a SHA-1 HMAC hash
- copy the decoded cookie from inspector and paste it into decoder
- decode it as base64, and notice the token is actually a serialized PHP object
- in repeater observe that if you try sending a request with a modified cookie an exception is reasied because the digital signature no longer matches, however in the error message we get a dev comment showing a debug file at `/cgi-bin/phpinfo.php` and it revealing the site is using `Symfony 4.3.6`
- request the `/cgi-bin/phpinfo.php` file in repeater and observe that it leaks some key information about the website, including the `SECRET_KEY` environment variable, save this key
- download the [PHPGGC tool](https://github.com/ambionics/phpggc) and execute the following command: `./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64`
- now we need to construct a valid cookie containing this malicious object and sign it correctly using the secret key you obtained earlier, you can use the following PHP script to do this, just make sure to assign the object you generated in PHPGCC to the `$object` variable, and assign the secret_key that you copied from the phpinfo.php file to the `$secretKey` variable

```
<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```

- in repeater replace your session cookie with the malicious one you just created then send it

### Exploiting Ruby deserialization using a documented gadget chain

Background: 

```
This lab uses a serialization-based session mechanism and the Ruby on Rails framework. There are documented exploits that enable remote code execution via a gadget chain in this framework.

To solve the lab, find a documented exploit and adapt it to create a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials: wiener:peter

Hint: Try searching for "ruby deserialization gadget chain" online. 
```

- log into your own account and notice that the session cookie contains a serialized "marshalled" ruby object, send a request containing this to repeater
- browse the web to find the `Universal Deserialization Gadget for Ruby 2.x-3.x` by `vakzz` on `devcraft.io` copy the final script for generating the payload
- modify the script as follows:
    - change the command from `id` to `rm /home/carlos/morale.txt`
    - replace the final two lines with `puts Base64.encode64(payload)`
- run the script and copy the resulting Base64 object and replace the session cookie in repeater with it and send it 
