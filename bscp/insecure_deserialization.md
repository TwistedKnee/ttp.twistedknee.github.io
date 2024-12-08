# Insecure Deserialization Notes

[Portswigger](https://portswigger.net/web-security/deserialization)

## Methodology

- burp scanner will flag if it identified possible serialized objects

### PHP serialization format

letter represent the data type and numbers representing the length of each entry, for example consider a `User` object with the attributes

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



## Labs walkthrough
