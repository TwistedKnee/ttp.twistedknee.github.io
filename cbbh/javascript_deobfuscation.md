# Javascript Deobfuscation Notes

## Source code

We can view the source code of a web page with CTRL+U

JavaScript is displayed in between <script> elements or written in a seperate .js file

## Obfuscation

Code Obfuscation is a technique used to make a script more difficult to read, but it still is functional. 

### Basic Obfuscation

Code minification is a technique that transforms the code into a single line of code. Online [TOOL](https://www.toptal.com/developers/javascript-minifier)
Most minified JavaScript is saved with the extension `.min.js`

### Packing JavaScript

We can use this tool to pack our JavaScript [TOOL](https://beautifytools.com/javascript-obfuscator.php)

Then afterwards we can copy this into [jsconsole](https://jsconsole.com/) and verify the code does its main function

This is an example of a packer being used to replace all words and symbols of the code into a list or a dictionary, and reference them.


### Advanced Obfuscation

We can use [obfuscator.io](https://obfuscator.io/) and we can use it by changing `String Array Encoding` to `Base64`

Then paste example code and click obfuscate. We can still use jsconsole to verify that the code still does what we want. 

Other obfuscation tools: [jsfuck](https://jsfuck.com/), [jj encode](https://utf-8.jp/public/jjencode.html), and [aaencode](https://utf-8.jp/public/aaencode.html)

## Deobfuscation

Tools we can use to deobfuscate code

### Beautify 

so we can use [Prettier](https://prettier.io/playground/) or [Beautifier](https://beautifier.io/)

## Deobfuscate

Here we can use tools that try to deobfuscate the code like [Unpacker](https://matthewfl.com/unPacker.html)

## Code Analysis

### HTTP Requests

example code:
```
'use strict';
function generateSerial() {
  ...SNIP...
  var xhr = new XMLHttpRequest;
  var url = "/serial.php";
  xhr.open("POST", url, true);
  xhr.send(null);
};
```

This is from deobfuscated code from steps above, we can see that there is a POST request to `/serial.php` being referenced. We can go further in attempting to abuse this. We can test using curl to see what values we get. 

```
curl -w "\n" -s http://<server>/<port>/serial.php -X POST
```

We can also do the request with post data to see the behavior
```
curl -w "\n" -s http://<server>/<port>/serial.php -X POST -d "param1=sample"
```

## Decoding

For continuity we will assume a base64 value was returned from above. You can use hasid to identify a type of hasing/encoding

```
hashid <value>
```

### Base64
base64 is pretty easy to spot by the use of `=` being padding characters.

We can encode with base64 in linux cmd like so

```
echo <value> | base64
```

Decode

```
echo <value> | base64 -d
```

### Hex

Another common encoding method. Encodes each character into it's hex order in the ASCII table. All characters would be hex values which are `0-9 and a-f`

Encoding

```
echo <value> | xxd -p
```

Decoding

```
echo <value> | xxd -p -r
```

### Caeser/Rot13

This just rotates a value from where it is in the alphabet to the character that many steps from it. So encoding `a` will become `b` if the value is 1 to shift from. Common one for this is rot13.

Encoding

```
echo <value> | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Decooding, we can use the same since rot13 of rot13 will result in the same values. 

```
echo <value> | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

## Other tools

You can use other tools like [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier) to try and identify other ciphers
