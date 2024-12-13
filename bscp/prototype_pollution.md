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



## Labs walkthrough




































