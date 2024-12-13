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




## Labs walkthrough






















