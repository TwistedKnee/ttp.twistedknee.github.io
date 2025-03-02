# Web Cache Poisoning Notes

[Portswigger](https://portswigger.net/web-security/web-cache-poisoning)

## Methodology

- use a cache buster parameter to avoid poisoning arbitrary users: `?cache=1234`
- send request of main page until you see a `X-Cache: hit` or `X-Cache: miss` - this means caching is happening
- if your query parameters are reflected in the response and when changed cause a `X-Cache: miss` in the response they are keyed and you can break out of them
- test with param miner for possible hidden headers, or get requests information or just to test for any unkeyed value you can use in caching attacks
- check if the `utm_content` parameter is supported

## Labs walkthrough

### Web cache poisoning with an unkeyed header

Background: 

```This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser. ```

- go to the sites home page
- study the requests and responses that you generated, find the `GET` request for the home page and send it to repeater
- add a cache buster query parameter such as `?cb=1234`
- add the `X-Forwarded-Host` header with an arbitrary hostname such as `example.com` and send the request
- observe the `X-Forwarded-Host` header has been used to dynamically generate an absolute URL for importing a JavaScript file stored at `/resources/js/tracking.js`
- replay the request and observe that the response contains the `X-Cache: hit`, this tells us that the response came from the cache
- go to the exploit server and change the file name to match the path used by the vulnerable path `/resource/js/tracking.js`
- in the body enter the payload `alert(document.cookie)` and store it
- in repeater remove the cache buster and add the exploit server to the `X-Forwarded-Host` header
- send the malicious request, keep replaying the request until you see your exploit server URL being reflected in the response and `X-Cache: hit` in the headers
- to simulate the victim, load the poisoned URL in the browser and make sure that the `alert()` is triggered, note that you have to perform this test before the cache expires which is every 30 seconds

### Web cache poisoning with an unkeyed cookie

Background: 
```This lab is vulnerable to web cache poisoning because cookies aren't included in the cache key. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(1) in the visitor's browser.```

- go to the sites home page
- Notice that the first response you received sets the cookie `fehost=prod-cache-01`
- Reload the home page and observe that the value from the fehost cookie is reflected inside a double-quoted JavaScript object in the response
- send this to repeater and add a cache buster as a query parameter
- change the cookie to some arbitrary value and resend and observe it being reflected in the reponse
- now put a payload in the cookie like so: `fehost=someString"-alert(1)-"someString`
- Replay the request until you see the payload in the response and X-Cache: hit in the headers
- Load the URL in the browser and confirm the alert() fires
- now go back to repeater and remove the cache buster and redeliver

### Web cache poisoning with multiple headers

Background:

```This lab contains a web cache poisoning vulnerability that is only exploitable when you use multiple headers to craft a malicious request. A user visits the home page roughly once a minute. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser.```

- go to the sites home page
- in burps history find the GET request for the JavaScript file `/resources/js/tracking.js` and send to repeater
- add a cache-buster query parameter and the `X-Forwarded-Host` header with a random value, we come to the conclusion it doesn't do anything
- remove the `X-Forwarded-Host` header and add the `X-Forwarded-Scheme` header instead, notice that any value other than `HTTPS` gets a `302` response, notice in the `Location` header we are being redirected to the same URL that we requested but using `https://`
- add the `X-Forwarded-Host: example.com` header back to the request but keep the `X-Forwarded-Scheme: nothttps` as well, this time we notice that the `Location` header of the `302` redirect now points to `https://example.com/`
- go to the exploit server and change the file name to match the path used by the vulnerable response: `/resources/js/tracking.js`
- in the body enter the payload `alert(document.cookie)` and store it
- go back to the request in repeater and set the `X-Forwarded-Host` header with the exploit servers URL as the value
- set the `X-Forwarded-Scheme` header to anything but `HTTPS` so you get the redirect
- send the request until you see your exploit server URL reflected in the response and `X-Cache: hit` in the headers
- to validate that this worked, right click the request in repeater and do the `Copy URL` and open in the browser, if the alert exists in here than it worked (the alert won't actually fire here)
- go back to repeater, remove the cache buster and resend the request until you poison the cache again
- reload the home page until your alert triggers, then poison again until the user visits

### Targeted web cache poisoning using an unknown header

Background: 

```A victim user will view any comments that you post. To solve this lab, you need to poison the cache with a response that executes alert(document.cookie) in the visitor's browser. However, you also need to make sure that the response is served to the specific subset of users to which the intended victim belongs. ```

- go to the sites home page
- in burps history find the `GET` of the homepage and right-click it and in extensions use `Param Miner` with the `Guess headers` option, param miner will report back about a secret input in the form of `X-Host` header
- send this request to repeater and add a cache-buster query parameter
- add the `X-Host` header with an arbitrary hostname such as `example.com`, observe that the value of this header is used to dunamically generate a URL for importing the JavaScript file stored at `/resources/js/tracking.js`
- go to the exploit server and change the file name to match the path used by the vulnerable response `/resources/js/tracking.js`
-  In the body, enter the payload `alert(document.cookie)` and store it
-  add exploit server to the `X-Host` header and send it until you see the exploit server in the response and the `X-Cache: hit` header
-  load the URL in the browser and validate the alert triggers
-  notice that the `Vary` header is used to specify that the `User-Agent` is part of the cache key, we need to find the victims `User-Agent` to target them
-  in the website a comment functionality accepts HTML tags, post a comment with the exploit server to grab the users `User-Agent` with somehting like:  `<img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/foo" />`
-  open access log on exploit server and check until you get the users `User-Agent`
-  place the victims `User-Agent` into your repeater request, remove your cache buster and send it again until you poison with the exploit server URL in the response and it having the `X-Cache: hit` header as well

### Web cache poisoning via an unkeyed query string

Background: 

```
 This lab is vulnerable to web cache poisoning because the query string is unkeyed. A user regularly visits this site's home page using Chrome. To solve the lab, poison the home page with a response that executes alert(1) in the victim's browser
```

- load the websites home page, and send the `GET` request in burp to repeater
- Add arbitrary query parameters to the request. Observe that you can still get a cache hit even if you change the query parameters. This indicates that they are not included in the cache key
- we can add the `Origin` header as a cache buster, let's add it to the request
- when you get a cache miss, notice that you injected parameters are reflected in the response, if the response to your request is cached, remove the query parameters and they will still be reflected in the cached response
- add an arbitrary parameter that breaks out o f the reflected string and injects an XSS payload: `GET /?evil='/><script>alert(1)</script>`
- keep replaying until your payload is reflectd in the response and `X-Cache: hit` header is in the response
- remove the query string and send it again, while using the same cache buster, check that you still receive the cached response containing your payload
- remove the cache-buster `Origin` header and add your payload back to the query string, replay until you have poisoned the cache

### Web cache poisoning via an unkeyed query parameter

Background: 

```
This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. A user regularly visits this site's home page using Chrome. To solve the lab, poison the cache with a response that executes alert(1) in the victim's browser. 
```

- Observe that the home page is a suitable cache oracle. Notice that you get a cache miss whenever you change the query string. This indicates that it is part of the cache key. Also notice that the query string is reflected in the response
- Add a cache-buster query parameter
- Use Param Miner's "Guess GET parameters" feature to identify that the parameter utm_content is supported by the application
- Confirm that this parameter is unkeyed by adding it to the query string and checking that you still get a cache hit. Keep sending the request until you get a cache miss. Observe that this unkeyed parameter is also reflected in the response along with the rest of the query string
- Send a request with a utm_content parameter that breaks out of the reflected string and injects an XSS payload: `GET /?utm_content='/><script>alert(1)</script>`
- Once your payload is cached, remove the utm_content parameter, right-click on the request, and select "Copy URL". Open this URL in the browser and check that the alert() is triggered when you load the page
- Remove your cache buster, re-add the utm_content parameter with your payload, and replay the request until the cache is poisoned

### Parameter cloaking

Background: 

```
This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. There is also inconsistent parameter parsing between the cache and the back-end. A user regularly visits this site's home page using Chrome. To solve the lab, use the parameter cloaking technique to poison the cache with a response that executes alert(1) in the victim's browser. 
```

- identify that the `utm_content` parameter is supported, observe that it is also excluded from the cache key
- append another parameter using the `;` and notice the cache treats this as a single parameter, this means that the extra parameter is also excluded from the cache key, we can also just use `Param Miner` with the `Bulk Scan > Rails parameter cloaking scan` to identify the vulnerability automatically
- observe that every page imports the script `/js/geolocate.js`, executing the callback function: `setCountryCookie()` send the request `GET /js/geolocate.js?callback=setCountryCookie` to repeater
- Notice that you can control the name of the function that is called on the returned data by editing the callback parameter. However, you can't poison the cache for other users in this way because the parameter is keyed
- study this cache behavior, observe that if you add duplicate `callback` parameters, only the final one is reflected in the response, but both are stil keyed. If you append the second `callback` parameter to the `utm_content` parameter using a semicolon it is excluded from the cache key and still overwrites the callback function in the response

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=arbitraryFunction

HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
…
arbitraryFunction({"country" : "United Kingdom"})
```

- send the request again, but this time pass in `alert(1)` as the callback function: `GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)`
- get the response cached, then load the home page in the browser, check that the alert is triggered
- replay until it poisons the cache

### Web cache poisoning via a fat GET request

Background:

```
This lab is vulnerable to web cache poisoning. It accepts GET requests that have a body, but does not include the body in the cache key. A user regularly visits this site's home page using Chrome. To solve the lab, poison the cache with a response that executes alert(1) in the victim's browser
```

- Observe that every page imports the script `/js/geolocate.js`, executing the callback function `setCountryCookie()`. Send the request `GET /js/geolocate.js?callback=setCountryCookie` to repeater
- Notice that you can control the name of the function that is called in the response by passing in a duplicate callback parameter via the request body. Also notice that the cache key is still derived from the original callback parameter in the request line

```
GET /js/geolocate.js?callback=setCountryCookie
…
callback=arbitraryFunction

HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
…
arbitraryFunction({"country" : "United Kingdom"})
```

- send the request again but this time pass in `alert(1)` as the callback function
- remove any cache busters and repoison the cache

### URL normalization

Background: 

```
This lab contains an XSS vulnerability that is not directly exploitable due to browser URL-encoding. To solve the lab, take advantage of the cache's normalization process to exploit this vulnerability. Find the XSS vulnerability and inject a payload that will execute alert(1) in the victim's browser. Then, deliver the malicious URL to the victim. 
```

- browse to any non-existant path such as `GET /random` and notice your path is reflected in the error message, send this to repeater
- add a suitable reflected XSS payload to the request line: `GET /random</p><script>alert(1)</script><p>foo`
- Notice that if you request this URL in the browser, the payload doesn't execute because it is URL-encoded
- in repeater poison the cache with your payload and then immediately load the URL in the browser, this time the alert does trigger because the browsers encoded payload was RL decoded by the cache, causing a cache hit with the earlier request
- repoison the cache then immediately go to the lab and click `deliver to victim`
