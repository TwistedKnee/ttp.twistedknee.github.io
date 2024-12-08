# Web Cache Poisoning Notes

[Portswigger](https://portswigger.net/web-security/web-cache-poisoning)

## Methodology

- use a cache buster parameter to avoid poisoning arbitrary users: `?cache=1234`
- send request of main page until you see a `X-Cache: hit` or `X-Cache: miss` - this means caching is happening

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

### 




