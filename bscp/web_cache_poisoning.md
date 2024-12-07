# Web Cache Poisoning Notes

[Portswigger](https://portswigger.net/web-security/web-cache-poisoning)

## Methodology

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

###   



