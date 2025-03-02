# Web Cache Deception Notes

[Portswigger](https://portswigger.net/web-security/web-cache-deception)

[Research](https://portswigger.net/research/gotta-cache-em-all)

Delimiter list [here](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list)


## Methodology

### Constructing a web cache deception attack

- Identify a target endpoint that returns a dynamic response containing sensitive information. Review responses in Burp, as some sensitive information may not be visible on the rendered page. Focus on endpoints that support the `GET`, `HEAD`, or `OPTIONS` methods as requests that alter the origin server's state are generally not cached
- identify any discrepancies from the origin and cache in how they parse URL path, this could be:
  - Map URLs to resources
  - processes delimiter characters
  - normalize paths
- craft a malicious URL that uses this discrepancy to trick the cache into storing a dynamic response

Note: When the victim accesses the malicious URL, their response is stored in the cache. Using Burp, you can then send a request to the same URL to fetch the cached response containing the victim's data. Avoid doing this directly in the browser as some applications redirect users without a session or invalidate local data, which could hide a vulnerability
 
**Using a cache buster**

While testing for discrepancies and crafting a web cache deception exploit, make sure that each request you send has a different cache key. Otherwise, you may be served cached responses, which will impact your test results. 

As both URL path and any query parameters are typically included in the cache key, you can change the key by adding a query string to the path and changing it each time you send a request. Automate this process using the Param Miner extension. To do this, once you've installed the extension, click on the top-level `Param miner > Settings` menu, then select `Add dynamic cachebuster`. Burp now adds a unique query string to every request that you make. You can view the added query strings in the Logger tab. 

**Detecting cached responses**

Review response headers like:
- `X-Cache`
  - `X-Cache: hit` - means response served from cache
  - `X-Cache: miss` - means response served is not from cache, but in most circumstances the next request will be, send again to test
  - `X-Cache: dynamic` - means response was dynamically served, usually not a target for caching
  - `X-Cache: refresh` - means reponse cache was outdated and needed refreshing
- `Cache-Control` - header that may have information on whether the cache is public and the time limit on the cache. not always indicative of the cache and can be overriden by a cache

### Exploiting static extension cache rules

Cache rules often target static resources by matching common file extensions like .css or .js. This is the default behavior in most CDNs.

If there is a separation on how the cache and origin server deal with URL paths or use delimeters, you can abuse this. 

**Path mapping discrepancies**

URL path mapping is the process of associating URL paths with resources on a server, such as files, scripts, or command executions

Multiple types but two common are traditional URL mapping and RESTful mapping

Traditional: `http://example.com/path/in/filesystem/resource.html`
- `http://example.com` points to the server
- `/path/in/filesystem/` represents the directory path in the server's file system
- `resource.html` is the specific file being accessed

RESTful: `http://example.com/path/resource/param1/param2`
- `http://example.com` points to the server
- `/path/resource/` is an endpoint representing a resource
- `param1 and param2` are path parameters used by the server to process the request

Discrepancies in how the cache and origin server map the URL path to resources can result in web cache deception vulnerabilities. Consider the following example: `http://example.com/user/123/profile/wcd.css` 

URL will see this as a call against `/user/123/profile` to get the profile of user 123, and ignore the `wcd.css` file

While traditional will call it as a file with the direct path

**Exploiting path mapping discrepancies**

To test how the origin server maps the URL path to resources, add an arbitrary path segment to the URL of your target endpoint. If the response still contains the same sensitive data as the base response, it indicates that the origin server abstracts the URL path and ignores the added segment. For example, this is the case if modifying `/api/orders/123` to `/api/orders/123/foo` still returns order information.

To test how the cache maps the URL path to resources, you'll need to modify the path to attempt to match a cache rule by adding a static extension. For example, update `/api/orders/123/foo` to `/api/orders/123/foo.js`

Caches may have rules based on specific static extensions. Try a range of extensions, including `.css`, `.ico`, and `.exe`

You can then craft a URL that returns a dynamic response that is stored in the cache. Note that this attack is limited to the specific endpoint that you tested, as the origin server often has different abstraction rules for different endpoints. 

**Delimiter discrepancies**

Discrepancies in how the cache and origin server use characters and strings as delimiters can result in web cache deception vulnerabilities. Consider the example `/profile;foo.css`

**Java Spring Example**
An origin server that uses Java Spring would therefore interpret `;` as a delimiter. It truncates the path after `/profile` and returns profile information

A cache that doesn't use Java Spring is likely to interpret ; and everything after it as part of the path. If the cache has a rule to store responses for requests ending in .css, it might cache and serve the profile information as if it were a CSS file

**Ruby on Rails Example**
The Ruby on Rails framework, which uses `.` as a delimiter to specify the response format.
- `/profile` - This request is processed by the default HTML formatter, which returns the user profile information.
- `/profile.css` - This request is recognized as a CSS extension. There isn't a CSS formatter, so the request isn't accepted and an error is returned.
- `/profile.ico` - This request uses the .ico extension, which isn't recognized by Ruby on Rails. The default HTML formatter handles the request and returns the user profile information. In this situation, if the cache is configured to store responses for requests ending in .ico, it would cache and serve the profile information as if it were a static file.

**Encoded characters as delimiters**
Encoded characters may also sometimes be used as delimiters. For example, consider the request `/profile%00foo.js`

- An origin server that uses OpenLiteSpeed would interpret the path as `/profile`
- Most other frameworks respond with an error if `%00` is in the URL. However, if the cache uses Akamai or Fastly, it would interpret `%00` and everything after it as the path

**Exploiting delimiter discrepancies**
You may be able to use a delimiter discrepancy to add a static extension to the path that is viewed by the cache, but not the origin server. To do this, you'll need to identify a character that is used as a delimiter by the origin server but not the cache

find characters that are used as delimiters by the origin server. Start this process by adding an arbitrary string to the URL of your target endpoint. For example, modify `/settings/users/list` to `/settings/users/listaaa`. You'll use this response as a reference when you start testing delimiter characters

Next, add a possible delimiter character between the original path and the arbitrary string, for example `/settings/users/list;aaa`
- if response is the same as the base response the `;` is being processed as a delimiter
- if the reponse is the same as the arbitrary response then it was not being processed as a delimeter

 Once you've identified delimiters that are used by the origin server, test whether they're also used by the cache. To do this, add a static extension to the end of the path. If the response is cached, this indicates:

- That the cache doesn't use the delimiter and interprets the full URL path with the static extension
- That there is a cache rule to store responses for requests ending in `.js`

Test all ASCII characters and a range of common extensions, including `.css`, `.ico`, and `.exe`

Delimiter list [here](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list)

Note: To prevent Burp Intruder from encoding the delimiter characters, turn off Burp Intruder's automated character encoding under `Payload encoding` in the `Payloads` side panel

**Delimiter decoding discrepancies**

Differences in which delimiter characters are decoded by the cache and origin server can result in discrepancies in how they interpret the URL path, even if they both use the same characters as delimiters. Consider the example `/profile%23wcd.css`, which uses the URL-encoded `#` character:

- The origin server decodes `%23` to `#`. It uses `#` as a delimiter, so it interprets the path as `/profile` and returns profile information.
- The cache also uses the `#` character as a delimiter, but doesn't decode `%23`. It interprets the path as `/profile%23wcd.css`. If there is a cache rule for the .css extension it will store the response

**Exploiting delimiter decoding discrepancies**
You may be able to exploit a decoding discrepancy by using an encoded delimiter to add a static extension to the path that is viewed by the cache, but not the origin server.

Use the same testing methodology you used to identify and exploit delimiter discrepancies, but use a range of encoded characters. Make sure that you also test encoded non-printable characters, particularly `%00`, `%0A` and `%09`. If these characters are decoded they can also truncate the URL path. 

### Exploiting static directory cache rules

Cache rules often target static directories by matching specific URL path prefixes, like `/static`, `/assets`, `/scripts`, or `/images`. These rules can also be vulnerable to web cache deception. 

Discrepancies in how the cache and origin server normalize the URL can enable an attacker to construct a path traversal payload that is interpreted differently by each parser. Consider the example `/static/..%2fprofile`
- An origin server that decodes slash characters and resolves dot-segments would normalize the path to `/profile` and return profile information
- a cache that doesn't resolve dot-segments or decode slashes would interpret the path as `/static/..%2fprofile` If the cache stores responses for requests with the /static prefix, it would cache and serve the profile information

Note: an exploitable normalization discrepancy requires that either the cache or origin server decodes characters in the path traversal sequence as well as resolving dot-segments

**Detecting normalization by the origin server**

To test how the origin server normalizes the URL path, send a request to a non-cacheable resource with a path traversal sequence and an arbitrary directory at the start of the path. To choose a non-cacheable resource, look for a non-idempotent method like `POST`. For example, modify `/profile` to `/aaa/..%2fprofile`

- if you get info the same like `/profile` the dot segments and the path traversal is being processed
- if you get an error then you most likely don't have one or both dot segment or path traversal to abuse


Note: When testing for normalization, start by encoding only the second slash in the dot-segment. This is important because some CDNs match the slash following the static directory prefix. You can also try encoding the full path traversal sequence, or encoding a dot instead of the slash. This can sometimes impact whether the parser decodes the sequence.

**Detecting normalization by the cache server**

In `Proxy > HTTP history`, look for requests with common static directory prefixes and cached responses. Focus on static resources by setting the HTTP history filter to only show messages with 2xx responses and script, images, and CSS MIME types.

You can then choose a request with a cached response and resend the request with a path traversal sequence and an arbitrary directory at the start of the static path. Choose a request with a response that contains evidence of being cached. For example, `/aaa/..%2fassets/js/stockCheck.js`

- If the response is no longer cached, this indicates that the cache isn't normalizing the path before mapping it to the endpoint. It shows that there is a cache rule based on the /assets prefix.
- If the response is still cached, this may indicate that the cache has normalized the path to /assets/js/stockCheck.js

You can also add a path traversal sequence after the directory prefix. For example, modify `/assets/js/stockCheck.js` to `/assets/..%2fjs/stockCheck.js`

- If the response is no longer cached, this indicates that the cache decodes the slash and resolves the dot-segment during normalization, interpreting the path as `/js/stockCheck.js`. It shows that there is a cache rule based on the `/assets` prefix.
- If the response is still cached, this may indicate that the cache hasn't decoded the slash or resolved the dot-segment, interpreting the path as `/assets/..%2fjs/stockCheck.js`

To confirm that the cache rule is based on the static directory, replace the path after the directory prefix with an arbitrary string. For example, /assets/aaa. If the response is still cached, this confirms the cache rule is based on the /assets prefix. Note that if the response doesn't appear to be cached, this doesn't necessarily rule out a static directory cache rule as sometimes 404 responses aren't cached.

Note: It's possible that you may not be able to definitively determine whether the cache decodes dot-segments and decodes the URL path without attempting an exploit. 

**Exploiting normalization by the origin server**

If the origin server resolves encoded dot-segments, but the cache doesn't, you can attempt to exploit the discrepancy by constructing a payload according to the following structure: `/<static-directory-prefix>/..%2f<dynamic-path>`

For example, consider the payload `/assets/..%2fprofile`:

- The cache interprets the path as: `/assets/..%2fprofile`
- The origin server interprets the path as: `/profile`

The origin server returns the dynamic profile information, which is stored in the cache. 

**Exploiting normalization by the cache server**

If the cache server resolves encoded dot-segments but the origin server doesn't, you can attempt to exploit the discrepancy by constructing a payload according to the following structure: `/<dynamic-path>%2f%2e%2e%2f<static-directory-prefix>`

Note: When exploiting normalization by the cache server, encode all characters in the path traversal sequence. Using encoded characters helps avoid unexpected behavior when using delimiters, and there's no need to have an unencoded slash following the static directory prefix since the cache will handle the decoding. 

In this situation, path traversal alone isn't sufficient for an exploit. For example, consider how the cache and origin server interpret the payload `/profile%2f%2e%2e%2fstatic`:

- The cache interprets the path as: `/static`
- The origin server interprets the path as: `/profile%2f%2e%2e%2fstatic`

The origin server is likely to return an error message instead of profile information.

To exploit this discrepancy, you'll need to also identify a delimiter that is used by the origin server but not the cache. Test possible delimiters by adding them to the payload after the dynamic path:

- If the origin server uses a delimiter, it will truncate the URL path and return the dynamic information.
- If the cache doesn't use the delimiter, it will resolve the path and cache the response.

For example, consider the payload `/profile;%2f%2e%2e%2fstatic`. The origin server uses ; as a delimiter:

- The cache interprets the path as: `/static`
- The origin server interprets the path as: `/profile`

The origin server returns the dynamic profile information, which is stored in the cache. You can therefore use this payload for an exploit. 

### Exploiting file name cache rules

Certain files such as `robots.txt`, `index.html`, and `favicon.ico` are common files found on web servers. They're often cached due to their infrequent changes. Cache rules target these files by matching the exact file name string.

To identify whether there is a file name cache rule, send a `GET` request for a possible file and see if the response is cached. 

**Detecting normalization discrepancies**

To test how the origin server normalizes the URL path, use the same method that you used for static directory cache rules. 

To test how the cache normalizes the URL path, send a request with a path traversal sequence and an arbitrary directory before the file name. For example, `/aaa%2f%2e%2e%2findex.html`:

- If the response is cached, this indicates that the cache normalizes the path to `/index.html`
- If the response isn't cached, this indicates that the cache doesn't decode the slash and resolve the dot-segment, interpreting the path as `/profile%2f%2e%2e%2findex.html`

**Exploiting normalization discrepancies**

Because the response is only cached if the request matches the exact file name, you can only exploit a discrepancy where the cache server resolves encoded dot-segments, but the origin server doesn't. Use the same method as for static directory cache rules - simply replace the static directory prefix with the file name.

## Labs Walkthrough

### Exploiting path mapping for web cache deception

Background:

```
To solve the lab, find the API key for the user carlos. You can log in to your own account using the following credentials: wiener:peter
```

Identify a target endpoint
- log into the application and notice that the reponse contains your API keys

Identify a path mapping discrepancy
- find the `GET /my-account` in burp history and send to repeater, add an arbitrary value to the end of it like `/my-account/abc` and send
- Notice that you still receive a response containing your API key. This indicates that the origin server abstracts the URL path to `/my-account`
- Add a static extension to the URL path, for example `/my-account/abc.js`
- Send the request. Notice that the response contains the `X-Cache: miss` and `Cache-Control: max-age=30`
- resend and see that you get a `X-Cache: hit` response saying that the response was cached

Craft an exploit
- go to exploit server
- in the body of the server create a javascript fetch against the my-account that will be cached: `<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js"</script>`
- Click Deliver exploit to victim. When the victim views the exploit, the response they receive is stored in the cache.
- Go to the URL that you delivered to carlos in your exploit: `https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js`
- grab the API from the cache, make sure you waited the 30 seconds between testing and you delivering the exploit

### Exploiting path delimiters for web cache deception

Identify a target endpoint
- log into the application and notice that the reponse contains your API keys

Identify path delimiters used by the origin server
- in burp history send the `GET /my-account` to repeater
- add an arbitrary path to the end like `/abc` and send
- notice the `404 not found` error in the response, this indicates that the origin server doesn't abstract the path to `/my-account`
- remove the arbitrary path but add an arbitrary string to the original path like: `/my-accountabc`
- still getting a `404 not found` error in the response
- send the request to intruder, make the attack type `sniper attack` and add a payload position after `/my-account` like: `/my-account§§abc`
- use this [delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list) as the payload
- under `payload encoding` deselect `URL encode these characters` and start the attack, find responses that equal `200` which are the `?` and `;` characters

Investigate path delimiter discrepancies
- go back to repeater and add the `?` and send and review what happens, make it a static file at the end of `abc` like `abc.js` and notice that the response is telling us it was cached, now do the same with `;`
- notice that with `;` the response does have a `X-Cache: miss` header
- this will be are target to cache using similar steps as above

Craft an exploit
- go to the exploit server and add this to the body: `<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account;wcd.js"</script>`
- store it and deliver to the victim
- then visit the above url to steal the users api keys that were cached

### Exploiting origin server normalization for web cache deception

Identify a target endpoint
- log into the application and notice that the reponse contains your API keys

Identify path delimiters used by the origin server
- in burp history send the `GET /my-account` to repeater
- add an arbitrary path to the end like `/abc` and send
- notice the `404 not found` error in the response, this indicates that the origin server doesn't abstract the path to `/my-account`
- remove the arbitrary path but add an arbitrary string to the original path like: `/my-accountabc`
- still getting a `404 not found` error in the response
- send the request to intruder, make the attack type `sniper attack` and add a payload position after `/my-account` like: `/my-account§§abc`
- use this [delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list) as the payload
- under `payload encoding` deselect `URL encode these characters` and start the attack, find responses that equal `200` which is the `?` character

Investigate normalization discrepancies
- in repeater remove the arbitrary `abc` string and add an arbitrary directory followed by an encoded dot-segment to the start of the original path like: `/aaa/..%2fmy-account`
- send the request and notice the `200` response with your API key
- reivew the burp history and notice static resources are in the `/resources` directory, notice that responses with requests to the `/resources` prefix show evidence of caching
- find a request with a call to the `/resources` directory and send to repeater
- in repeater add an encoded dot-segment after the `/resources` path prefix such as `/resources/..%2fyour-resource`
- send the request and notice the `404` response which contains the `X-Cache: miss` header meaning it was cached
- modify the URL path after `/resources` to an arbitrary string like: `/resources/aaa` and send
- notice that the `404` response now has the `X-Cache: miss` header

Craft an exploit
- now craft this to directory traversal to `/my-account` on a `/resources` call like: `/resources/..%2fmy-account` and send
- notice it does give you back a `X-Cache: hit` when sent twice, indicating it was cached
- now go to exploit server and place this in: `<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/resources/..%2fmy-account?wcd"</script>`
- store it and deliver to victim
- go to the above resource path in your exploit to get carlos' API key 

### Exploiting cache server normalization for web cache deception

Identify a target endpoint
- log into the application and notice that the reponse contains your API keys

Identify path delimiters used by the origin server
- in burp history send the `GET /my-account` to repeater
- add an arbitrary path to the end like `/abc` and send
- notice the `404 not found` error in the response, this indicates that the origin server doesn't abstract the path to `/my-account`
- remove the arbitrary path but add an arbitrary string to the original path like: `/my-accountabc`
- still getting a `404 not found` error in the response
- send the request to intruder, make the attack type `sniper attack` and add a payload position after `/my-account` like: `/my-account§§abc`
- use this [delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list) as the payload
- under `payload encoding` deselect `URL encode these characters` and start the attack, find responses that equal `200` which are the `#`,`%23`,`?` and `%3f` characters

Investigate path delimiter discrepancies
- in repeater add review each delimiter while adding a `.js` extension to the end of `abc` and test sending
- notice that responses don't show evidence of caching

Investigate normalization discrepancies
- remove the query string and add an arbitrary directory followed by an encoded dot-segment to the start of the original path like: `/aaa/..%2fmy-account`
- in burp history notice that static resources are saved under `/resources` notice that responses to requests with the `/resources` shows evidence of caching
- send a `/resources` request to repeater and add that dot-segment peace like earlier: `/aaa/..%2fresources/YOUR-RESOURCE` then send it
- notice the `404` has a cache header now
- add a dot-segment path prefix to `/resources` now like: `/resources/..%2fYOUR-RESOURCE` and notice the `404` response no longer contains evidence of caching, this indicates that the cache decodes and resolves the dot-segment and has a cache rule based on the `resources` prefix

Craft an exploit
- in repeater that contains the `/aaa/..%2fmy-account` request. Use the `?` delimiter to attempt to construct an exploit like: `/my-account?%2f%2e%2e%2fresources`
- send the request and notice this receives a `200` response with your API key, but doesn't contain evidence of caching
- repeat this testing the `%23` and `%3f` characters instead of `?` notice that when you use the `%23` you get a `200` response with the caching header
- go to exploit server and place this in the body: `<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account%23%2f%2e%2e%2fresources?wcd"</script>`
- store and deliver
- go to the above link in your exploit to get carlos' api key

