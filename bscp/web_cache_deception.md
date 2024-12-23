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





## Labs Walkthrough
