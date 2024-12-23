# Web Cache Deception Notes

[Portswigger](https://portswigger.net/web-security/web-cache-deception)

[Research](https://portswigger.net/research/gotta-cache-em-all)

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
- X-Cache
  - `X-Cache: hit` - means response served from cache
  - `X-Cache: miss` - means response served is not from cache, but in most circumstances the next request will be, send again to test
  - `X-Cache: dynamic` - means response was dynamically served, usually not a target for caching
  - `X-Cache: refresh` - means reponse cache was outdated and needed refreshing



## Labs Walkthrough
