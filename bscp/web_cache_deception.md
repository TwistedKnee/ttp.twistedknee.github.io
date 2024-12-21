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







## Labs Walkthrough
