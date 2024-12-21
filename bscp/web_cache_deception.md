# Web Cache Deception Notes

[Portswigger](https://portswigger.net/web-security/web-cache-deception)

[Research](https://portswigger.net/research/gotta-cache-em-all)

## Methodology

### Constructing a web cache deception attack

- Identify a target endpoint that returns a dynamic response containing sensitive information. Review responses in Burp, as some sensitive information may not be visible on the rendered page. Focus on endpoints that support the `GET`, `HEAD`, or `OPTIONS` methods as requests that alter the origin server's state are generally not cached





## Labs Walkthrough
