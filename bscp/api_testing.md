# API Testing Notes

[Portswigger](https://portswigger.net/web-security/api-testing)

## Methodology

### API recon

you need to discover its attack surface, to begin you should identify API endpoints. This can be something like: 

```
GET /api/books HTTP/1.1
Host: example.com
```

The API endpoint for this request is `/api/books` this resulsts in an interaction with the API to retrieve a list of books from a library. Another API endpoint might be, `/api/books/mystery` which would retrieve a list of mystery books.

Next find out how to interact with them, find these details:
- what input data the API processes, including both compulsory and optional params
- the types of request the API accepts, including supported HTTP methods and media formats
- rate limits and auth mechanisms

### API Documentation

**Discovering API documentation**

even if the API isn't discoverable you can use burp scanner to crawl the API, you can also browse applications manually using burps browser, look for endpoints that ay refer to API docs: 
- /api
- /swagger/index.html
- /openapi.json

If you identify an ednpoint for a resource, make sure to investigate the base path, like these:
- /api/swagger/v1
- /api/swagger
- /api

You can also use a list of common paths to find documentation using Intruder

**Using machine readable documentation**

You can use a range of automated tools to analyze any machine readable API docs that you find. Using the OpenAPI Parser extension in burp makes this easier, or use Postman or SoapUI. Another I like is Bruno.

### Identifying API endpoints

























## Labs walkthrough


































