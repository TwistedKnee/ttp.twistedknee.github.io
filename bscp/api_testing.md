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

Use burp scanner to crawl the application, then manually investigate interesting attack surface. While browsing the applicaiton, look for patterns that suggest API endpoints in the URL structure, such as `/api/`, also look out for JavaScript files, these can cotain references to API endpoints you haven't triggered directly via the web browser. Burp scanner will do some of this, but the extension `JS link Finder` can do a more heavy extraction. You can also manually review JavaScript files in burp.

### Interacting with API endpoints

Use repeater and intruder to interact with the API's, this enables you to observe the APIs behavior and discover additional attack surface. Like changing the HTTP method or media type. While reviewing keep an eye on error messages and other responses closely. 

**Identifying supported HTTP methods**

HTTP method specifies the action to be performed:
- GET - retrieves data
- PATCH - applies partial changes to a resource
- OPTIONS - retrieves the methods that are allowed on a resource

Make sure to test all potential methods when you're investigating API endpoints.

Note: You can use the intruders built-in `HTTP verbs` list to test all these types of methods

**Identifying supported content types**

API endpoints often expect data in a specific format, changing the content type may:
- trigger errors that disclose useful information
- bypass flawed defenses
- take advantage of differences in processing logic, example: an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML

Again the `Content type converter` extension exists to make this easier.

**Using intruder to find hidden endpoints**

can use intruder to test endpoints that might not be exposed, like seeing a `PUT /api/user/update` put the fuzz around `/update` with a list of values like `delete` and `add`. Whichever fits right based on your previous recon. 

### Finding hidden parameters

Multiple tools in burp to find parameters:
- burp intruder can be used to brute force parameters
- the param minder burp extension can automatically guess a large number
- the content discovery tool enables you to discover content that isn't linked from visible content that you can browse to including parameters

### Mass assignment vulnerabilities

**Identifying hidden parameters**

Mass assignment creates parameters from object fields, you can identify these hidden parameters by manually examining objects returned by the API.

Example: a call against `PATCH /api/users` only includes this:

```
{
    "username": "wiener",
    "email": "wiener@example.com",
}
```

but a `GET /api/users/123` returns this:

```
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "isAdmin": "false"
}
```

this may indicate that the hidden `id` and `isAdmin` params are bound to the internal user object, alongside the updated username and email params

**testing mass assignment vulnerabilities**

to test whether you can modify the `isAdmin` param value, just add it to the `PATCH` request:

```
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": false,
}
```

In addition, send a `PATCH` request with an invalid `isAdmin` param value:

```
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": "foo",
}
```

if the application behaves differently, this may indicate that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user. Now just send the request with `isAdmin` as true and you escalated your privileges.


## Labs walkthrough

### Exploiting an API endpoint using documentation
































