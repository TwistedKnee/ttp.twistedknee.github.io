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

- log into the application with provided creds, and update your email address
- in burp history send the `PATCH /api/user/wiener` request to repeater
- in repeater notice that this retrieves credentials for `wiener`, now remove the wiener from it and send just `/api/user`, this returns an error, now just do `/api` and this gets back the api documentation
- right click the response and select `show response in browser` and open this in the browser
- to solve click on the `DELETE` row in the documentaiton and enter `carlos` and send it

### Exploiting server-side parameter pollution in a query string

- trigger a password reset for the administrator account in the application
- in burp history find the `POST /forgot-password` request in the `/static/js/forgotPassword.js` JavaScript file, send this request to repeater
- in repeater resend to see the response is consistent
- change the username to an invalid value like `administratorx`, send and notice you get an `invalid account` error
- add a second parameter-value pair to the server-side request using a URL-encoded & character. For example, add URL-encoded `&x=y`: `username=administrator%26x=y`, send and notice the `Parameter is not supported error message` meaning the parameter was evaluated separately instead of as the username variable
- Attempt to truncate the server-side query string using a URL-encoded `#` character: `username=administrator%23`, notice the `field is not supported` error message, meaning that their exists a `field` parameter that was excluded by the `#` value
- Truncate the query string after the added parameter-value pair. For example, add URL-encoded `&field=x#`: `username=administrator%26field=x%23`, Send the request. Notice that this results in an `Invalid field` error message. This suggests that the server-side application may recognize the injected field parameter
- send this request to intruder and select the `x` in the above `username=administrator%26field=x%23` parameter to brute force it, use the `Server-side variable names` list in intruder and start the attack. Notice the `200` requests to see `email` and `username` are valid parameters
- now in repeater add `email` to the `field` variable: `username=administrator%26field=email%23`, this returns a normal value meaning it is a valid field
- review the `/static/js/forgotPassword.js` file again and notice the `reset_token` like `/forgot-password?reset_token=${resetToken}`
- in repeater change the values to include the `reset_token` value instead of `email`: `username=administrator%26field=reset_token%23`, send and notice this gives you a reset token value
- now in the browser add your password reset token as the value of the `reset_token` parameter . For example: `/forgot-password?reset_token=123456789`, reset the administrator's password
- log in as administrator and delete the carlos user

### Finding and exploiting an unused API endpoint

Background:

```
To solve the lab, exploit a hidden API endpoint to buy a Lightweight l33t Leather Jacket. You can log in to your own account using the following credentials: wiener:peter
```

- in the lab go to a product
- in repeater notice the `/api/products/3/price` API, send this to repeater
- in repeater change the `GET` HTTP header to `OPTIONS` and send, notice the `PATCH` option, change the request to this
- notice you get an `unauthorized` error
- in the browser, log in with wiener's credentials
- now select the `Lightweight "l33t" Leather Jacket` product and in burps history find the `/API/products/1/price` and send to repeater
- change the HTTP method to `PATCH` and send, notice the error saying `content-type` isn't `application/json`
- in repeater change the content type to `application/json` and include an empty json value in the body `{}` and send
- notice the error saying no `price` value is present in the json, change the body of it too `{"price": 0}` and send
- now in the browser refresh the jacket's page and notice the price is now `$0` add this to your cart and buy it to finish

### Exploiting a mass assignment vulnerability

Background:

```
To solve the lab, find and exploit a mass assignment vulnerability to buy a Lightweight l33t Leather Jacket. You can log in to your own account using the following credentials: wiener:peter
```

- log into the application and select the `Lightweight "l33t" Leather Jacket` product, add it to your cart and attempt to buy it
- notice that you don't have enough store credit to buy
- in burps history notice both the `GET` and `POST` API requests for `/api/checkout`
- Notice that the response to the `GET` request contains the same JSON structure as the `POST` request. Observe that the JSON structure in the `GET` response includes a `chosen_discount` parameter, which is not present in the `POST` request
- send the `POST /api/checkout` request to repeater
- add the chosen_discount parameter to the request. The JSON should look like the following

```
{
    "chosen_discount":{
        "percentage":0
    },
    "chosen_products":[
        {
            "product_id":"1",
            "quantity":1
        }
    ]
}
```

- send the request and notice you receive no error, indicating it is being processed fine
- Change the `chosen_discount` value to the string `x`, then send the request. Observe that this results in an error message as the parameter value isn't a number. This may indicate that the user input is being processed
- Change the `chosen_discount` percentage to `100`, then send the request to solve the lab

