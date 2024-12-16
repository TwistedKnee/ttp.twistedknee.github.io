# Race Conditions Notes

[Portswigger](https://portswigger.net/web-security/race-conditions)

[Research](https://portswigger.net/research/smashing-the-state-machine)

## Methodology

### Detecting and exploiting limit overrun race conditions with Burp Repeater

- identify a single use or rate limited endpoint that has some kind of security impact or other useful purpose
- issue multiple requests to this endpoint in quick succession to see if you can overrun this limit

Details on how to send multiple requests in parallele [here](https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group#sending-requests-in-parallel)

### Detecting and exploiting limit overrun race conditions with Turbo Intruder

To use the single-packet attack in Turbo Intruder: 
- ensure that the target supports HTTP/2, the single packet attack is incompatible with HTTP/1
- set the `engine=Engine.BURP2` and `concurrentConnections=1` configuration options for the request engine
- when queueing your requests, group them by assigning them to a named gate using the `gate` argument for the `engine.queue()` method
- to send all of the requests in a given group, open the respective gate with the `engine.openGate()` method

```
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )
    
    # queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    # send all requests in gate '1' in parallel
    engine.openGate('1')

```

For more details, see the `race-single-packet-attack.py` template provided in Turbo Intruder's default examples directory

### Steps to follow for methodology

**1 - Predict potential collisions**

Map the target as usual, then ask these questions about the requests:
- is this endpoint security critical? many endpoints don't touch critical functionality so they're not worth testing
- is there any collision potential? for a successful collision, you typically need two or more requests that trigger opertaions on the same record, for example considuer the following variations of a password reset implementation. Send two seperate requests with `session=b94` and `userid=hacker` for one and `userid=victim` for the second

Think about how in this case, if having the userid's of both being sent at the same time this create a collision, and may let us leak the victims token information instead of just the hackers

**2 - Probe for clues** 

need to benchmark how the endpoint behaves under normal conditions. Group all of you requests in repeater and use the `send group in sequence (separate connections)`, next send the same group of requests at once using the single packet attack, or last byte sync attack if HTTP/2 isn't supported. In repeater do this by selecting `Send gorup in parallel`, or use Turbo intruder

Look for any deviation from what you observed during benchmarking, this includes a change in one or more responses, or also second-order effects like different email contents or a visible change in the applications behavior afterward

**3 - prove the concept**

Try to understand what's happening, remove superfluous requests, and make sure you can still replicate the effects.

Advanced race conditions can cause unusual and unique primitives, so the path to maximum impact isn't always immediately obvious. It may help to think of each race condition as a structural weakness rather than an isolated vulnerability. 

### Multi-endpoint race conditions

Perhaps the most intuitive form of these race conditions are those that involve sending requests to multiple endpoints at the same time.

Think about the classic logic flaw in online stores where you add an item to your basket or cart, pay for it, then add more items to the cart before force-browsing to the order confirmation page. 

A variation of this vulnerability can occur when payment validation and order confirmation are performed during the processing of a single request.

In this case, you can potentially add more items to your basket during the race window between when the payment is validated and when the order is finally confirmed. 

### Aligning multi-endpoint race windows

When testing for multi-endpoint race conditions, you may encounter issues trying to line up the race windows for each request, even if you send them all at exactly the same time using the single-packet technique.

**Connection warming**

 Back-end connection delays don't usually interfere with race condition attacks because they typically delay parallel requests equally, so the requests stay in sync.

It's essential to be able to distinguish these delays from those caused by endpoint-specific factors. One way to do this is by "warming" the connection with one or more inconsequential requests to see if this smoothes out the remaining processing times. In Burp Repeater, you can try adding a GET request for the homepage to the start of your tab group, then using the `Send group in sequence (single connection)` 

**Abusing rate or resource limits**

If connection warming doesn't make any difference, there are various solutions to this problem

Using Turbo Intruder, you can introduce a short client-side delay. However, as this involves splitting your actual attack requests across multiple TCP packets, you won't be able to use the single-packet attack technique. As a result, on high-jitter targets, the attack is unlikely to work reliably regardless of what delay you set. 

Web servers often delay the processing of requests if too many are sent too quickly. By sending a large number of dummy requests to intentionally trigger the rate or resource limit, you may be able to cause a suitable server-side delay. This makes the single-packet attack viable even when delayed execution is required.

### Single-endpoint race conditions

Sending parallel requests with different values to a single endpoint can sometimes trigger powerful race conditions.

Consider a password reset mechanism that stores the user ID and reset token in the user's session.

In this scenario, sending two parallel password reset requests from the same session, but with two different usernames, could potentially cause a collision

 Note the final state when all operations are complete:

    session['reset-user'] = victim
    session['reset-token'] = 1234

The session now contains the victim's user ID, but the valid reset token is sent to the attacker. 

### Session-based locking mechanisms

Some frameworks attempt to prevent accidental data corruption by using some form of request locking. For example, PHP's native session handler module only processes one request per session at a time.

It's extremely important to spot this kind of behavior as it can otherwise mask trivially exploitable vulnerabilities. If you notice that all of your requests are being processed sequentially, try sending each of them using a different session token. 

### Partial construction race conditions

Many applications create objects in multiple steps, which may introduce a temporary middle state in which the object is exploitable.

This kind of behavior paves the way for exploits whereby you inject an input value that returns something matching the uninitialized database value, such as an empty string, or null in JSON, and this is compared as part of a security control. 

Frameworks often let you pass in arrays and other non-string data structures using non-standard syntax. For example, in PHP:

    param[]=foo is equivalent to param = ['foo']
    param[]=foo&param[]=bar is equivalent to param = ['foo', 'bar']
    param[] is equivalent to param = []

Ruby on Rails lets you do something similar by providing a query or POST parameter with a key but no value. In other words param[key] results in the following server-side object:

```
params = {"param"=>{"key"=>nil}}
```

In the example above, this means that during the race window, you could potentially make authenticated API requests as follows: 

```
GET /api/user/info?user=victim&api-key[]= HTTP/2
Host: vulnerable-website.com
```

### Time-sensitive attacks

One such example is when high-resolution timestamps are used instead of cryptographically secure random strings to generate security tokens.

Consider a password reset token that is only randomized using a timestamp. In this case, it might be possible to trigger two password resets for two different users, which both use the same token. All you need to do is time the requests so that they generate the same timestamp. 

## Labs Walkthrough

### Limit overrun race conditions

Background:

```
This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a Lightweight L33t Leather Jacket. 
```

**Predict a potential collision**
- log in and buy the cheapest item possible, makig sure to use the provided discount code so that you can study the purchasing flow
- consider that the shopping cart mechanism and in particular the restrictions that determine what you are allowed to order, are worth trying to bypass
- in bup history identify all endpoints that enable you to interact with the cart. for example a `POST /cart` request adds items to the cart and a `POST /cart/coupon` request applies the discount code
- try to identify any restrictions that are in place on these endpoints, for example observe that if you try applying the discount code more than once you receive a `Coupon already applied`
- make sure you have an item to your cart then send the `GET /cart` request to repeater
- in repeater try sending the `GET /cart` request both with and without your session cookie, confirm that without the session cookie you can only access an empty cart, from this you can infer:
  - the state of the cart is stored server-side in your session
  - any operations onthe cart are keyed on your session ID or the associated user ID
- consider that there may be a race window between when you first apply a discount code, and when the database is updated to reflect that you've done this already

**Benchmark the behavior**
- make sure there is no discount code currently applied to your cart
- send the request for applying the discount code to repeater `POST /cart/coupon`
- in repeater, add the new tab to a group
- right click the grouped tab, then select `Duplicate tab` and do this 19 times
- send the group of requests in sequence using separate connections to reduce the chance of interference
- observe that the first response confirms that the discount was successfully applied, but the rest of the responses consistently reject the code with the same `Coupon already applied`

**Probe for clues**
- remove the discount code from your cart
- in repeater send the group of requests again, but this time in parallel
- study the response and observe that multiple requests received a response indicating that the code was successfully applied, if not remove the code from your cart and repeat the attack
- in the browser, refresh your cart and confirm that the 20% reduction has been applied more than once

**Prove the concept
**- remove the applied codes and the arbitrary item from your cart and add the leather jacket to your cart instead
- resend the group of `POST /cart/coupon` requests in parallel
- refresh the cart and check the order total:
  - if the order total is still higher than your remaining store credit, remove the discount codes and repeat the attack
  - if the order total is less than your remaining store credit, purchas the jacket to finish
 
### Bypassing rate limits via race conditions

Background:

```
This lab's login mechanism uses rate limiting to defend against brute-force attacks. However, this can be bypassed due to a race condition.

To solve the lab:

- Work out how to exploit the race condition to bypass the rate limit.
- Successfully brute-force the password for the user carlos.
- Log in and access the admin panel.
- Delete the user carlos.

There is a list of passwords provided on the lab page
```

**Predict a potential collision
**- experiment with the login function by intentionally submitting incorrect passwords for your own account
- observe that if you enter the incorrect password more than three times, you're temporarily blocked from making any more login attempts for the same account
- try logging in using arbitrary username and observet hat you see the normal `Invalid username or password` message, this indicates that the rate limit is enforced per-username rather than per-session
- deduce that the number of failed attempts per username must be stored server-side
- consider that there may be a race window between:
  - when you submit the login attempt
  - when the website increments the counter for the number of failed login attempts associated with a username

**Benchmark the behavior**
- from burp history find a `POST /login` request containing an unsuccessful login attempt for your own account, send this to repeater
- in repeater add the new tab to a group, irght click the grouped tab then select `duplicate tab` and create 19 additional tabs
- send the group of requests in sequence, using separate connections to reduce the chance of interference
- observe that after two more failed login attempts, you're temporarily locked out as expected

Probe for clues
- send the requests but in parallel
- study the responses, and notice that although you have triggered the account lockout, more than three requests received the normal `Invalid username and password` response
- infer that if you're quick enough you're able to submit more than three login attempts before the account lock is triggered

Prove the concept
- still in repeater highlight the value of the `password` parameter in the `POST /login` request
- right click and select `Extensions > Turbo Intruder > Send to turbo intruder`
- in turbo intruder, in the request editor notice that the value of the password param is automatically marked as a payload position with a `%s` placeholder
- change the `username` param to carlos
- from the drop-down menu, select `examples/race-single-packet-attack.py` template
- inthe python editor, edit the template so that your attack queues the request once using each of the candidate passwords:

```
def queueRequests(target, wordlists):

    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # assign the list of candidate passwords from your clipboard
    passwords = wordlists.clipboard
    
    # queue a login request using each password from the wordlist
    # the 'gate' argument withholds the final part of each request until engine.openGate() is invoked
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    # once every request has been queued
    # invoke engine.openGate() to send all requests in the given gate simultaneously
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)

```

- note that we're assigning the password list from the clipboard, make sure to copy the list of passwords so they are in your clipboard
- launch the attack
- study the responses
  - if you have no successful logins, wait for the attack lock to reset and then repeat the attack
  - if you get a 302 response, notice that this login appears to be successful, make a note of the corresponding password from the `Payload` column
- wait for the account lock to reset then log in as carlos using the identifie password, access the admin panel delete the user carlos to complete

### Multi-endpoint race conditions

Background:

```
This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a Lightweight L33t Leather Jacket. 
```

Predict a potential collision
- log in and purhcase a gift card so you can study the purchasing flow
- consider that the shopping cart mechanism and in particular the restrictions that determine what you are allowed to order, are worth trying to bypass
- in burp history identify all of the requests for interacting with the cart, example: `POST /cart` to add items, `POST /cart/checkout` to submit the order
- add another gift card to your cart, then send the `GET /cart` request to repeater
- in repeater try sending `GET /cart` request both with and without your session cookie, confirm that without your session cookie you can only access an empty cart. infer this:
  - the state of the cart is stored server-side in your session
  - any operations on the cart are keyed on your session ID or the associated use ID
- notice that submitting and receiving confirmation of a successful order takes place over a single request
- consider that there may be a race window between when your oder is validated and when it is confirmed, this could enable you to add more items to the order after the server checks whether you have enough credit

Benchmark the behavior
- send both the `POST /cart` and `POST /cart/checkout` request to repeater
- add the two tabs into a new group in repeater
- send the two requests in sequence over a single connection a few times, notice from the response times that the first request consistently takes significantly longer than the second one
- add a `GET` request for the homepage to the start of your tab group
- send all three requests in sequence over a single connection, observe that the first request still takes longer, but by warming the connection this way the second and third requests are now completed within a much smaller window
- deduce that this delay is caused by the back end network architecture rather than the respective processing time of each endpoint, therefore it is not likely to interfere with your attack
- remove the `GET` request for the homepage from your tab group
- make sure you have a single gift card in your cart
- in repeater modify the `POST /cart` request in your tab group so that the `productId` parameter is set to `1`
- send the requests in sequence again
- observe that the order is rejected due to insufficient funds as you would expect

Prove the concept
- remove the jacket from your cart and add another gift card
- in repeater try sending the requests again, but this time in parallel
- look at the response to the `POST /cart/checkout`
  - if you received the same `insufficient funds` response, remove the jacket from your cart and repeat the attack, this may take several attempts
  - if you received a 200 response, check whether you successfully purchased the leather jacket
 
### Single-endpoint race conditions

Background:

```
This lab's email change feature contains a race condition that enables you to associate an arbitrary email address with your account.

Someone with the address carlos@ginandjuice.shop has a pending invite to be an administrator for the site, but they have not yet created an account. Therefore, any user who successfully claims this address will automatically inherit admin privileges.

To solve the lab:

    Identify a race condition that lets you claim an arbitrary email address.
    Change your email address to carlos@ginandjuice.shop.
    Access the admin panel.
    Delete the user carlos

You can log in to your own account with the following credentials: wiener:peter.

You also have access to an email client, where you can view all emails sent to @exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net addresses. 
```

Predict a potential collision
- log in and attempt to change your email to `anything@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net` observe that a confirmation email is sent to your intended new address, and you're prompted to click a link containing a unique token to confirm the change
- complete the process and confirm that your email address has been updated on your account page
- try submitting two different `@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net` email addresses in succession, then go to the email client
- notice that if you try to use the first confirmation link you received this is no longer valid, from this you can infer that the website only stores one pending email address at a time. as submitting a new email addresss edits this entry in the database rather than appending to it, there is potential for a collision

Benchmark the behavior
- send the `POST /my-account/change-email` request to repeater
- add the new tab to a group
- in repeater add the new tab to a group, irght click the grouped tab then select `duplicate tab` and create 19 additional tabs
- in each tab modify the first part of the email address so that it is unique to each request like test1@email, test2@email, etc
- send the requests in sequence over separate connections
- go back to the email client and observe that you have received a single confirmation email for each of the email change requests

Probe for clues
- in repeater, send the group of requests again, but this time in parallel
- go to the email client and study the new set of confirmation emails you've received. notice that this time, the recipient address doesn't always match the pending new email address
- consider that there may be a race window between when the website:
  - kicks off a task that eventually sends and email the provided address
  - retrieves data from the database and uses this to render the email template
- dude that when a parallel request changes the pending email addresss stored in the database during this window, this results in confirmation emails being sent to the wrong address

Prove the concept
- in repeater, create a new group containing two copies of the `POST /my-account/change-email` request
- change the `email` parameter of one request to `anything@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net`
- change the `email` param of the other request to `carlos@ginandjuice.shop`
- send the requests in parallel
- check your inbox
  - if you received a confirmation email in which the address in the body matches your own address, resend the requests in parallel and check again
  - if you received a confirmation email in which the address in the body is `carlos@ginandjuice.shop` click the confirmation link to update your address accordingly
  - go to your account page and notice that you now see a link for accessing the admin panel
  - visit the admin panel and dleete the user `carlos`
 
### Exploiting time-sensitive vulnerabilities

Background:

```
This lab contains a password reset mechanism. Although it doesn't contain a race condition, you can exploit the mechanism's broken cryptography by sending carefully timed requests.

To solve the lab:

    Identify the vulnerability in the way the website generates password reset tokens.
    Obtain a valid password reset token for the user carlos.
    Log in as carlos.
    Access the admin panel and delete the user carlos.

You can log into your account with the following credentials: wiener:peter. 
```

Study the behavior
- study the password reset process by submitting a password reset for your own account and observe that you're sent an email containing a reset link. the query string of this link includes your username and a token
- send the `POST /forgot-password` request to repeater
- in repeater, send the request a few times then check your inbox again
- observe that every reset request results in a link with a different token
- consider the following:
  - the token is of a consistent length, this suggests that it's either a randomly generated string with a fixed number of characters, or could be a hash of some unknown data, which may be predictable
  - the fact that the token is different each time indicates that, if it is in fact a hash digest, it must contain some kind of internal state, such as an RNG, a counter, or a timestamp
- duplicate the repeater tab and add both tabs to a new group
- send the pair of reset requests in parallel a few times
- oberve that there is still a significant delay between each response and that you still get a different otken in each confirmation email. infer that your requests are still being processed in sequence rather than concurrently

Bypass the per-session locking restriction
- notice that your session cookie suggests that the website uses a PHP back-end. this could mean that the server only processes one request at a time per session
- send the `GET /forgot-password` request to burp repeater, remove the session cookie from the request then send it
- from the response copy the newly issued session cookie and CSRF token and use them to replace the respective values in one of the two `POST /forgot-password` requests, you now have a pair of password reset requests from two different sessions
- send the two `POST` requests in parallel a few times and observe that the processing times are now much more closely aligned and sometimes identical

Confirm the vulnerability
- go back to to your inbox and notice that when the response times match for the pair of reset requests, this results in two confirmation emails that use an identical token. this confirm that a timestamp must be one of the inputs for the hash
- consider that this also means the token would be predictable if you knew the other inputs for the hash function
- notice the separate `username` param, this suggests that the username might not be included in the hash, which means that two different usernames could theoretically have the same token
- in repeater, go to the pair of `POST /forgot-password` request and change the username param of one to carlos
- resend the requests in parallel again, if the attack worked both users should be assigned the same reset token, although you won't be able to see this
- check your inbox again, and observe that this time, you've only received one new confirmation email, infer that the other email hopefully contianing the same token has been sent to carlos
- copy the link from the email and change the username to carlos and load int he browser
- set the new password for the carlos account and try logging in
  - if you can't log in, resend the pair of password resets emails and repeat the process
  - if you successfully log in visit the admin panel and delete the user carlos to solve the lab
 
