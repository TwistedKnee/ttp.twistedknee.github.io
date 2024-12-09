# Business Logic Vulnerabilities

[Portswigger](https://portswigger.net/web-security/logic-flaws)

## Methodology

examples of logic flaws
- excessive trust in client side controls
- failing to handle unconventional input
- making flawed assumptions about user behavior
- domain specific flaws
- providing an encryption oracle
- email address parser discrepancies

try input in ranges that legitimate users are unlikely to ever enter. This includes exceptionally high or exceptionally low numeric inputs and abnormally long strings for text-based fields. You can even try unexpected data types. By observing the application's response, you should try and answer the following questions:

    Are there any limits that are imposed on the data?
    What happens when you reach those limits?
    Is any transformation or normalization being performed on your input?

When probing for logic flaws, you should try removing each parameter in turn and observing what effect this has on the response. You should make sure to:

    Only remove one parameter at a time to ensure all relevant code paths are reached.
    Try deleting the name of the parameter as well as the value. The server will typically handle both cases differently.
    Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow.

This applies to both URL and POST parameters, but don't forget to check the cookies too. This simple process can reveal some bizarre application behavior that may be exploitable. 

**encryption oracle**
Dangerous scenarios can occur when user-controllable input is encrypted and the resulting ciphertext is then made available to the user in some way. This kind of input is sometimes known as an "encryption oracle".

## Labs Walkthrough

### Excessive trust in client-side controls

Background: 

```
This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket". 
```

- log in and attempt to buy the leather jacket, the order is rejected without enough store credit
- go to burp and study the order process, notice that when you add an item to your cart the corresponding request contains a `price` parameter, send the `POST /cart` request to repeater
- change the price to an arbitrary integer and send the request, refresh the cart and confirm the price has changed based on your input
- repeat this process to set the price to any amount less than your available store credit and buy the jacket

### High-level logic vulnerability

Background: 

```
This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket". 
```

- log in and add a cheap item to your cart
- study this process in burp, and notice the quantity is determined by a parameter in the `POST /cart` request
- go to intercept and turn it on, add another item to you cart and got to the intercepted `POST /cart` request in burp
- change the quantity parameter to an arbitrary integer, then forward any remaining requests, observe the quantity in the cart was successfully updated based on your input
- repeat this process, but request a negative quantity this time, check that this is successfully deducted from the cart quantity
- request a suitable negative quantity to remove more untis from the cart than it currently contains
- add the leather jacket to your cart as normal, add a suitable negative quantity of another item to reduce the total price to less than your remaining store credit

### Inconsistent security controls

- open the lab, then go to `Target > site map` tab in burp, right click on the lab domain and select `Engagement tools > discover content` to open the discovery tool
- click `session is not running` to start the content discovery, wait for results and check the `site map` again and notice the `/admin` path
- try and browse to `/admin`, although you don't have access the error message indicates that `DontWannaCry` users do
- go to the account registration page, otice the message telling `DontWannaCry` employees to use their company email address, register with an arbitrary email address in the format: `anything@your-email-id.web-security-academy.net`, theirs an email client to pull your email domain
- go to the email client and click the link in the confirmation email to complete the registration
- log in using your new account and go to the `my account` page, notice that you have the option to change your email address, change this to an arbitrary `@dontwannacry.com` address
- now notice we have access to the admin panel to delete the carlos user now

### Flawed enforcement of business rules

Background: 

```
This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".
```

- log in and notice that there is a coupon code, `NEWCUST5`
- at the bottom of the page sign up to the newsletter, you receive another coupon code `SIGNUP30`
- add the leather jacket to your cart
- go to the checkout and apply both of the coupon codes
- try applying the codes more than once, notice that if you enter the same code twice in a row it is rejected because the coupon has already been applied, however if we alternate between the two codes you can bypass this control
- reuse the two codes enough times to reduce your order total to less than your remaining store credit, and complete the order

### Low-level logic flaw

Background:

```
This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket". 
```

- log in and attempt to buy the leather jacket, the order is rejected because you don't have enough store credit, send the `POST /cart` to repeater
- notice that you can only add a 2-digit quanitity with each request, send the request to intruder
- in intruder set the `quantity` param to 99
- in payloads side panel select the payload type `null payloads` under `payload configuration` select `Continue indefinitely`, start the attack
- while the attack is running, go to the cart and keep refreshing the page every so often and monitor if the price goes down
- clear your cart, in the next few steps we'll try to add enough units so that the price loops back around and settles between $0 and $100
- create the same intruder attack again, but this time under payload configuration choose to generate exactly `323` payloads
- click `resource pool` to add a resource pool with the `maximum concurrent requests` set to `1`, start the attack
- when intruder is done go to the `POST /cart` request in repeater and send a single request for `47` jackets, the totla price of the order should be `-$1221.96`
- use repeater to add a suitable quantity of another item to your cart so that the total falls between $0 and $100
- place the order

### Inconsistent handling of exceptional input

Background:

```
This lab doesn't adequately validate user input. You can exploit a logic flaw in its account registration process to gain access to administrative functionality. To solve the lab, access the admin panel and delete the user carlos.
Hint: You can use the link in the lab banner to access an email client connected to your own private mail server. The client will display all messages sent to @YOUR-EMAIL-ID.web-security-academy.net and any arbitrary subdomains. Your unique email ID is displayed in the email client. 
```

- open the lab then go to the `Target > site map` tab in burp, right click on the lab domain and select `engagement tools > discover content`
- click `session is not running` to start the discovery scan, wait a while to see the `/admin` in the `site map`
- try to browse to `/admin`, you are blocked but an error message shows that `DontWannaCry` users can
- go to the account registration page, and see a message telling `DontWannaCry` employees to use their company email address
- open the email client, make note of the unique ID in the domain name for your email server
- go back to the lab and register with an exceptionally long email address in the format: `very-long-string@YOUR-EMAIL-ID.web-security-academy.net`, make sure the `very-long-string` is at least 200 characters long
- go to the email client and notice that you have received a confirmation email, click the link to complete the registration process
- log in and go to the `my account` page and notice that your email address has been truncated to 255 characters
- log out and go back to registering an account, this time include dontwannacry.com as a subdomain in your email address as follows `very-long-string@dontwannacry.com.YOUR-EMAIL-ID.web-security-academy.net` Make sure that the very-long-string is the right number of characters so that the "m" at the end of @dontwannacry.com is character 255 exactly
- go to your email client and click the link in the confirmation email that you have received, log into your new account and notice that you now have access to the admin panel, go tot he admin panel and delete the carlos user

### Weak isolation on dual-use endpoint

Background: 

```
This lab makes a flawed assumption about the user's privilege level based on their input. As a result, you can exploit the logic of its account management features to gain access to arbitrary users' accounts. To solve the lab, access the administrator account and delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter 
```

- log in and access your account page
- change your password
- study the `POST /my-account/change-password` request in repeater
- notice that if you remove the `current-password` parameter entirely you are bale to successfully change your password without providing your current one
- observe that the user whose password is changed is determined by the `username` parameter, set the `username=administrator` and send the request again
- log out and notice that you can now successfully login as the administrator using the password you just set, go to the amdin panel and delete carlos

### Insufficient workflow validation

Background:

```
This lab makes flawed assumptions about the sequence of events in the purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket". 
```

- log into your account and attempt to buy any item you can afford
- study the proxy history, observer that when you place an order, the `POST /cart/checkout` request redirects you to an order confirmation page, send the `GET /cart/order-confirmation?order-confirmation=true` to repeater
- add the leather jacket to you basket
- in repeater resend the order confirmation request, observer that the order is completed without the cost being deducted from your store credit

### Authentication bypass via flawed state machine

Background:

```
This lab makes flawed assumptions about the sequence of events in the login process. To solve the lab, exploit this flaw to bypass the lab's authentication, access the admin interface, and delete the user carlos
```

- log into the applicaiton and notice that you need to select your role before you are taken to the home page
- use the content discovery tool to identify the `/admin` path
- try browsing to `/admin` directly from the role selection page and observe that this doesn't work
- log out and go back to the login page and with intercept turned on log in
- forward the `POST /login` request, the next request is `GET /role-seletor` drop this request and then browse to the lab's home page and see we have been defaulted to the `administrator` role and have access to the `/admin` panel to delete carlos


### Infinite money logic flaw

Background:

```
This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket". 
```

- log in and sign up for the newsletter to obtain a coupon code `SINGUP30`, notice that you can buy $10 gift cards and redeem them in the `my account` page
- add a gift card to your basket and proceed to checkout, apply the coupon code to get a %30 discount, complete the order and copy the gift card code to you clipboard
- go to you account page and redeem the gift card, giving us an additional $3 to our store credit
- study the proxy history and notice that you redeem your gift card by supplying the code in the `gift-card` parameter of the `POST /gift-card` request
- in burp click `Settings` and go to the `session handling rules` panel and click `add`
- go to the `scope` tab and under the `URL scope` select `include all URLs`
- go back to the `Details` tab, under `rule actions` click `add > run a macro` under select macro, click add again to open the `macro recorder`
- select the following sequence of requests, then click OK:

```
POST /cart
POST /cart/coupon
POST /cart/checkout
GET /cart/order-confirmation?order-confirmed=true
POST /gift-card
```

- in the list of requests select `GET /cart/order-confirmation?order-confirmed=true`, click `configure item` click `add` to create a custom parameter, name the parameter `gift-card` and highlight the gift card code at the bottom of the response. Click `OK` twice to go back tot he `macro editor`
- select the `POST /gift-card` request and click the `configure item` again, in the `parameter handling` section use the drop down to specify the `gift-card` parameter be derived from the prior response, click `OK`
-  in the `macro editor` click `test macro` look at the response to `GET /cart/order-confirmation?order-confirmation=true` and note the gift card code that was generated, look at the `POST /gift-card` request, make sure that the `gift-card` parmater matches and confirm that it received a `302` response, click OK until you get back to the main burp window
-  send the `GET /my-account` request to intruder, make sure that the `sniper attack` is selected
-  in the `payloads` side panel under `payload configuration` select the payload type `Null payloads` choose to generate `412` payloads
-  click on `resource pool` and add the attack to a resource pool with the `maximum concurrent requests` set to `1` and start the attack
-  when the attack finishes and you have enough store credit buy the jacket

###  Authentication bypass via encryption oracle

Background:

```
This lab contains a logic flaw that exposes an encryption oracle to users. To solve the lab, exploit this flaw to gain access to the admin panel and delete the user carlos. 
```

- log in with the `stay logged in` option enabled and post a comment, study the history in burp and notice the `stay-logged-in` cookie is encrypted
- notice that when you try and submit a comment using an invalid email addresss, the response sets an ecrypted `notification` cookie before redirecting you to the blog post
- notice that the error message reflects your input from the `email` parameter in cleartext, `Invalid email address: your-invalid-email`
- this must be decrypted from the `notification` cookie, send the `POST /post/comment` and the subsequent `GET /post?postId=x` request to repeater
- in repeater observe that you can use the `email` parameter of the POST request to encrypt arbitrary data and reflect the corresponding ciphertext in the `Set-Cookie` header, likewise you can use the `notification` cookie in the `GET` request to decrypt arbitrary ciphertext and reflect the output in the error message, for simplicity double click the tab for each request and rename the tabs `encrypt` and `decrypt` respectively
- in the decrypt request copy your `stay logged in` cookie value and paste it into the `notification` cookie, send the request, instead of the error message the response now contains the decrypted `stay logged in` cookie foir example: `wiener:1598530205184`, this shows the cookie is in this format: `username:timestamp`
- go to the encrypt request and change the email parameter to `administrator:your-timestamp` send the request and then copy the new `notification` cookie from the response
- decrypt the new cookie and observe that the 23-character Invalid email address: " prefix is automatically added to any value you pass in using the email parameter. Send the notification cookie to Burp Decoder
- In Decoder, URL-decode and Base64-decode the cookie
- in repeater, switch to the message editor's "Hex" tab. Select the first 23 bytes, then right-click and select "Delete selected bytes"
- Re-encode the data and copy the result into the notification cookie of the decrypt request. When you send the request, observe that an error message indicates that a block-based encryption algorithm is used and that the input length must be a multiple of 16. You need to pad the "Invalid email address: " prefix with enough bytes so that the number of bytes you will remove is a multiple of 16
- in repeater go back to the encrypt request and add 9 characters to the start of the intended cookie value: `xxxxxxxxxadministrator:your-timestamp` Encrypt this input and use the decrypt request to test that it can be successfully decrypted
- Send the new ciphertext to Decoder, then URL and Base64-decode it. This time, delete 32 bytes from the start of the data. Re-encode the data and paste it into the notification parameter in the decrypt request, check that the response to confirm that it no longer contains the "Invalid email address:" prefix, you should only see `administrator:your-timestamp`
- from the proxy history send the `GET /` request to repeater, delete the session cookie entirely and replace the `stay-logged-in` cookie with the ciphertext of your selfmade cookie
- go to `/admin` and use the panel to delete carlos
