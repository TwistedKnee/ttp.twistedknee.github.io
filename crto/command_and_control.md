# Command and Control Notes

CRTO focuses on cobalt strike as the C2 for the course. 

## Starting the Team Server
```
sudo ./teamserver <IP> <password> <webbug.profile>
```
IP is the IP address of the Attacker, password is the shared password to connect from cobalt strike, webbug.profile is malleable C2.

## Listener Management
Can make a HTTP listener and give it a name, also an SMB, TCP and TCP local listener. DNS is also an option.

**Generating Payloads**
You can create multiple different type of payloads, explore what might be a good fit here.

## Interacting with beacon
Commands of interest:
```
help
pwd
sleep 5
```

## Pivot Listeners
Tells the beacon what port to bind and listen on. Right click a beacon and click Pivoting>Listener.

## Running as a Service
Allows teamserver to run as service automatically.

Create new file:
```
sudo vim /etc/systemd/system/teamserver.service
```
Paste, make sure to change webbug.profile path, IP and password:
```
[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver <IP> <password> path/to/webbug.profile

[Install]
WantedBy=multi-user.target
```
Next just reload the systemd manager a check status, it will be inactive/dead
```
sudo systemctl daemon-reload
sudo systemctl status teamserver.service
```
Then restart the service and check it status to ensure it ran correctly. Last command starts it on reboot
```
sudo systemctl start teamserver.service
sudo systemctl status teamserver.service
sudo systemctl enable teamserver.service
```
