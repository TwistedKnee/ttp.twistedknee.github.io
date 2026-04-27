start session:

I saved inside the drozer's apk download github folder location a testmob virtualenv that has drozer downloaded in. 

I activate with just `./testmob/Scripts/activate`

in another powershell I setup forward after starting the drozer server apk: `adb forward tcp:31415 tcp:31415`

now connect with: `drozer console connect`

list all packages: 
`run app.package.list`

can search with -f: `run app.package.list -f vuln`

getting general info: `run app.package.info -a <com package name of apk>`

data directory is interesting here

getting attack surface: `run app.package.attacksurface <com package name of apk>`

getting activity info: `run app.activity.info -a <com package name of apk> `

starting activity: `run app.activity.start --component <com package name of apk> <com name of activity>`

content provider info: `run app.provider.info -a <com package name of apk>`

drozer provides a scanner module that brings together various ways to guess paths and divine a list of accessible content URIs: `dz> run scanner.provider.finduris -a <com package name of apk>
