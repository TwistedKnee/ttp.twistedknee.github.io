## MessageBox in C++

Open Visual Studio, create a new C++ Console App and delete the template code.  Then, add `#include <Windows.h>` at the top.  This header file contains the declarations for the main Windows API, macros, and data types.

The "A" functions use ANSI strings and "W" functions use Unicode.  Unicode is the preferred character encoding on Windows, which is why the MessageBox macro points to MessageBoxW by default.  If you look at the function definitions for MessageBoxA and MessageBoxW, you'll see that MessageBoxA takes in LPCSTR and MessageBoxW takes LPCWSTR.  If the API also returns a string (MessageBox returns an int), then the return type would also be ANSI or Unicode depending on which version of the API is called.

official Microsoft documentation on [learn.microsoft.com](https://learn.microsoft.com/).

The 'L' character denotes a `wchar_t` literal, which is a wide character type.

Complete code:

```
#include <Windows.h>

int main()
{
    MessageBox(NULL, L"Hello World!", L"Alert", 0);
    return 0;
}
```


## CreateProcess in C++

The [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) API requires us to utilise some additional data structures, namely `STARTUPINFOW` and `PROCESS_INFORMATION`.  The STARTUPINFOW struct can provide some parameters for how the process should start, and PROCESS_INFORMATION returns information about the new process (such as it's PID).  Most arguments can be NULL with the exception of the process command line arguments, a pointer to the STARTUPINFO and a pointer to the PROCESS_INFORMATION.

```
#include <windows.h>
#include <stdio.h>

int main()
{
    LPSTARTUPINFOW       si;
    PPROCESS_INFORMATION pi;
    BOOL                 success;
    
    si = new STARTUPINFOW();
    si->cb = sizeof(LPSTARTUPINFOW);

    pi = new PROCESS_INFORMATION();

    wchar_t cmd[] = L"notepad.exe\0";

    success = CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        si,
        pi);

    if (!success) {
        printf("[x] CreateProcess failed.");
        return 1;
    }

    printf("dwProcessId : %d\n", pi->dwProcessId);
    printf("dwThreadId  : %d\n", pi->dwThreadId);
    printf("hProcess    : %p\n", pi->hProcess);
    printf("hThread     : %p\n", pi->hThread);

    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
}
```

Note that `CreateProcess` is a macro for `CreateProcessW`

## P/Invoke

Allows us to access structs and functions present in unmanaged libraries from our managed code. Applications and libraries written in C/C++ compile to machine code and are examples of unmanaged code. Meaning programmers manage the memory allocation themselves. Managed code on the other hand runs on a CLR, Common Language Runtime. C# is an example that compiles to an Intermediate Language first which the CLR later converts to machine code during runtime. The CLR handles aspects like garbage collection and various runtime checking, why it's called managed code.

P/Invoke is used in abstractions to allow code written in a language, like .NET, to access WinApis like CreateProcess API. Though we can't access all WinApis with .NET, we can write manual P/Invoke calls to call them, for things like VirtalAllocEx, WriteProcessMemory, CreateRemoteThread, etc. 

Keep an eye out for languages that support P/Invoke, like VBA.

## MessageBox in CSharp

Now let's create a new C# Console App (.NET Framework).  Make sure this is for .NET Framework and not .NET (Core).  By default, .NET Framework projects have a preference for running as 32-bit, which, I suspect is a legacy preference since 64-bit CPUs were not that common in the early days of .NET.

To change this, go to _Project > Properties > Build_ and untick the _Prefer 32-bit_ box.

C# does not have a Windows header file like C++ does, so we have to declare all the Windows APIs and structures manually.  The MessageBoxW API is first declared using this `DllImport` attribute.  This tells the CLR that a function called MessageBoxW is exported from the user32.dll.  It returns an int and expects an IntPtr and three string arguments.  You may notice that the C++ definition declares the hWnd parameter as a HWND, rather than IntPtr.  Not all languages share the same data types and they often need to be changed or "marshalled" when moving between managed and unmanged languages.

```
using System;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    internal class Program
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        static void Main(string[] args)
        {
            MessageBoxW(IntPtr.Zero, "Hello World!", "P/Invoke", 0);
        }
    }
}
```

## Type Marshalling

"Marshalling" is the process of transforming a data type when it needs to cross between managed and unmanaged code.  Unless specified otherwise, the P/Invoke subsystem tries to automatically marshal data for you.  In the previous lesson, we called MessageBoxW which took two `string` parameters, and we know these needed to be Unicode (LPCWSTR).  We didn't have to do anything magical, because P/Invoke did it for us.

However, there may be situations where you need to be more explicit, for which there are two methods.  The first is by using the `CharSet` field of the `DllImport` attribute, which is a quick and easy way to define how all string parameters should be marshalled.

```
[DLLImport]("user32.dll", CharSet = CharSet.Unicode)
private static extern int MessageBoxW(IntPtr hWnd, string lpTest, string lpCaption, uint uType);
```

The second is using the MarshAs attribute on each parameter. This is more flexible because it is not limited to strings. Example, can force the uint parameter to be marshalled as either a 1,2,4, or 8-byte integer if needed:

```
[DLLImport("user43.dll")]
private static extern int MessageBoxW(
IntPtr hWnd,
[MarshalAs(UnmanagedType.LPWStr)] string lpTest,
[MarshalAs(UnmanagedType.LPWStr)] string lpCaption,
[MarshalAs(UnmanagedType.U4)] uint uType
);
```

We can also marshal any data returned by a P/Invoke method using the `return` keyword, followed by a `MarshalAs` attribute.

```
[DLLImport(user32.dll")]
[return: MarshalAs(UnmanagedType.I4)]
private static extern int MessageBoxW(IntPtr hWnd, string lpTest, string lpCaption, uint uType);
```

In this case, it would force the data to be marshalled as a 4-byte signed integer.

More information about managed and unmanaged data type mappings: [here](https://learn.microsoft.com/en-us/dotnet/framework/interop/marshalling-data-with-platform-invoke)

## CreateProcess in CSharp

Moving the P/Invoke signatutes, structs and enums to their own class keeps the code cleaner:

```
internal static class Win32
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessW(
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

Then you can call these structures with Win32.xxx

```
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
            var success = Win32.CreateProcessW(
                null,
                "notepad.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                null,
                ref startupInfo,
                out var processInfo);

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

## Error Handling

Learning how to handles errors when the API fails, example code with a failing CreateProcessW:

```
#include <windows.h>
#include <stdio.h>

int main()
{
    LPSTARTUPINFOW      si;
    PROCESS_INFORMATION pi;
    BOOL                success;
    
    si = new STARTUPINFOW();
    si->cb = sizeof(LPSTARTUPINFOW);

    wchar_t cmd[] = L"this is a mistake.exe\0";

    success = CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        si,
        &pi);

    if (!success) {
        printf("[x] CreateProcess failed with error code: %d\n", GetLastError());
        return 1;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
```

After checking the boolean return value, we can get the error code by calling `GetLastError()`, produces this: `[x] CreateProcess failed with error code: 2`

The net utility can be used to translate the code: `net helpmsg 2`, or visiting https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes

*NOTE* in C# P/Invoke ensure to use the SetLastError to true in the DLLImport: `[DLLImport("kernel32.dll", CharSet= CharSet.Unicode, SetLastError=true)]`

The error code can then be retrieved using `Marshal.GetLastWin32Error()`.

```
static void Main(string[] args)
{
    var si = new Win32.STARTUPINFO();
    si.cb = Marshal.SizeOf(si);

    var success = Win32.CreateProcessW(
        null,
        "this is a mistake.exe\0",
        IntPtr.Zero,
        IntPtr.Zero,
        false,
        0,
        IntPtr.Zero,
        null,
        ref si,
        out var pi);

    if (!success)
    {
        Console.WriteLine("[x] CreateProcess failed with error code: {0}", Marshal.GetLastWin32Error());
        return;
    }

    // close handles
    Win32.CloseHandle(pi.hThread);
    Win32.CloseHandle(pi.hProcess);
}
```

It's actually quite easy to get the failure message as a string in C# by instantiating a new `Win32Exception` and passing the error code in on the constructor.  The `Message` property of the exception will then have the full friendly message:

```
if (!success)
{
    var exception = new Win32Exception(Marshal.GetLastWin32Error());
    Console.WriteLine("[x] CreateProcess failed with error: {0}.", exception.Message);
    return;
}
```

## NT APIs

NtQueryInformationProcess example to query the current process:
```
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

int main()
{
    NTSTATUS                    status;
    PPROCESS_BASIC_INFORMATION  pbi;
    DWORD                       dwSize;

    // call once to get the size
    NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        NULL,
        0,
        &dwSize);

    // allocate memory
    pbi = (PPROCESS_BASIC_INFORMATION)malloc(dwSize);
    RtlZeroMemory(pbi, dwSize);

    // call again
    status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &dwSize);

    if (!NT_SUCCESS(status)) {
        printf("[x] NtQueryInformationProcess failed: %ld.\n", status);
        return 1;
    }

    printf("[+] PEB base address: 0x%p\n", pbi->PebBaseAddress);
}
```

THIS WILL FAIL, to have it not fail you have to use LoadLibrary and GetProcAddress to dynamically resolve the function at runtime, for that we must copy the function definition for the NTQueryInformaitonProcess as a typedef:

```
typedef NTSTATUS(NTAPI * NT_QUERY_INFORMATION_PROCESS)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);
```

When calling GetProcAddress we cast the function point to our type:

```
HMODULE hNtdll;
NT_QUERY_INFORMATION_PROCESS hNtQueryInformationProcess;

hNtdll = LoadLibrary(L"ntdll.dll\0");
hNtQueryInformationProcess = (NT_QUERY_INFORMATION_PROCESS) GetProcAddress(hNtdll, "NtQueryInformationProcess");
```

Then we use the function point `hNtQueryInformationProcess` to call the API:
```
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI * NT_QUERY_INFORMATION_PROCESS)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

int main()
{
    NTSTATUS                    status;
    PPROCESS_BASIC_INFORMATION  pbi;
    DWORD                       dwSize;

    HMODULE hNtdll;
    NT_QUERY_INFORMATION_PROCESS hNtQueryInformationProcess;

    hNtdll = LoadLibrary(L"ntdll.dll\0");
    hNtQueryInformationProcess = (NT_QUERY_INFORMATION_PROCESS) GetProcAddress(hNtdll, "NtQueryInformationProcess");

    // call once to get the size
    hNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        NULL,
        0,
        &dwSize);

    // allocate memory
    pbi = (PPROCESS_BASIC_INFORMATION)malloc(dwSize);
    RtlZeroMemory(pbi, dwSize);

    // call again
    status = hNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &dwSize);

    if (!NT_SUCCESS(status)) {
        printf("[x] NtQueryInformationProcess failed: %ld.\n", status);
        return 1;
    }

    printf("[+] PEB base address: 0x%p\n", pbi->PebBaseAddress);
}
```

*NOTE* if you have the Windows Driver Kit installed you can use the ntdll import library, simply add the `#pragma comment(lib, "ntdll")`

## Ordinals

Referencing an exported function via ordinals can bypass some tools to make the binary appear less malicious. To find the correct number for an API like CreateProcessW, load `C:\Windows\System32\kernel32.dll` into PE-bear, go to the exports tab and search for the exported function.

Go to the Ordinal column, we see the value E9. To get it's decimal value use the programmer mode on a calculator to quickly convert between the two:

![[Pasted image 20250322084753.png]]

Now intead of using CreateProcessW directly in the DLLImport attribute, we can use the ordinal number with the EntryPoint field and give the function a more benign name:
```
[DLLImport("kernel32.dll", EntryPoint = "#233", CharSet = CharSet.Unicode, SetLastError = true)  ]
public static extern bool TotallyLegitApi(etc..)
```

Any analyst familiar with the Windows APIs would know that this is not legitimate.  So for extra sneakiness, use an API that is actually exported from kernel32.dll.  This will still work because the EntryPoint field takes priority over the function name.

## MessageBox in VBA

To call P/Invoke in VBA you use a `Declare` directive. The rest is similar, in that we declare the parameters along with their VBA data types and the return type comes at the end:


```
Declare PtrSafe Function MessageBoxW Lib "user32.dll" (ByVal hWnd As LongPtr, ByVal lpText As String, ByVal lpCaption As String, ByVal uType As Integer) As Integer
```

Calling this function can be done in a VBA method.  Because we're calling the unicode version, we need `StrConv` to convert the strings to the appropriate format.

```
Sub Demo()
    Dim result As Integer
    result = MessageBoxW(0, StrConv("Hello World", vbUnicode), StrConv("MS Word", vbUnicode), 0)
End Sub
```

## CreateProcess in VBA

As with C#, we must first declare the WinAPI functions and structures.  A struct can be defined with the `Type` keyword.

```
Declare PtrSafe Function CreateProcessW Lib "kernel32.dll" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As LongPtr, ByVal lpThreadAttributes As LongPtr, ByVal bInheritHandles As Boolean, ByVal dwCreationFlags As Long, ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Boolean

Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As LongPtr
    hStdInput As LongPtr
    hStdOutput As LongPtr
    hStdError As LongPtr
End Type

Type PROCESS_INFORMATION
    hProcess As LongPtr
    hThread As LongPtr
    dwProcessId As Long
    dwThreadId As Long
End Type
```

Then call the API:

```
Sub Demo()
    Dim startup_info As STARTUPINFO
    Dim process_info As PROCESS_INFORMATION
    
    Dim nullStr As String
    
    Dim success As Boolean
    success = CreateProcessW(nullStr, StrConv("notepad.exe", vbUnicode), 0&, 0&, False, 0, 0&, nullStr, startup_info, process_info)
End Sub
```

## D/Invoke

[tool](https://github.com/TheWover/DInvoke) D/Invoke is a C# project intended as a direct replacement for P/Invoke, it can do things like:

- Invoke unmanaged code without P/Invoke
- Manually map unmanaged PE's into memory and call their associated entry point or an exported function
- Generate syscall wrappers for native APIs

Let's swap out the P/Invoke for D/Invoke

Go to *Project > Add Reference > Browse* and add a reference to DInvoke.data.dll and DInvoke.DynamicInvoke.dll in C:\Tools\DInvoke\DInvoke.DynamicInvoke\bin\Release\netstandard2.0

Change the DllImport attribute to `UnmanagedFunctionPointer` and the extern keyword to `delegate`:

```
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
    out PROCESS_INFORMATION processInfo);
```

The arguments for the API call are placed in an object array and everything is then passed to the `DynamicApiInvoke` method

```
object[] parameters =
{
    null, "notepad.exe", IntPtr.Zero, IntPtr.Zero, false, (uint)0,
    IntPtr.Zero, null, startupInfo, new Win32.PROCESS_INFORMATION()
};

var success = (bool)Generic.DynamicApiInvoke(
    "kernel32.dll",
    "CreateProcessW",
    typeof(Win32.CreateProcessWDelegate),
    ref parameters);
```

One aspect to watch out for are default datatypes.  The dwCreationFlags parameter is a DWORD, or uint in C#.  However, if you just type 0 then the compiler assumes an int which will cause a runtime exception when trying to call the API.  This is why it must be explicitly cast to a uint.

If the call succeeds, the PROCESS_INFORMATION will be sitting in index 9 of the parameters array
```
var processInfo = (Win32.PROCESS_INFORMATION)parameters[9];
```

## D/Invoke & Ordinals

D/Invoke is also compatible with ordinals, which is useful for hiding easily detectable strings like "CreateProcessW".  To find the given ordinal for an API, we need to open the DLL in a tool such as PE-bear.  Simply go to the _Exports_ tab and scroll until you find the API

Here, we can see the ordinal for CreateProcessW is E9 hex, or 233 in decimal.  We then use that with `GetLibraryAddress` to get a pointer to the API and then make the API call with `DynamicFunctionInvoke`

```
var hLibrary = Generic.GetLibraryAddress("kernel32.dll", 233);

var success = (bool)Generic.DynamicFunctionInvoke(
    hLibrary,
    typeof(Win32.CreateProcessWDelegate),
    ref parameters);
```

## D/Invoke API Hashing

Another way to avoid the use of strings in D/Invoke is to use hashing.  This is a technique whereby we take a string and run it through a hash function with a pre-determined key.  That hash is then used in our code instead of a literal DLL name or API name.

The easiest way to generate these hashes is by using D/Invoke inside CSharpREPL.  Simply import `DynamicInvoke.dll` and call `GetApiHash`

```
Run CSharpREPL:
#r "C:\Tools\DInvoke\DInvoke.DynamicInvoke\bin\Release\netstandard2.0\DInvoke.DynamicInvoke.dll"
DInvoke.DynamicInvoke.Utilities.GetApiHash("kernel32.dll", 0xdeadbeef)
DInvoke.DynamicInvoke.Utilities.GetApiHash("CreateProcessW", 0xdeadbeef)
```

When writing your code, `GetLoadedModuleAddress` and `GetExportAddress` both have overloads to accept a hashed string and the key used

```
//get kernel32
var hKernel = Generic.GetLoadedModuleAddress("<hash>", 0xdeadbeef);
//get createprocessw
var hCreateProcess = Generic.GetExportedAddress(hKernel, "<hash>", 0xdeadbeef);
```

The API can then be executed with DynamicFunctionInvoke