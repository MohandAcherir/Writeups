# L3akCTF - Safe Gets
 
**Points:** 50 \
**Category:** Pwn

---

## TL;DR

[The challenge provides an implementation of a safe gets in python, but it's still vulnerable to encoding errors.]

---

## Provided files:
- **chall** : ELF binary that receives strings and reverses them (NO PIE, NO CANARY protections).
- **wrapper.py** : Python wrapper that calls `chall`
- **Dockerfile** : to set up the environment

## The Vulnerable Code

Let's examine the Python wrapper script that was supposed to protect a vulnerable binary:

```python
import subprocess
import sys

BINARY = "./chall"
MAX_LEN = 0xff  # 255 characters

# Get input from user
payload = input(f"Enter your input (max {MAX_LEN} bytes): ")
if len(payload) > MAX_LEN:  # Length check
    print("[-] Input too long!")
    sys.exit(1)

# Start the binary with pipes
proc = subprocess.Popen(
    [BINARY],
    stdin=subprocess.PIPE,
    stdout=sys.stdout,
    stderr=subprocess.PIPE
)

try:
    # Send initial payload
    proc.stdin.write(payload.encode() + b'\n') # RISKY
    proc.stdin.flush()
    
    # Interactive loop
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        if proc.poll() is not None:
            print("[+] Process has exited.")
            break
        proc.stdin.write(line.encode('latin1'))
        proc.stdin.flush()
        
except (KeyboardInterrupt, BrokenPipeError):
    print("[+] Exiting.")
finally:
    try:
        proc.terminate()
    except Exception:
        pass
```
## Vulnerable binary code:
Here's the raw decompiled binary functions:
```

undefined8 main(void)

{
  size_t sVar1;
  char local_118 [259];
  char local_15;
  int local_14;
  ulong local_10;
  
  FUN_004010a0(local_118);
  sVar1 = strlen(local_118);
  local_14 = (int)sVar1;
  for (local_10 = 0; local_10 < (ulong)(long)(local_14 / 2); local_10 = local_10 + 1) {
    local_15 = local_118[(long)(local_14 + -1) - local_10];
    local_118[(long)(local_14 + -1) - local_10] = local_118[local_10];
    local_118[local_10] = local_15;
  }
  puts("Reversed string:");
  puts(local_118);
  return 0;
}

void FUN_004010a0(char *param_1)

{
  gets(param_1);
  return;
}

void win(void)

{
  system("/bin/sh");
  return;
}

```

The target binary `./chall` contains a classic buffer overflow vulnerability:
- Uses `gets()` to read user input
- Has a fixed-size buffer that can be overflowed
- Performs string reversal before exiting

## Initial Analysis

At first glance, the Python wrapper appears to provide adequate protection:
- Limits input to 255 characters (`MAX_LEN = 0xff`)
- Validates length before sending to the binary
- Uses `len(payload)` to check the constraint

However, this protection has a critical flaw.

## The Vulnerability: Character vs. Byte Count Mismatch

The core issue lies in this line:
```python
if len(payload) > MAX_LEN:  # Checks CHARACTER count
    print("[-] Input too long!")
    sys.exit(1)

# Later...
proc.stdin.write(payload.encode() + b'\n')  # Sends BYTE count
```

### The Problem

**`len(payload)`** counts Unicode **characters** and **`payload.encode()`** produces **bytes**, so Multi-byte Unicode characters can bypass the length check.

**UTF-8 Encoding Examples**

| Character | Unicode | UTF-8 Bytes | Character Count | Byte Count |
|-----------|---------|-------------|-----------------|------------|
| `A` | U+0041 | `0x41` | 1 | 1 |
| `é` | U+00E9 | `0xC3 0xA9` | 1 | 2 |
| `€` | U+20AC | `0xE2 0x82 0xAC` | 1 | 3 |
| `𝔸` | U+1D538 | `0xF0 0x9D 0x94 0xB8` | 1 | 4 |


So, for example we have ```len("é") == 1``` and ```len("é".encode()) == 2```

## Exploitation

So, now we can bypass intial length check using the `é` character and fill the whole buffer, and then overwrite `rbp` and `rip` backups in order to redirect the flow to the `win()` function.  

**Note**: `win()` function's address is `0x00401262` (NO PIE Binary)
```  
        00401262 f3 0f 1e fa     ENDBR64
        00401266 55              PUSH       RBP
        00401267 48 89 e5        MOV        RBP,RSP
        0040126a 48 8d 05        LEA        RAX,[s_/bin/sh_00402015]                         = "/bin/sh"
                 a4 0d 00 00
        00401271 48 89 c7        MOV        RDI=>s_/bin/sh_00402015,RAX                      = "/bin/sh"
        00401274 e8 17 fe        CALL       <EXTERNAL>::system                               int system(char * __command)
                 ff ff
        00401279 90              NOP
        0040127a 5d              POP        RBP
        0040127b c3              RET
```
Due to stack aligment issues, i didn't jump to `0x00401262` but to `0x00401267` instead in order to avoid the `push rbp` instruction that misaligned somehow the stack.


### Proof of Concept

![PoC](./pics/Screenshot%20from%202025-07-12%2015-50-39.png)
