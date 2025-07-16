# SwampCTF - Rock-my-Password

**Points:** 150 \
**Category:** Crypto

---

## TL;DR

[This challenge uses multiple layers of hashing, but more hashing doesn't mean more security.]

---
![Res](./pics/Screenshot%202025-07-16%20222530.png)

## Analysis:
The challenge's description says it all: we need to use the famous `rockyou.txt` wordlist and apply for each candidate the hashing functions sequence:
- MD5 (100 times)
- SHA-256 (100 times)
- SHA-512 (100 times)
and compare each time with the given hash.

## Result:

![Res](./pics/Screenshot%202025-07-16%20221840.png)

### Proof of Concept

```
import hashlib

def hash_password(password):
    # Apply MD5 hashing 100 times
    for i in range(100):
        if i == 0:
            password = hashlib.md5(password.encode()).hexdigest()
            continue
        password = hashlib.md5(bytes.fromhex(password)).hexdigest()
    
    # Apply SHA-256 hashing 100 times
    for _ in range(100):
        password = hashlib.sha256(bytes.fromhex(password)).hexdigest()
    
    # Apply SHA-512 hashing 100 times
    for _ in range(100):
        password = hashlib.sha512(bytes.fromhex(password)).hexdigest()
    
    return password

# Given hashed flag
hashed_flag = "f600d59a5cdd245a45297079299f2fcd811a8c5461d979f09b73d21b11fbb4f899389e588745c6a9af13749eebbdc2e72336cc57ccf90953e6f9096996a58dcc"

int_flag = int(hashed_flag, 16)

# Path to RockYou wordlist (Update this to your actual file path)
rockyou_path = "../rockyou.txt"

try:
    with open(rockyou_path, "r", encoding="latin-1") as file:
        for line in file:
            RYpassword = line.strip()
            if len(RYpassword) == 10:  # Check for 10-character passwords only
                password = "swampCTF{" + RYpassword + "}"
                res = int(hash_password(password), 16)
                if res == int_flag:
                    print(f"Flag: {password}")
                    break
        else:
            print("Password not found in RockYou list.")
except FileNotFoundError:
    print("RockYou wordlist not found! Ensure the file path is correct.")

```

