# ropfu

## Summary

This challenge provides a Linux CLI program with a stack buffer overflow
vulnerability that is exploited by executing functions within the program different from the original intended execution.

**Artifacts:**
* chall/canaveral.c: vulnerable program source code provided by challenge authors
* solve.py: exploit script that manipulates the program to call `win`
* note: challenge authors provided a `canaveral` executable during the actual time of the competition

## Context

The `canaveral` challenge authors provide a domain and port to connect to the
challenge. They also provide a copy of the compiled challenge binary
(`canaveral`) which is not included here and the source code used to produce the binary (`chall/canaveral.c`).

`canaveral` runs as a CLI program and
reads input from `stdin` and prints to `stdout`.

The program functions only to prompt the user to enter a line of text,
receive that text, and then exit:

```
$ ./chall/vuln
Enter the launch command: 
```

The binary is statically compiled without standard exploit mitigations applied:
the stack is *executable* and position independent executable (PIE) settings
are *disabled*. 

```
$ checksec canaveral
[*] 'canaveral'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX disabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

$ objdump -d chall/canaveral
<snip>
00000000000011c8 <func0>:
    11c8:       f3 0f 1e fa             endbr64 
    11cc:       55                      push   %rbp
    11cd:       48 89 e5                mov    %rsp,%rbp
    11d0:       48 83 c4 80             add    $0xffffffffffffff80,%rsp
    11d4:       64 48 8b 04 25 28 00    mov    %fs:0x28,%rax
    11db:       00 00 
    11dd:       48 89 45 f8             mov    %rax,-0x8(%rbp)
    11e1:       31 c0                   xor    %eax,%eax
    11e3:       48 8d 05 22 0e 00 00    lea    0xe22(%rip),%rax        # 200c <_IO_stdin_used+0xc>
    11ea:       48 89 c7                mov    %rax,%rdi
    11ed:       b8 00 00 00 00          mov    $0x0,%eax
    11f2:       e8 99 fe ff ff          call   1090 <printf@plt>
    11f7:       48 8d 45 80             lea    -0x80(%rbp),%rax
    11fb:       48 89 c7                mov    %rax,%rdi
    11fe:       b8 00 00 00 00          mov    $0x0,%eax
    1203:       e8 98 fe ff ff          call   10a0 <gets@plt>
    1208:       90                      nop
    1209:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    120d:       64 48 2b 04 25 28 00    sub    %fs:0x28,%rax
    1214:       00 00 
    1216:       74 05                   je     121d <func0+0x55>
    1218:       e8 63 fe ff ff          call   1080 <__stack_chk_fail@plt>
    121d:       c9                      leave  
    121e:       c3                      ret    
<snip>
```

## Vulnerability

The `canaveral` program contains a stack buffer overwrite vulnerability in the `func0`
function. By using `gets` to read user input from `stdin`, it allows the user to overflow the buffer and overwrite the return address of the original execution.

`func0`  contains a call to libc `gets` to read user input from `stdin`:

```
void func0() {
	char inp[100];
	printf("Enter the launch command: ");
	gets(inp);
}
```

`gets` will read a line from stdin into the `inp` buffer which is of size 100. However, `gets` has no limit on how many bytes is read into the buffer, and it does not check for buffer ovveruns. 

This means that an attacker can write past the 100 bytes allocated on the stack for the `inp` buffer and overwrite information stored in addresses beyong the buffer.



## Exploitation

**Exploit overview**: the exploit uses a local stack buffer overflow to change the original execution of the program by overwriting the return address in the function call stack

**Exploit mitigation considerations**:
* Stack canary disabled: stack canaries being disabled means that we can overwrite the return addresses on the stack and manipulate program execution flow.
* PIE disabled: the addresses of executable instructions are fixed for every run and can be known before execution which allows the attacker to easily redirect the program to functions with the known addresses.


**Exploit description**: the `solve.py` exploit sends a single input that writes into the `inp` buffer and continues to write past it into the return address to execute the `win` function

```
vuln() stack layout:
low address     +------------+  <--- ebp - 0x50       +------------+
                |            |                        |            |
                |  inp[100]  |                        |   all 1s   |
                |            |                        |            |    
                +------------+                        |            |
                |   padding  |                        |            |         
                +------------+  <--- current ebp      +------------+
                | saved old  |                        |   all 1s   |  
                |     ebp    |                        |            |     
                +------------+                        +------------+
                |   return   |                        |  addr of   |    
                |   address  |                        | ret instr  |    
high address    +------------+                        +------------+  
                                                      |    win     |
                                                      |    addr    |
                                                      +------------+
```


However, 28 bytes is not a lot of space; the pwntools x86 Linux `/bin/sh`
shellcode is 42 bytes long and will not fit in the padding space. Rather than
trying to minimize the shellcode to squeeze it in, we instead place a single
`jmp` instruction at the beginning of the input that jumps forward 32 bytes (a
trampoline), and then place the full shellcode _after_ the gadget, where we
have no limitation on the size of the shellcode. The only remaining constraint
is that the input cannot contain any newline characters.

```
eax
 |
 V
 0           2                    28        32
 [jmp $+0x20][---padding---------][@JMP-EAX][----shellcode----]
  |                                          ^
  |                                          |
  --------------------------------------------
```

Executing the vulnerable program with this input results in the execution of
a `/bin/sh` shell to read the flag. See the `solve.py` script for proof of
concept.

**Exploit primitives used**:
1. Local stack buffer overwrite to overwrite saved return address
2. Overwrite saved return address to control instruction pointer
3. Control instruction pointer to execute arbitrary code

## Remediation

To patch the vulnerability, the `gets` function call should be replaced with a
size-sensitive function call like `fgets`, and restricted to only read as many
bytes as are allocated:

```
void vuln() {
  char buf[16];
  printf("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n");
  return fgets(buf, sizeof buf, stdin);
}
```

Compiling the program with standard exploit mitigations would make the
vulnerability more difficult to exploit:
* a stack canary would prevent turning the local overwrite into instruction
  pointer control.
* PIE would prevent the use of program instructions as ROP gadgets.
* a non-executable stack would prevent the execution of shellcode written to
  the stack.

None of the above mitigations would guarantee that the vulnerability is not
exploitable, but they would have made exploitation more challenging.

We could search programs for more vulnerabilities of this type by conducting a
simple regex search for calls to the `gets` library function.