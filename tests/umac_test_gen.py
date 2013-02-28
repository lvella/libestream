from Crypto.Cipher import AES
import struct

def h(str):
    return ''.join(['%02X' % ord(n) for n in str])

def kdf(key, index, numbytes):
    n = (numbytes / 16) + 1

    cipher = AES.new(key, AES.MODE_ECB)

    out = ''
    for i in xrange(1, n +1):
        T = struct.pack('>QQ', index, i)
        c = cipher.encrypt(T)
        out += c

    return out[:numbytes]

def pdf(key, nonce, taglen):
    if taglen in (4, 8):
        n = struct.unpack('>Q', nonce)[0]
        index = n % (16 / taglen)
        n = n ^ index
        nonce = struct.pack('>Q', n)

    nonce = nonce + ('\0' * max(0, 16 - len(nonce)))

    k2 = kdf(key, 0, 16)
    cipher = AES.new(k2, AES.MODE_ECB)

    t = cipher.encrypt(nonce)
    if taglen in (4, 8):
        return t[(taglen*index):][:8]
    else:
        return t[:taglen]

def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

def keygen(key, taglen):
    iters = taglen / 4
    l1key = kdf(key, 1, 1024 + (iters - 1) * 16)
    l2key = kdf(key, 2, iters * 24)
    l3key1 = kdf(key, 3, iters * 64)
    l3key2 = kdf(key, 4, iters * 4)

    return (l1key, l2key, l3key1, l3key2)

def keys_write(key):
    out = open('uhash_vec_keys.h', 'w')
    out.write('#include "umac.h"\n\n')

    for bitsize in (32, 64, 96, 128):
        (l1key, l2key, l3key1, l3key2) = keygen(key, bitsize / 8)

        out.write('uhash_{0}_key key_{0} = {{\n{{\n'.format(bitsize))
        for k1 in split_len(l1key, 4):
            out.write('0x{}u,\n'.format(h(k1)))

        out.write('},\n{\n')
        for k2 in split_len(l2key, 24):
            vals = [struct.unpack('>Q', x)[0] & 0x01ffffff01ffffff
                    for x in split_len(k2, 8)]
            out.write('{{0x{:016X}u, {{ {{0x{:016X}u, 0x{:016X}u }} }} }}, \n'
                      .format(*vals))

        out.write('},\n{\n')
        for k3_1 in  split_len(l3key1, 8):
            val = struct.unpack('>Q', k3_1)[0] % 0xFFFFFFFFB
            out.write('0x{:08X}u,\n'.format(val))

        out.write('},\n{\n')
        for k3_2 in split_len(l3key2, 4):
            out.write('0x{}u,\n'.format(h(k3_2)))

        out.write('}};\n\n')

key = "abcdefghijklmnop"
nonce = "bcdefghi"
keys_write(key)
print h(pdf(key, nonce, 8))
print h(pdf(key, nonce, 16))
