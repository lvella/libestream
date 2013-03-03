from Crypto.Cipher import AES
import struct
from umac import umac_tag

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
        return t[(taglen*index):][:taglen]
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

def keys_write(key, out):
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

def pads_write(key, nonce, out):
    pad = pdf(key, nonce, 4)
    out.write('uint32_t pad32 = 0x{}u;\n\n'.format(h(pad)))

    for i in xrange(2, 4+1):
        pad = pdf(key, nonce, i*4)
        out.write('uint32_t pad{}[{}] = {{\n'.format(i*32, i))
        for c in split_len(pad, 4):
            out.write('0x{}u,\n'.format(h(c)))
        out.write('};\n\n')

def main():
    outfile = open('uhash_vec_keys.h', 'w')
    outfile.write('#include "umac.h"\n\n')

    key = "abcdefghijklmnop"
    nonce = "bcdefghi"

    keys_write(key, outfile)
    pads_write(key, nonce, outfile)

    outfile = open('uhash_test_correct_output.txt', 'w')
    cases = (('<empty>', ''),
             ("'a' * 3", 'aaa'),
             ("'a' * 2^10", 'a' * (1 << 10)),
             ("'a' * 2^15", 'a' * (1 << 15)),
             ("'a' * 2^20", 'a' * (1 << 20)),
             ("'a' * 2^25", 'a' * (1 << 25)),
             ("'abc' * 1", "abc"),
             ("'abc' * 500", 'abc' * 500))

    for (case_name, message) in cases:
        print >>outfile, "Message: %s" % case_name
        for taglen in (32, 64, 96, 128):
            tag = umac_tag(message, key, nonce, taglen)
            print >>outfile,  "%d:%s" % (taglen, tag)

if __name__ == '__main__':
    main()
