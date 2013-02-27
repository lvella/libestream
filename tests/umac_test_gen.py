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

def keyset(key, taglen):
    iters = taglen / 4
    l1key = kdf(key, 1, 1024 + (iters - 1) * 16)
    l2key = kdf(key, 2, iters * 24)
    l3key1 = kdf(key, 3, iters * 64)
    l3key2 = kdf(key, 4, iters * 4)

    for (k, i) in zip(split_len(l1key, 4), range(1, 256 + 4 + 1)):
        #print map(ord, k)
        print 'K_%d' % i, h(k)

    print ''

    for k in split_len(l2key, 24):
        n = struct.unpack('>Q', k[:8])[0] & 0x01ffffff01ffffff
        print "%016X" % n

    print ''

    for k in split_len(l3key1, 64):
        for l in split_len(k, 8):
            n = struct.unpack('>Q', l)[0] % 0xFFFFFFFFB
            print "%010X" % n

    print ''

    for k in split_len(l3key2, 4):
        print h(k)

    print ''

key = "abcdefghijklmnop"
nonce = "bcdefghi"
taglen = 8
keyset(key, taglen)
print h(pdf(key, nonce, taglen))
print h(pdf(key, nonce, 16))
