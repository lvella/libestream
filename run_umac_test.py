import subprocess
import random

child = subprocess.Popen(['./umac'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE);
def values():
    x = [[0xffffffffffffffffffffffffffffffff, 1],
         [0xfffffffffffffffffffffffffffffffa, 1],
         [0xfffffffffffffffffffffffffffffffa, 2],
         [0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61, 1],
         [0xffffffffffffffffffffffffffffffff,
          0xffffffffffffffffffffffffffffffff]]

    for e in x:
        print e
        yield e

    x = raw_input()

    for i in xrange(100000):
        yield [random.randrange(2**128) for x in xrange(2)]

for n in values():
    def fmt(val):
        val = "%032x" % val
        return ' '.join((val[:16], val[16:]))
    params = ' '.join(map(fmt, n)) + '\n'

    child.stdin.write(params)
    child.stdin.flush()

    ref_res = (n[0] * n[1]) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61L
    
    res = int(child.stdout.readline(), 0)

    if res == ref_res:
        print "Match:", hex(res)
    else:
        print "FAIL!\n", params, "Calculated:", hex(ref_res), "got:", hex(res)
        break;

child.kill()
