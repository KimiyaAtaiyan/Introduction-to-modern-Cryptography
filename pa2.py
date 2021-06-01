import sys, os, itertools, json

sys.path.append(os.path.abspath(os.path.join('..')))
from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.function_family import *

from playcrypt.games.game_prf import GamePRF
from playcrypt.simulator.world_sim import WorldSim

"""
Problem 1 [100 points]
Let G: {0, 1}^k x {0, 1}^l --> {0, 1}^l be a family of functions and let r>= 1 be an
integer. The r-round Feistel cipher associated to G is the family of functions
Gr: {0, 1}^k x {0, 1}^2l --> {0, 1}^2l, defined as shown below.
If E is a family of functions, then T_E denotes the time to compute it.
All times are worst case.
"""

def Gr(K,x):
    x0, x1 = split(x)

    L, R = [x0], [x1]

    for i in range(1, r + 1):
        L.append(R[i-1])
        R.append(xor_strings(G(K, R[i-1]), L[i-1]))

    return L[r] + R[r]

"""
1. [50 points] Show that Gr is not a secure PRF when r=1 by presenting in code
an O(T_G+k+l)-time adversary A1 making one query to its Fn oracle and achieving
Adv^prf_Gr(A1) = 1 - 2^-l.
"""


def A1(fn):
    """
    You must fill in this method. We will define variables r, k, l, k_bytes, l_bytes,
    and G for you.
    :param fn: This is the oracle supplied by GamePRF.
    :return: return 1 to indicate your adversary believes it is the real world
    and return 0 to indicate that your adversary believes it is in the random
    world.
    """

    m = 2 * l_bytes * '\x00'
    c = fn(m)
    l, r = split(c)

    if l == l_bytes * '\x00':
        return 1
    else:
        return 0



"""
2. [50 points] Show that Gr is not a secure PRF when r=2 by presenting in code
an O(T_G+k+l)-time adversary A2 making two queries to its Fn orcale and achieving
Adv^prf_Gr(A2) = 1 - 2^-l.
"""

def A2(fn):
    """
    You must fill in this method. We will define variables r, k, l, k_bytes, l_bytes,
    and G for you.
    :param fn: This is the oracle supplied by GamePRF.
    :return: return 1 to indicate your adversary believes it is the real world
    and return 0 to indicate that your adversary believes it is in the random
    world.
    """

    m0 = 2 * l_bytes * '\x00'
    m1 = l_bytes * '\x01' + l_bytes * '\x00'

    c0 = fn(m0)
    c1 = fn(m1)

    l0, _ = split(c0)
    l1, _ = split(c1)

    if l0 == xor_strings(l1, l_bytes * '\x01'):
        return 1
    else:
        return 0

if __name__ == '__main__':
    warning = False
    f = open("student_info.json", 'r')
    student_info = json.loads(f.read())
    f.close()
    for a in student_info:
        print "%s: %s" % (a, student_info[a])
        if a == "TODO" or student_info[a] == "TODO":
            warning = True
    if warning:
        print "Wrong personal information. Please fill in file student_info.json."

    print "\nWhen k=128, l=128:"
    r=1
    k=128
    l=128
    k_bytes = k/8
    l_bytes = l/8
    G = FunctionFamily(k_bytes, l_bytes, l_bytes).evaluate
    g1 = GamePRF(1, Gr, k_bytes, 2*l_bytes)
    s1 = WorldSim(g1, A1)
    adv1 = s1.compute_advantage(1000)
    print "The advantage of your adversary A1 is approximately " + str(adv1)
    r=2
    g2 = GamePRF(2, Gr, k_bytes, 2*l_bytes)
    s2 = WorldSim(g2, A2)
    adv2 = s2.compute_advantage(1000)
    print "The advantage of your adversary A2 is approximately " + str(adv2)

    print "\nWhen k=128, l=8:"
    r=1
    k=128
    l=8
    k_bytes = k/8
    l_bytes = l/8
    G = FunctionFamily(k_bytes, l_bytes, l_bytes).evaluate
    g1 = GamePRF(1, Gr, k_bytes, 2*l_bytes)
    s1 = WorldSim(g1, A1)
    adv1 = s1.compute_advantage(1000)
    print "The advantage of your adversary A1 is approximately " + str(adv1)
    r=2
    g2 = GamePRF(2, Gr, k_bytes, 2*l_bytes)
    s2 = WorldSim(g2, A2)
    adv2 = s2.compute_advantage(1000)
    print "The advantage of your adversary A2 is approximately " + str(adv2)
