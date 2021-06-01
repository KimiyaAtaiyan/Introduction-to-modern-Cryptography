#PID:A15753878
#Communicated with: Harsimran Singh
from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.function_family import *

from playcrypt.games.game_prf import GamePRF
from playcrypt.simulator.world_sim import WorldSim

"""
Problem 1 [100 points]
Let G: {0, 1}^k x {0, 1}^l --> {0, 1}^l be a family of functions and let r>= 1 be an
integer. The r-round Feistel cipher associated to G is the family of functions
G^(r): {0, 1}^k x {0, 1}^2l --> {0, 1}^2l, defined as follows for any key K in {0,
1}^k and input x in {0, 1}^2l.
"""
 
def Gr(K,x):
    x0, x1 = split(x)

    L, R = [x0], [x1]

    for i in range(1, r + 1):
        L.append(R[i-1])
        R.append(xor_strings(G(K, R[i-1]), L[i-1]))

    return L[r] + R[r]

"""
1. [40 points] Show that G^(1) is not a secure PRF by presenting in code an
O(T_G+k+l)-time adversary A1 making one query to its Fn oracle and achieving
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
    M = 2 * l_bytes * '\x00'
    C = fn(M)
    L, R = split(C)

    if L == l_bytes * '\x00':
        return 1
    else:
        return 0


"""
2. [60 points] Show that G^(2) is not a secure PRF by presenting in code an
O(T_G+k+l)-time adversary A2 making two queries to its Fn orcale and achieving
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

    M1 = 2 * l_bytes * '\x00'
    M2 = l_bytes * '\x01' + l_bytes * '\x00'

    C1 = fn(M1)
    C2 = fn(M2)

    L0, x = split(C1)
    L1, y = split(C2)

    if L0 == xor_strings(L1, l_bytes * '\x01'):
        return 1
    else:
        return 0



if __name__ == '__main__':
    print("\nWhen k=128, l=128:")
    r=1
    k=128
    l=128
    k_bytes = k//8
    l_bytes = l//8
    G = FunctionFamily(k_bytes, l_bytes, l_bytes).evaluate
    g1 = GamePRF(1, Gr, k_bytes, 2*l_bytes)
    s1 = WorldSim(g1, A1)
    adv1 = s1.compute_advantage(1000)
    print("The advantage of your adversary A1 is approximately " + str(adv1))
    r=2
    g2 = GamePRF(2, Gr, k_bytes, 2*l_bytes)
    s2 = WorldSim(g2, A2)
    adv2 = s2.compute_advantage(1000)
    print("The advantage of your adversary A2 is approximately " + str(adv2))
    
    print("\nWhen k=128, l=8:")
    r=1
    k=128
    l=8
    k_bytes = k//8
    l_bytes = l//8
    G = FunctionFamily(k_bytes, l_bytes, l_bytes).evaluate
    g1 = GamePRF(1, Gr, k_bytes, 2*l_bytes)
    s1 = WorldSim(g1, A1)
    adv1 = s1.compute_advantage(1000)
    print("The advantage of your adversary A1 is approximately " + str(adv1))
    r=2
    g2 = GamePRF(2, Gr, k_bytes, 2*l_bytes)
    s2 = WorldSim(g2, A2)
    adv2 = s2.compute_advantage(1000)
    print("The advantage of your adversary A2 is approximately " + str(adv2))
