#Student: Kimiya Ataiyan A15753878
#Worked with: Harsimran Singh
"""
Problem Set 1.1 : Block Ciphers and Key Recovery Security Module
"""

import json
import sys, os, itertools

from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.block_cipher import *

"""
Problem 1 [100 points]
Let E be a blockcipher  E:{0, 1}^k x {0, 1}^n --> {0, 1}^n
and E_I be its inverse.
Define F: {0, 1}^k+n x {0, 1}^n --> {0, 1}^n as shown below.

Notes:
Sizes in comments are bits, sizes in code are in bytes (bits / 8).
In the code K1\in{0,1}^k and K2,M\in{0,1}^n
"""

def F(K, M):
    """
    Blockcipher F constructed from blockcipher E.

    :param K: blockcipher key
    :param M: plaintext message
    :return: ciphertext
    """
    K1 = K[:k_bytes]
    K2 = K[k_bytes:]

    C = E(K1, xor_strings(M, K2))
    return C

"""
(a) [50 points] Give a 1-query adversary A1 that has advantage
                Adv^kr_F(A1) = 1 and running time O(T_E + k + n).
"""

def A1(fn):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for.

    :param fn: This is the oracle supplied by GameKR, you can call this
    oracle to get an "encryption" of the data you pass into it.
    :return: return the a string that represents a key guess.
    """
    rand_key1 = random_string(k_bytes)
    returned_message = random_string(n_bytes)
    C = fn(returned_message)                                    #created by true key
    result = E_I(rand_key1,C) 
    rand_key2 = xor_strings(result, returned_message)
    #C^-1 = xor_strings(M,K2) = M XOR K2 =>          E_I(rand_key1, C) = rand_key2 XOR returned_message XOR returned_message 
    return rand_key1 + rand_key2



"""
(b) [50 points] Give a 3-query adversary A3 that has advantage Adv^kr_F(A3) = 1
                and running time O(2^k * (T_E + k + n)).
"""

def A3(fn):
    """
    You must fill in this method. This is the adversary that the problem is
    asking for.

    :param fn: This is the oracle supplied by GameKR, you can call this
    oracle to get an "encryption" of the data you pass into it.
    :return: return the a string that represents a key guess.
    """
#want to find a key that matches (M1, M2, M3) into (C1,C2,C3)

    returned_message1 = random_string(n_bytes)
    returned_message2 = random_string(n_bytes)
    returned_message3 = random_string(n_bytes)

    C1 = fn(returned_message1) 
    C2 = fn(returned_message2) 
    C3 = fn(returned_message3) 

    #check that key is consistent with (M1,C1),(M2,C2), (M3,C3)
    for i in range(string_to_int((k_bytes)* "\xFF")):   #i is key
        key1 = int_to_string(i,1)
        key2_1 = xor_strings(E_I(key1,C1), returned_message1)
        key2_2 = xor_strings(E_I(key1,C2), returned_message2)
        key2_3 = xor_strings(E_I(key1,C3), returned_message3)
        if(key2_1 == key2_2 and key2_2 == key2_3):
            return key1+key2_1
       

    return i

"""
==============================================================================================
The following lines are used to test your code, and should not be modified.
==============================================================================================
"""

from playcrypt.games.game_kr import GameKR
from playcrypt.simulator.kr_sim import KRSim

if __name__ == '__main__':

    # Arbitrary choices of k, n.
    k = 128
    n = 64
    # Block & key size in bytes.
    k_bytes = k//8
    n_bytes = n//8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g1 = GameKR(1, F, k_bytes+n_bytes, n_bytes)
    s1 = KRSim(g1, A1)
    print("The advantage of your adversary A1 is approximately " + str(s1.compute_advantage(20)))

    # Smaller choices of k, n.
    k = 8
    n = 64
    k_bytes = k//8
    n_bytes = n//8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g3 = GameKR(3, F, k_bytes+n_bytes, n_bytes)
    s3 = KRSim(g3, A3)
    print("The advantage of your adversary A3 is approximately " + str(s3.compute_advantage(20)))
