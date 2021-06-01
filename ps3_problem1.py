#A15753878
import sys, os, itertools

from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.function_family import *

"""
Problem 1 [100 points]
Let F be a family of functions  F:{0, 1}^k x {0, 1}^n --> {0, 1}^n.
Define Enc: {0, 1}^k x {0, 1}^(mn) --> {0, 1}^((m+2)*n) as shown below.
The message space of Enc is the set of all strings M whose length is an
integer multiple of n. 

Notes:
Sizes in comments are bits, sizes in code are in bytes (bits / 8).
In the code K\in{0,1}^k.
"""

def Enc(K, M):
    """
    Encryption algorithm Enc constructed from function family F.

    :param K: blockcipher key
    :param M: plaintext message
    :return: ciphertext
    """
    M = split(M,n_bytes)
    M= [chr(0)*n_bytes]+M
    R = [random_string(n_bytes) for i in range(2)]
    C = [R[i] for i in range(2)]
    d = [ord(R[1][-1]) % 2] # d[0] <- lsb(C[0] = lsb(R0||R1) = lsb(R1)
    for i in range(1,len(M)): 
        Wi = xor_strings(R[d[i-1]], M[i-1])
        Pi = F(K,Wi)
        C.append(xor_strings(Pi,M[i]))
        d.append(ord(C[-1][-1]) %2) # C[-1] denotes the last block of C. 
    return join(C)

"""
(1) [30 points] Give a decryption algorithm Dec such that SE = (K,Enc,Dec) is a 
    symmetric encryption scheme satisfying the correct decrypiton condition of Slide 3.
"""

def Dec(K,C):
    """
    You must fill in this method. This is the decryption algorithm that the problem is
    asking for.

    :param K: This is the secret key for the decryption algorithm. It is an n-bit string
    :param C: This is the ciphertext to decrypt. You may assume that C is a bitstring whose length is a multiple of n. 
    :return: return a plaintext string.
    """
    C=  split(C,n_bytes)
    M = [chr(0)*n_bytes]
    R = [C[i] for i in range(2)] 
    d = [ord(R[1][-1]) % 2] 

    for i in range(2,len(C)): 
        Wi = xor_strings(R[d[i-2]], M[i-2])
        Pi = F(K,Wi)
        M.append(xor_strings(Pi,C[i]))
        d.append(ord(C[i][-1]) %2) 
        
    return join(M[1:])

    
"""
(2) [70 points] Give a 1-query adversary A that has advantage Adv^ind-cpa_SE(A) >= 0.9
                and running time O(T_F + n).
"""

def A(fn):

    M0 = chr(1) * 3 *n_bytes
    M1 = chr(0) * 3 * n_bytes

    C = fn(M0,M1)
    C = split(C,n_bytes)
    #d = [ord(C[1][-1]) % 2]

    if(C[2] == C[3]):
        return 1
    if(C[3] == C[4]):
        return 1 
    if(C[2] == C[4]):
        return 1 

    if((C[2][-1] == C[3][-1])):
        return 1
    if(C[3][-1] == C[4][-1]):
        return 1
    if(C[2][-1] == C[4][-1]):
        return 1

    if((C[2][1] == C[3][1])):
        return 1
    if(C[3][1] == C[4][1]):
        return 1
    if(C[2][1] == C[4][1]):
        return 1
    
    return 0

   
"""
========================================================================================
Code below this line is used to test your solution and should not be changed.
========================================================================================
"""

from playcrypt.games.game_lr import GameLR
from playcrypt.simulator.lr_sim import LRSim

def testDecryption():
    worked = True
    for j in range(100):
        K = random_string(k_bytes)
        num_blocks = random.randrange(n_bytes*8)
        M = random_string(num_blocks*n_bytes)
        C = Enc(K, M)
        if M != Dec(K, C):
            print ("Your decryption function is incorrect.")
            worked = False
            break
    if worked:
        print ("Your decryption function appears correct.")

if __name__ == '__main__':
    # Arbitrary choices of k, n.
    k = 128
    n = 64
    # Block & key size in bytes.
    k_bytes = k//8
    n_bytes = n//8

    FF = FunctionFamily(k_bytes, n_bytes, n_bytes)
    F = FF.evaluate

    g = GameLR(1, Enc, k_bytes)
    s = LRSim(g, A)
    testDecryption()
    print ("The advantage of your adversary A1 is approximately " + str(s.compute_advantage(20)))
