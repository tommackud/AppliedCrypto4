#################################################################
# Module 5 - Lesson 1 - Part 2: Diffie-Hellman Key Exchange (DHKE)
# Generate a "Strong" prime (script below) p
# Pick a "base" which can really just be the number g=2
# Generate a PRIVATE random number, a, which shares no factors with p−1 (recipe below)
# Calculate the public exponent: A:=ga(modp).
# Publish your public key (triplet): p,g,A (DO NOT PUBLISH a!)
#################################################################
from Crypto.Util.number import *

p = getStrongPrime(512)


def get_good_randy():
    value = 0
    rand = 0
    while value != 1:
        rand = getRandomRange(2, p-2)
        value = GCD(rand, p-1)
    return rand


# ALICE
a = get_good_randy()
g = 2
A = pow(g, a, p)

print('ALICE triplet: ' + str(p) + ' ' + str(g) + ' ' + (str(A)))
print()

# BOB
b = get_good_randy()
B = pow(g, b, p)
BobsK = pow(A, b, p)

# ALICE
AlicesK = pow(B, a, p)

print('Supporting characters: ')
print('a: ' + str(a) + '\n'
      'b: ' + str(b) + '\n'
      'BobsK: ' + str(BobsK) + '\n'
      'AlicesK: ' + str(AlicesK) + '\n'
      'base: ' + str(g) + '\n'
      'p: ' + str(p) + '\n'
      'A: ' + str(A) + '\n'
      'B: ' + str(B) + '\n')



