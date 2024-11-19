import logging
import os
import sys
from hashlib import sha256
from math import lcm
from random import getrandbits
from random import randrange
from unittest import TestCase
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from sage.all import crt
from random import randrange

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

# from shared import ceil_div, floor_div

def floor_div(a, b):
    """
    Returns floor(a / b), works with large integers.
    :param a: a
    :param b: b
    :return: floor(a / b)
    """
    return a // b


def ceil_div(a, b):
    """
    Returns ceil(a / b), works with large integers.
    :param a: a
    :param b: b
    :return: ceil(a / b)
    """
    return a // b + (a % b > 0)

def valid_padding_v1_5(cipher, k, c, sentinel):
    """
    Validates PKCS#1 v1.5 padding
    """
    try:
        m = pow(c, cipher._key.d, cipher._key.n)
        em = int.to_bytes(m, k, byteorder='big')
        cipher.decrypt(em, sentinel)
        return True
    except:
        return False

def _insert(M, a, b):
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            a = min(a, a_)
            b = max(b, b_)
            M[i] = (a, b)
            return

    M.append((a, b))
    return


# Step 1.
def _step_1(padding_oracle, n, e, c):
    s0 = 1
    c0 = c
    while not padding_oracle(c0):
        s0 = randrange(2, n)
        c0 = (c * pow(s0, e, n)) % n

    return s0, c0


# Step 2.a.
def _step_2a(padding_oracle, n, e, c0, B):
    s = ceil_div(n, 3 * B)
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1

    return s


# Step 2.b.
def _step_2b(padding_oracle, n, e, c0, s):
    s += 1
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1

    return s


# Step 2.c.
def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    r = ceil_div(2 * (b * s - 2 * B), n)
    while True:
        left = ceil_div(2 * B + r * n, b)
        right = floor_div(3 * B + r * n, a)
        for s in range(left, right + 1):
            if padding_oracle((c0 * pow(s, e, n)) % n):
                return s

        r += 1


# Step 3.
def _step_3(n, B, s, M):
    M_ = []
    for (a, b) in M:
        left = ceil_div(a * s - 3 * B + 1, n)
        right = floor_div(b * s - 2 * B, n)
        for r in range(left, right + 1):
            a_ = max(a, ceil_div(2 * B + r * n, s))
            b_ = min(b, floor_div(3 * B - 1 + r * n, s))
            _insert(M_, a_, b_)

    return M_


def attack(padding_oracle, n, e, c):
    """
    Recovers the plaintext using Bleichenbacher's attack.
    More information: Bleichenbacher D., "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
    :param padding_oracle: the padding oracle taking integers, returns True if the PKCS #1 v1.5 padding is correct, False otherwise
    :param n: the modulus
    :param e: the public exponent
    :param c: the ciphertext (integer)
    :return: the plaintext (integer)
    """
    k = ceil_div(n.bit_length(), 8)
    B = 2 ** (8 * (k - 2))
    logging.info("Executing step 1...")
    s0, c0 = _step_1(padding_oracle, n, e, c)
    M = [(2 * B, 3 * B - 1)]
    logging.info("Executing step 2.a...")
    s = _step_2a(padding_oracle, n, e, c0, B)
    M = _step_3(n, B, s, M)
    logging.info("Starting while loop...")
    while True:
        if len(M) > 1:
            s = _step_2b(padding_oracle, n, e, c0, s)
        else:
            (a, b) = M[0]
            if a == b:
                m = (a * pow(s0, -1, n)) % n
                return m
            s = _step_2c(padding_oracle, n, e, c0, B, s, a, b)
        M = _step_3(n, B, s, M)

# p = 8371433218848358145038188834376952780015970046874950635276595345380605659774957836526221018721547441806561287602735774125878237978059976407232379361297183
# q = 11466377869587829648871708469119992174705652479796097233499813683057983019116298140412758762054846456284362676185136356912754651085919371755263313171141577
# n = p * q
# phi = (p - 1) * (q - 1)
# e = 65537
# d = pow(e, -1, phi)
# k = 128
# cipher = PKCS1_v1_5.new(RSA.construct((n, e, d)))
# sentinel = b"\x00" * k
# message = b"we love Prof. Tay Kian Boon"

# ciphertext = cipher.encrypt(message)
# plaintext = cipher.decrypt(ciphertext, sentinel)
# print(plaintext)

# p = 8371433218848358145038188834376952780015970046874950635276595345380605659774957836526221018721547441806561287602735774125878237978059976407232379361297183
# q = 11466377869587829648871708469119992174705652479796097233499813683057983019116298140412758762054846456284362676185136356912754651085919371755263313171141577
# n = p * q
# phi = (p - 1) * (q - 1)
# e = 65537
# d = pow(e, -1, phi)
# k = 128
# cipher = PKCS1_v1_5.new(RSA.construct((n, e, d)))
# sentinel = b"\x00" * k

# # We know it doesn't take too long to decrypt this c using Bleichenbacher's attack (~7700 queries).
# c =     41825379700061736537842449489601003429572348310436151924728709132681706878857980459161227458335791180711615257337302674792944628957924785690808047623816090305399357488221035015598239161665727483209037254608986214222956682098319678174134123989991914343760644546568563066348494878863941359213637733834134515197
# m = pow(c, d, n)
# # m_ = attack(
# # lambda c: valid_padding_v1_5(cipher, k, c, sentinel), n, e, c)

# # Then update your attack call:
# m_ = attack(
#     lambda c: valid_padding_v1_5(cipher, k, c, sentinel), n, e, c)
# assert isinstance(m_, int)
# assertEqual(m, m_)

import logging

# Some logging so we can see what's happening.
logging.basicConfig(level=logging.DEBUG)

# N=95988313752173787236464264997222317633178058207164462965320376498486955373050811718386697262465065333666742809707245077446652923787683573783908267900940743801315278868655372316905644954787452099747246676769634015447101433755319775690938793374962397741199657254430474660701691504550173338934906408117508164191
# e = 65537
# p_bits = 512
# delta = 0.26

# p, q = attack(N, e, p_bits, delta=delta, m=3)
# assert p * q == N
# print(f"Found {p = } and {q = }")
p = 8371433218848358145038188834376952780015970046874950635276595345380605659774957836526221018721547441806561287602735774125878237978059976407232379361297183
q = 11466377869587829648871708469119992174705652479796097233499813683057983019116298140412758762054846456284362676185136356912754651085919371755263313171141577
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
k = 128
cipher = PKCS1_v1_5.new(RSA.construct((n, e, d)))
sentinel = b"\x00" * k

        # We know it doesn't take too long to decrypt this c using Bleichenbacher's attack (~7700 queries).
c = 41825379700061736537842449489601003429572348310436151924728709132681706878857980459161227458335791180711615257337302674792944628957924785690808047623816090305399357488221035015598239161665727483209037254608986214222956682098319678174134123989991914343760644546568563066348494878863941359213637733834134515197
# m = pow(c, d, n)
m_ = attack(lambda c: valid_padding_v1_5(cipher, k, c, sentinel), n, e, c)
#         self.assertIsInstance(m_, int)
#         self.assertEqual(m, m_)

print(m_)