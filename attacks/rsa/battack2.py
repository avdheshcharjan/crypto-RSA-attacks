import logging
import os
import sys
from hashlib import sha256
from math import lcm
from random import getrandbits
from random import randrange
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from sage.all import crt

def floor_div(a, b):
    return a // b

def ceil_div(a, b):
    return a // b + (a % b > 0)

def _insert(M, a, b):
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            a = min(a, a_)
            b = max(b, b_)
            M[i] = (a, b)
            return
    M.append((a, b))

def _step_1(padding_oracle, n, e, c):
    s0 = 1
    c0 = c
    attempts = 0
    while not padding_oracle(c0):
        s0 = randrange(2, n)
        c0 = (c * pow(s0, e, n)) % n
        attempts += 1
        if attempts % 1000 == 0:
            print(f"Step 1: Tried {attempts} values...")
    print(f"Step 1: Found valid s0 after {attempts} attempts")
    return s0, c0

def _step_2a(padding_oracle, n, e, c0, B):
    s = ceil_div(n, 3 * B)
    attempts = 0
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1
        attempts += 1
        if attempts % 1000 == 0:
            print(f"Step 2a: Tried {attempts} values...")
    print(f"Step 2a: Found valid s after {attempts} attempts")
    return s

def _step_2b(padding_oracle, n, e, c0, s):
    attempts = 0
    s += 1
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1
        attempts += 1
        if attempts % 1000 == 0:
            print(f"Step 2b: Tried {attempts} values...")
    print(f"Step 2b: Found valid s after {attempts} attempts")
    return s

def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    r = ceil_div(2 * (b * s - 2 * B), n)
    attempts = 0
    while True:
        left = ceil_div(2 * B + r * n, b)
        right = floor_div(3 * B + r * n, a)
        for s_candidate in range(left, right + 1):
            if padding_oracle((c0 * pow(s_candidate, e, n)) % n):
                print(f"Step 2c: Found valid s after {attempts} attempts")
                return s_candidate
            attempts += 1
        r += 1
        if attempts % 1000 == 0:
            print(f"Step 2c: Tried {attempts} values...")

def _step_3(n, B, s, M):
    if not M:
        print("Warning: M is empty in step 3")
        return []
    
    M_ = []
    for (a, b) in M:
        left = ceil_div(a * s - 3 * B + 1, n)
        right = floor_div(b * s - 2 * B, n)
        for r in range(left, right + 1):
            a_ = max(a, ceil_div(2 * B + r * n, s))
            b_ = min(b, floor_div(3 * B - 1 + r * n, s))
            _insert(M_, a_, b_)
    
    if not M_:
        print("Warning: No valid intervals found in step 3")
    else:
        print(f"Step 3: Found {len(M_)} intervals")
    return M_

def valid_padding_v1_5(cipher, k, c, sentinel):
    try:
        m = pow(c, cipher._key.d, cipher._key.n)
        em = int.to_bytes(m, k, byteorder='big')
        cipher.decrypt(em, sentinel)
        return True
    except:
        return False

def attack(padding_oracle, n, e, c):
    k = ceil_div(n.bit_length(), 8)
    B = 2 ** (8 * (k - 2))
    print("Executing step 1...")
    s0, c0 = _step_1(padding_oracle, n, e, c)
    M = [(2 * B, 3 * B - 1)]
    print(f"Initial M size: {len(M)}")
    
    print("Executing step 2.a...")
    s = _step_2a(padding_oracle, n, e, c0, B)
    M = _step_3(n, B, s, M)
    
    if not M:
        raise ValueError("No valid intervals found after step 2.a")
    
    print("Starting while loop...")
    iteration = 0
    while True:
        iteration += 1
        print(f"Iteration {iteration}, M size: {len(M)}")
        
        if len(M) > 1:
            s = _step_2b(padding_oracle, n, e, c0, s)
        else:
            (a, b) = M[0]
            if a == b:
                m = (a * pow(s0, -1, n)) % n
                return m
            s = _step_2c(padding_oracle, n, e, c0, B, s, a, b)
        
        M = _step_3(n, B, s, M)
        if not M:
            raise ValueError(f"No valid intervals found in iteration {iteration}")

# Set up RSA parameters
p = 8371433218848358145038188834376952780015970046874950635276595345380605659774957836526221018721547441806561287602735774125878237978059976407232379361297183
q = 11466377869587829648871708469119992174705652479796097233499813683057983019116298140412758762054846456284362676185136356912754651085919371755263313171141577
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
k = 128
cipher = PKCS1_v1_5.new(RSA.construct((n, e, d)))
sentinel = b"\x00" * k

# Create test message and encrypt it
message = b"we love prof tay"
print("Original message:", message)

# Encrypt the message
ciphertext = cipher.encrypt(message)
c = int.from_bytes(ciphertext, byteorder='big')
print("Encrypted value:", c)

# Attack to decrypt
print("\nStarting Bleichenbacher attack...")
try:
    m_ = attack(lambda c: valid_padding_v1_5(cipher, k, c, sentinel), n, e, c)
    # Convert recovered integer to bytes and remove padding
    recovered = int.to_bytes(m_, k, byteorder='big')
    print("\nRecovered message:", recovered.split(b'\x00', 2)[-1])
except Exception as e:
    print(f"Attack failed: {str(e)}")
    print("Debug information:")
    print(f"n bits: {n.bit_length()}")
    print(f"k value: {k}")