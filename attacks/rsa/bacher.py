import logging
from math import ceil
from random import randrange
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

def floor_div(a, b):
    return a // b

def ceil_div(a, b):
    return a // b + (a % b > 0)

def valid_padding_v1_5(cipher, k, c, sentinel):
    try:
        m = pow(c, cipher._key.d, cipher._key.n)
        em = int.to_bytes(m, k, byteorder='big')
        cipher.decrypt(em, sentinel)
        return True
    except:
        return False

def _insert(M, a, b):
    if a > b:
        return False
    
    for i, (a_, b_) in enumerate(M):
        if max(a, a_) <= min(b, b_):
            M[i] = (min(a, a_), max(b, b_))
            return True
            
    M.append((a, b))
    M.sort()
    return True

def _step_2a(padding_oracle, n, e, c0, B):
    s = ceil_div(n, 3 * B)
    attempts = 0
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1
        attempts += 1
        if attempts > 10000:
            raise ValueError("Too many attempts in step 2a")
    logging.info(f"Step 2a found s = {s} after {attempts} attempts")
    return s

def _step_2b(padding_oracle, n, e, c0, s):
    attempts = 0
    s_prev = s
    s = s_prev + 1
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1
        attempts += 1
        if attempts > 10000:
            raise ValueError("Too many attempts in step 2b")
    logging.info(f"Step 2b found s = {s} after {attempts} attempts")
    return s

def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    ri = 2 * (b * s - 2 * B) // n
    if (2 * b * s - 2 * B) % n != 0:
        ri += 1
    
    while True:
        si = (2 * B + ri * n + b - 1) // b
        if si * a >= 3 * B + ri * n:
            ri += 1
            continue
            
        if padding_oracle((c0 * pow(si, e, n)) % n):
            return si
            
        ri += 1

def _step_3(n, B, si, M):
    M_ = []
    for (a, b) in M:
        ri_min = (a * si - 3 * B + 1) // n
        ri_max = (b * si - 2 * B) // n
        
        for ri in range(ri_min, ri_max + 1):
            a_new = max(a, ceil_div(2 * B + ri * n, si))
            b_new = min(b, (3 * B - 1 + ri * n) // si)
            
            if a_new <= b_new:
                _insert(M_, a_new, b_new)
                logging.debug(f"Added interval: ({a_new}, {b_new})")
    
    if not M_:
        logging.error(f"Step 3: No valid intervals found for si = {si}")
        logging.error(f"Original intervals: {M}")
    else:
        logging.info(f"Step 3: Found {len(M_)} intervals")
        logging.debug(f"New intervals: {M_}")
    
    return M_

def attack(padding_oracle, n, e, c):
    k = ceil_div(n.bit_length(), 8)
    B = 2 ** (8 * (k - 2))
    
    logging.info("Executing step 1...")
    s0 = 1
    c0 = c
    
    if not padding_oracle(c0):
        attempts = 0
        while not padding_oracle(c0):
            s0 = randrange(2, n)
            c0 = (c * pow(s0, e, n)) % n
            attempts += 1
            if attempts > 10000:
                raise ValueError("Could not find initial s0")
    
    logging.info(f"Found initial s0 = {s0}")
    
    M = [(2 * B, 3 * B - 1)]
    logging.info(f"Initial interval: {M[0]}")
    
    logging.info("Executing step 2.a...")
    si = _step_2a(padding_oracle, n, e, c0, B)
    
    M = _step_3(n, B, si, M)
    if not M:
        raise ValueError("Initial M became empty after step 3")
    
    logging.info("Starting while loop...")
    iteration = 0
    
    while True:
        iteration += 1
        logging.info(f"Iteration {iteration}, |M| = {len(M)}")
        
        if len(M) > 1:
            si = _step_2b(padding_oracle, n, e, c0, si)
        else:
            a, b = M[0]
            if a == b:
                m = (a * pow(s0, -1, n)) % n
                return m
            si = _step_2c(padding_oracle, n, e, c0, B, si, a, b)
        
        M = _step_3(n, B, si, M)
        if not M:
            raise ValueError(f"M became empty during iteration {iteration}")
        
        if len(M) == 1:
            logging.info(f"Current interval: ({M[0][0]}, {M[0][1]})")

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Test parameters
p = 8371433218848358145038188834376952780015970046874950635276595345380605659774957836526221018721547441806561287602735774125878237978059976407232379361297183
q = 11466377869587829648871708469119992174705652479796097233499813683057983019116298140412758762054846456284362676185136356912754651085919371755263313171141577
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
k = 128
cipher = PKCS1_v1_5.new(RSA.construct((n, e, d)))
sentinel = b"\x00" * k

c = 41825379700061736537842449489601003429572348310436151924728709132681706878857980459161227458335791180711615257337302674792944628957924785690808047623816090305399357488221035015598239161665727483209037254608986214222956682098319678174134123989991914343760644546568563066348494878863941359213637733834134515197

try:
    m_ = attack(lambda c: valid_padding_v1_5(cipher, k, c, sentinel), n, e, c)
    print(f"Recovered message: {m_}")
    
    # Try to convert to bytes and string
    try:
        msg_bytes = m_.to_bytes((m_.bit_length() + 7) // 8, byteorder='big')
        print(f"As bytes: {msg_bytes}")
        print(f"As string: {msg_bytes.decode('utf-8', errors='ignore')}")
    except:
        print("Couldn't convert message to bytes/string")
except ValueError as e:
    print(f"Attack failed: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")