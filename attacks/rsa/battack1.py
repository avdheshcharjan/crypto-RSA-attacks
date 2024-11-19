import logging
import os
import sys
from random import randrange
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

def floor_div(a, b):
    return a // b

def ceil_div(a, b):
    return a // b + (a % b > 0)

def generate_rsa_keys(bits=1024):
    """Generate RSA key pair"""
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (n, e), (n, d)

def pkcs1v15_pad(message, k):
    """PKCS#1 v1.5 padding"""
    message = message.encode() if isinstance(message, str) else message
    mLen = len(message)
    ps = os.urandom(k - mLen - 3)  # Generate random padding
    return b'\x00\x02' + ps + b'\x00' + message

def pkcs1v15_unpad(message, k):
    """PKCS#1 v1.5 unpadding"""
    if len(message) != k:
        return False
    if message[0:2] != b'\x00\x02':
        return False
    i = 2
    while i < len(message):
        if message[i] == 0:
            break
        i += 1
    if i >= len(message) - 1:
        return False
    return message[i+1:]

def encrypt(message, pub_key):
    """Encrypt message using RSA PKCS#1 v1.5"""
    n, e = pub_key
    k = (n.bit_length() + 7) // 8
    padded = pkcs1v15_pad(message, k)
    m = bytes_to_long(padded)
    return pow(m, e, n)

def decrypt(ciphertext, priv_key):
    """Decrypt RSA PKCS#1 v1.5 ciphertext"""
    n, d = priv_key
    k = (n.bit_length() + 7) // 8
    m = pow(ciphertext, d, n)
    padded = long_to_bytes(m, k)
    return pkcs1v15_unpad(padded, k)

def create_padding_oracle(priv_key):
    """Create a PKCS#1 v1.5 padding oracle"""
    def padding_oracle(ciphertext):
        n, d = priv_key
        k = (n.bit_length() + 7) // 8
        m = pow(ciphertext, d, n)
        try:
            padded = long_to_bytes(m, k)
            return padded[0:2] == b'\x00\x02'
        except:
            return False
    return padding_oracle

def _insert(M, a, b):
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            a = min(a, a_)
            b = max(b, b_)
            M[i] = (a, b)
            return
    M.append((a, b))

# [Previous step_1, step_2a, step_2b, step_2c, step_3 functions remain the same]
# ... [Keep all the previous step functions unchanged]

def attack(padding_oracle, n, e, c):
    """Main attack function - keep unchanged"""
    # ... [Keep the previous attack function implementation]

# Main execution
if __name__ == "__main__":
    # Generate RSA keys
    pub_key, priv_key = generate_rsa_keys(1024)
    n, e = pub_key
    
    # Message to encrypt
    message = "we love Prof Tay"
    logging.info(f"Original message: {message}")
    
    # Encrypt message
    c = encrypt(message, pub_key)
    logging.info(f"Encrypted ciphertext: {c}")
    
    # Create padding oracle
    oracle = create_padding_oracle(priv_key)
    
    # Perform attack
    try:
        m = attack(oracle, n, e, c)
        k = (n.bit_length() + 7) // 8
        recovered = pkcs1v15_unpad(long_to_bytes(m, k), k)
        if recovered:
            recovered_message = recovered.decode()
            logging.info(f"Recovered message: {recovered_message}")
            assert recovered_message == message, "Message recovery failed!"
        else:
            logging.error("Failed to unpad recovered message")
    except Exception as e:
        logging.error(f"Attack failed: {e}")