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

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

# from attacks.rsa import bleichenbacher
# from attacks.rsa import boneh_durfee
from attacks.rsa import manger

class TestRSA(TestCase):
    def _crt_faulty_sign(self, m, p, q, d):
        sp = pow(m, (d % (p - 1)), p)
        sq = pow(m, (d % (q - 1)), q)
        # Random bitflip?
        return crt([sp, sq ^ 1], [p, q])

    def _valid_padding_v1_5(self, cipher, k, c, sentinel):
        return cipher.decrypt(c.to_bytes(k, byteorder="big"), sentinel) != sentinel

    def _valid_padding_oaep(self, n, d, B, c):
        return pow(c, d, n) < B

    def test_manger(self):
        p = 11550140397625831237795340388931764619590203348477070899900744712142057429184408396002838334752152208585447782690486121190515605653404086833126302256665293
        q = 11235144439517708878544315543777445305219755865213735904183809061384223163112309675101975657775860815518111926557521605302651507623721470417911684612028139
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        k = 128
        B = 2 ** (8 * (k - 1))

        # We know it doesn't take too long to decrypt this c using Manger's attack (~1000 queries).
        c = 88724310553655024406998673890906955926769391892532500091257501059546128411164957509885727337380526571122120832873601676837576704085217211100300291225160276367472411100146256463969941418608788600822191439544173046896875356040910136817300727665043174773434871223215069772985286442145129776197191070321384162933
        m = pow(c, d, n)
        m_ = manger.attack(lambda c: self._valid_padding_oaep(n, d, B, c), n, e, c)
#         self.assertIsInstance(m_, int)
#         self.assertEqual(m, m_)
#         print(f"plaintext: {m =}")
#         print(f"plaintext: {m_ =}")
        assertEqual(m, m_)
        print(f"found m {m}")
            # Convert to bytes and display (assuming PKCS#1 v1.5 padding)
#         try:
#         # Get byte length
#             byte_length = (n.bit_length() + 7) // 8
#             message_bytes = m_.to_bytes(byte_length, byteorder='big')
        
#         # Look for padding boundary
#         # Standard PKCS#1 v1.5 padding starts with 0x00 0x02
#             if b'\x00\x02' in message_bytes:
#                 padding_end = message_bytes.find(b'\x00', 2)  # Find end of padding
#                 if padding_end != -1:
#                     plaintext = message_bytes[padding_end+1:]
#                     print(f"Decrypted plaintext (hex): {plaintext.hex()}")
#                     try:
#                         print(f"Decrypted plaintext (ascii): {plaintext.decode('ascii')}")
#                     except UnicodeDecodeError:
#                         print("Note: Plaintext is not ASCII-decodable")
#         except ValueError as e:
#             print(f"Could not convert to bytes: {e}")