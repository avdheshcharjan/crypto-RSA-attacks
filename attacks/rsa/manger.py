import logging
import os
import sys

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)


def _valid_padding_oaep(self, n, d, B, c):
    return pow(c, d, n) < B

def ceil_div(a, b):
    """
    Returns ceil(a / b), works with large integers.
    :param a: a
    :param b: b
    :return: ceil(a / b)
    """
    return a // b + (a % b > 0)

def floor_div(a, b):
    """
    Returns floor(a / b), works with large integers.
    :param a: a
    :param b: b
    :return: floor(a / b)
    """
    return a // b


# Step 1.
def _step_1(padding_oracle, n, e, c):
    f1 = 2
    while padding_oracle((pow(f1, e, n) * c) % n):
        f1 *= 2

    return f1


# Step 2.
def _step_2(padding_oracle, n, e, c, B, f1):
    f2 = floor_div(n + B, B) * f1 // 2
    while not padding_oracle((pow(f2, e, n) * c) % n):
        f2 += f1 // 2

    return f2


# Step 3.
def _step_3(padding_oracle, n, e, c, B, f2):
    mmin = ceil_div(n, f2)
    mmax = floor_div(n + B, f2)
    while mmin < mmax:
        f = floor_div(2 * B, mmax - mmin)
        i = floor_div(f * mmin, n)
        f3 = ceil_div(i * n, mmin)
        if padding_oracle((pow(f3, e, n) * c) % n):
            mmax = floor_div(i * n + B, f3)
        else:
            mmin = ceil_div(i * n + B, f3)
    return mmin


def attack(padding_oracle, n, e, c):
    """
    Recovers the plaintext using Manger's attack.
    More information: Manger J., "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0"
    :param padding_oracle: the padding oracle taking integers, returns True if the PKCS #1 OAEP padding length is correct, False otherwise
    :param n: the modulus
    :param e: the public exponent
    :param c: the ciphertext (integer)
    :return: the plaintext (integer)
    """
    k = ceil_div(n.bit_length(), 8)
    B = 2 ** (8 * (k - 1))
    # TODO: extend at some point?
    assert 2 * B < n
    logging.info("Executing step 1...")
    f1 = _step_1(padding_oracle, n, e, c)
    logging.info("Executing step 2...")
    f2 = _step_2(padding_oracle, n, e, c, B, f1)
    logging.info("Executing step 3...")
    m = _step_3(padding_oracle, n, e, c, B, f2)
    return m


# #testing
# p = 11550140397625831237795340388931764619590203348477070899900744712142057429184408396002838334752152208585447782690486121190515605653404086833126302256665293
# q = 11235144439517708878544315543777445305219755865213735904183809061384223163112309675101975657775860815518111926557521605302651507623721470417911684612028139
# n = p * q
# phi = (p - 1) * (q - 1)
# e = 65537
# d = pow(e, -1, phi)
# k = 128
# B = 2 ** (8 * (k - 1))

# # We know it doesn't take too long to decrypt this c using Manger's attack (~1000 queries).
# c = 88724310553655024406998673890906955926769391892532500091257501059546128411164957509885727337380526571122120832873601676837576704085217211100300291225160276367472411100146256463969941418608788600822191439544173046896875356040910136817300727665043174773434871223215069772985286442145129776197191070321384162933
# m = pow(c, d, n)
# m_ = attack(lambda c: self._valid_padding_oaep(n, d, B, c), n, e, c)
# assertIsInstance(m_, int)
# assertEqual(m, m_)


def _valid_padding_v1_5(self, cipher, k, c, sentinel):
        return cipher.decrypt(c.to_bytes(k, byteorder="big"), sentinel) != sentinel

def _valid_padding_oaep(self, n, d, B, c):
        return pow(c, d, n) < B


p=11550140397625831237795340388931764619590203348477070899900744712142057429184408396002838334752152208585447782690486121190515605653404086833126302256665293
q=11235144439517708878544315543777445305219755865213735904183809061384223163112309675101975657775860815518111926557521605302651507623721470417911684612028139
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
k = 128
B = 2 ** (8 * (k - 1))

        # We know it doesn't take too long to decrypt this c using Manger's attack (~1000 queries).
c = 88724310553655024406998673890906955926769391892532500091257501059546128411164957509885727337380526571122120832873601676837576704085217211100300291225160276367472411100146256463969941418608788600822191439544173046896875356040910136817300727665043174773434871223215069772985286442145129776197191070321384162933
m = pow(c, d, n)
m_ = attack(lambda c: self._valid_padding_oaep(n, d, B, c), n, e, c)
# self.assertIsInstance(m_, int)
# self.assertEqual(m, m_)
assertEqual(m, m_)
print(f"found m {m}")