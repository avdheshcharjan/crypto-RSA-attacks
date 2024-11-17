import logging
import os
import sys

from sage.all import RR
from sage.all import ZZ


path = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
)
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks import known_phi
from shared import herrmann_may


def attack(N, e, factor_bit_length, partial_p=None, delta=0.25, m=1, t=None):
    """
    Recovers the prime factors if the private exponent is too small.
    This implementation exploits knowledge of least significant bits of prime factors, if available.
    More information: Boneh D., Durfee G., "Cryptanalysis of RSA with Private Key d Less than N^0.292"
    :param N: the modulus
    :param e: the public exponent
    :param factor_bit_length: the bit length of the prime factors
    :param partial_p: the partial prime factor p (PartialInteger) (default: None)
    :param delta: a predicted bound on the private exponent (d < N^delta) (default: 0.25)
    :param m: the m value to use for the small roots method (default: 1)
    :param t: the t value to use for the small roots method (default: automatically computed using m)
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    # Use additional information about factors to speed up Boneh-Durfee.
    p_lsb, p_lsb_bit_length = (0, 0) if partial_p is None else partial_p.get_known_lsb()
    q_lsb = (pow(p_lsb, -1, 2**p_lsb_bit_length) * N) % (2**p_lsb_bit_length)
    A = (N >> p_lsb_bit_length) + pow(2, -p_lsb_bit_length, e) * (
        p_lsb * q_lsb - p_lsb - q_lsb + 1
    )

    x, y = ZZ["x", "y"].gens()
    f = x * (A + y) + pow(2, -p_lsb_bit_length, e)
    X = int(RR(e) ** delta)
    Y = int(2 ** (factor_bit_length - p_lsb_bit_length + 1))
    t = int((1 - 2 * delta) * m) if t is None else t
    logging.info(f"Trying {m = }, {t = }...")
    for x0, y0 in herrmann_may.modular_bivariate(f, e, m, t, X, Y):
        z = int(f(x0, y0))
        if z % e == 0:
            k = pow(x0, -1, e)
            s = (N + 1 + k) % e
            phi = N - s + 1
            factors = known_phi.factorize(N, phi)
            if factors:
                return factors

    return None


def attack_multi_prime(N, e, factor_bit_length, factors, delta=0.25, m=1, t=None):
    """
    Recovers the prime factors if the private exponent is too small.
    This method works for a modulus consisting of any number of primes.
    :param N: the modulus
    :param e: the public exponent
    :param factor_bit_length: the bit length of the prime factors
    :param factors: the number of prime factors in the modulus
    :param delta: a predicted bound on the private exponent (d < n^delta) (default: 0.25)
    :param m: the m value to use for the small roots method (default: 1)
    :param t: the t value to use for the small roots method (default: automatically computed using m)
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    x, y = ZZ["x", "y"].gens()
    A = N + 1
    f = x * (A + y) + 1
    X = int(RR(e) ** delta)
    Y = int(2 ** ((factors - 1) * factor_bit_length + 1))
    t = int((1 - 2 * delta) * m) if t is None else t
    logging.info(f"Trying {m = }, {t = }...")
    for x0, y0 in herrmann_may.modular_bivariate(f, e, m, t, X, Y):
        z = int(f(x0, y0))
        if z % e == 0:
            k = pow(x0, -1, e)
            s = (N + 1 + k) % e
            phi = N - s + 1
            factors = known_phi.factorize_multi_prime(N, phi)
            if factors:
                return factors

    return None


# Some logging so we can see what's happening.
logging.basicConfig(level=logging.DEBUG)

N = 88320836926176610260238895174120738360949322009576866758081671082752401596826820274141832913391890604999466444724537056453777218596634375604879123818123658076245218807184443147162102569631427096787406420042132112746340310992380094474893565028303466135529032341382899333117011402408049370805729286122880037249
e = 36224751658507610673165956970793195381480143363550601971796688201449789736497322700382657163240771111376677180786660893671085854060092736865293791299460933460067267613023891500397200389824179925263846148644777638774319680682025117466596019474987378275216579013846855328009375540444176771945272078755317168511
p_bits = 512
delta = 0.26

p, q = attack(N, e, p_bits, delta=delta, m=3)
assert p * q == N
print(f"Found {p = } and {q = }")
