import logging
import os
import sys

from sage.all import RR
from sage.all import ZZ
from partial_integer import PartialInteger


path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import known_phi
# from ...shared.small_roots import herrmann_may

from shared.small_roots import herrmann_may


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
    q_lsb = (pow(p_lsb, -1, 2 ** p_lsb_bit_length) * N) % (2 ** p_lsb_bit_length)
    A = ((N >> p_lsb_bit_length) + pow(2, -p_lsb_bit_length, e) * (p_lsb * q_lsb - p_lsb - q_lsb + 1))

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


logging.basicConfig(level=logging.DEBUG)
# ATTACK 1
N = 88320836926176610260238895174120738360949322009576866758081671082752401596826820274141832913391890604999466444724537056453777218596634375604879123818123658076245218807184443147162102569631427096787406420042132112746340310992380094474893565028303466135529032341382899333117011402408049370805729286122880037249
# works perfectly
# doesnt work coz no rootsN=60823785598978114459958581268840513318966595087249212058136830110757174855782546322670721881300832872993349053980109673439422488528872403612648884635771696173053942505491012385767224597916479254890576886218228806352521769900372663349835559871671746484829007579243651088378744266046647219850861135210163285693

# N=68595459708599929960868517951775687813834103965138013705653032565442509729315425676054989085679079110776940478934809139499879095677996642112137738245257357432269999540527573982158030378683779245399842893573854543350926696905566475175828883113125167692239054270685175963423243738674642752068793541640300446949

# e for ATTACK 1 
e = 36224751658507610673165956970793195381480143363550601971796688201449789736497322700382657163240771111376677180786660893671085854060092736865293791299460933460067267613023891500397200389824179925263846148644777638774319680682025117466596019474987378275216579013846855328009375540444176771945272078755317168511
p_bits = 512
delta = 0.26

p, q = attack(N, e, p_bits, delta=delta, m=3)
assert p * q == N
print(f"ATTACK1: Found {p = } and {q = }")

# ATTACK 2 testing
# p = 7429785514579250742801544775265919278101812347596990219952070295565832940068576050760172625797740177649856558303705228580697611655581924559792513787731167
# q = 8956454992912744191779370381876516510424600089358399536385007696509658160926748770877487393045391618009844430934391226063349509549521733003051142111030287
# N = p * q
# phi = (p - 1) * (q - 1)
# d = 223183300830113475659369178959679373721083232456560212434233450629223847114638106475011
# e = pow(d, -1, phi)
# p_bits = 512
# delta = 0.26
# p, q = attack(N, e, p_bits, delta = delta, m=2)
# #         self.assertIsInstance(p_, int)
# #         self.assertIsInstance(q_, int)
# #         self.assertEqual(N, p_ * q_)

# assert p * q == N
# print(f"Found {p = } and {q = }")

# ATTACK 2
p = 7429785514579250742801544775265919278101812347596990219952070295565832940068576050760172625797740177649856558303705228580697611655581924559792513787731167
q = 8956454992912744191779370381876516510424600089358399536385007696509658160926748770877487393045391618009844430934391226063349509549521733003051142111030287
N = p * q
phi = (p - 1) * (q - 1)
d = 223183300830113475659369178959679373721083232456560212434233450629223847114638106475011
e = pow(d, -1, phi)
p_, q_ = attack(N, e, 512, partial_p=PartialInteger.lsb_of(p, 512, 128), delta=0.28, m=1, t=0)
# self.assertIsInstance(p_, int)
# self.assertIsInstance(q_, int)
# self.assertEqual(N, p_ * q_)

assert isinstance(p_, int)
assert isinstance(q_, int) 
assert N == p_ * q_
print(f"ATTACK 2: Found {p_=} and {q_=}")

#ATTACK 3
p = 8325745168193178400972753040703564893084541200047412976661161282688302811539795532035273420999644691751298134426448708785219125098284622056451489331098141
q = 7080360719238751828185760219712847628159086532214243460775078410347307461032019124186884558243018527644736008056891972556933157682087344942706360469169019
r = 8317461401474723268496312721678641458178047856339708030999240370931245730754892293396238744093254583460495063266635764778620495121324799900121222370364617
s = 13199869133047572552535353227205776086152310145389840540109659625854798126285664271625603061537083584881441157707264706431629568363715148727252158453179283
N = p * q * r * s
phi = (p - 1) * (q - 1) * (r - 1) * (s - 1)
d = 49488085514473555048624238840378082040802728458021785503334637098083
e = pow(d, -1, phi)
p_, q_, r_, s_ = attack_multi_prime(N, e, 512, 4, delta=0.1, m=6, t=1)
assert isinstance(p_, int)
assert isinstance(q_, int)
assert isinstance(r_, int)
assert isinstance(s_, int)
assert N == p_ * q_ * r_ * s_
print(f"ATTACK 3: Found {p_=} , {q_=}, {r_=}, {s_=}")

