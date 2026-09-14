"""Pure-Python Ed25519 (RFC 8032) - dependency-free reference implementation.

Same scheme as ``sneppx-alg``'s ``SNEPPX_ed25519_*`` API and
``sneppx-shield`` so artifacts signed by one product verify in another.
Not constant-time - use a compiled backend for performance-critical flows.
"""

import hashlib
import os

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P

_Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_B = (_Bx, _By)

_IDENTITY = None


def _inv(x):
    return pow(x % _P, _P - 2, _P)


def _sqrt(a):
    a = a % _P
    r = pow(a, (_P + 3) // 8, _P)
    if pow(r, 2, _P) == a:
        return r
    r = r * pow(2, (_P - 1) // 4, _P) % _P
    if pow(r, 2, _P) != a:
        raise ValueError("not a square")
    return r


def _on_curve(P):
    if P is None:
        return True
    x, y = P
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    denom_x = (1 + _D * x1 * x2 * y1 * y2) % _P
    denom_y = (1 - _D * x1 * x2 * y1 * y2) % _P
    x3 = (x1 * y2 + y1 * x2) * _inv(denom_x) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(denom_y) % _P
    return (x3, y3)


def _scalarmult(P, n):
    R = _IDENTITY
    while n > 0:
        if n & 1:
            R = _add(R, P)
        P = _add(P, P)
        n >>= 1
    return R


def _point_decompress(encoded):
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _sqrt((y * y - 1) * _inv(_D * y * y + 1))
    if (x & 1) != sign:
        x = _P - x
    return (x, y)


def _point_compress(P):
    x, y = P
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _clamp(scalar):
    scalar = bytearray(scalar)
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64
    return int.from_bytes(bytes(scalar), "little")


def _hash_mod_l(*parts):
    h = hashlib.sha512(b"".join(parts)).digest()
    return int.from_bytes(h, "little") % _L


def keypair(seed=None):
    """Return ``(pk, sk)`` - 32-byte public key, 64-byte secret key (RFC 8032)."""
    if seed is None:
        seed = os.urandom(32)
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a = _clamp(hashlib.sha512(seed).digest()[:32])
    A = _scalarmult(_B, a)
    pk = _point_compress(A)
    sk = bytes(seed) + pk
    return pk, sk


def publickey_from_seed(seed):
    return keypair(seed)[0]


def sign(sk, msg):
    """Sign ``msg`` with a 64-byte RFC 8032 secret key; returns 64-byte sig."""
    if len(sk) != 64:
        raise ValueError("secret key must be 64 bytes (seed || public key)")
    seed = sk[:32]
    pk = sk[32:]
    h = hashlib.sha512(seed).digest()
    a = _clamp(h[:32])
    prefix = h[32:]
    r = _hash_mod_l(prefix, msg)
    R = _point_compress(_scalarmult(_B, r))
    hram = _hash_mod_l(R, pk, msg)
    S = (r + hram * a) % _L
    return R + S.to_bytes(32, "little")


def verify(pk, msg, sig):
    """Return ``True`` iff ``sig`` is a valid Ed25519 signature of ``msg``."""
    if len(pk) != 32 or len(sig) != 64:
        return False
    try:
        A = _point_decompress(pk)
    except ValueError:
        return False
    if not _on_curve(A) or A is None:
        return False
    try:
        R = _point_decompress(sig[:32])
    except ValueError:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _L:
        return False
    hram = _hash_mod_l(sig[:32], pk, msg)
    lhs = _scalarmult(_B, S)
    rhs = _add(R, _scalarmult(A, hram))
    if lhs is None or rhs is None:
        return False
    return _point_compress(lhs) == _point_compress(rhs)