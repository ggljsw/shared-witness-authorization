from __future__ import annotations

import hashlib
import random
from functools import lru_cache

from chia_rs import G1Element, G2Element
from py_ecc.bls.hash_to_curve import hash_to_G1 as py_hash_to_G1
from py_ecc.bls.point_compression import compress_G1

P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
G1 = G1Element.generator()
G2 = G2Element.generator()
GT_ONE = G1Element().pair(G2)
Z = G1.pair(G2)
H1_DST = b"FH-CP-ABE-ATTRIBUTE-H1-G1-V1"


def inv(value: int) -> int:
    value %= P
    if value == 0:
        raise ZeroDivisionError("nonzero scalar denominator required")
    return pow(value, P - 2, P)


def scalar(rng: random.Random) -> int:
    return rng.randrange(1, P)


def eval_poly(coefficients: list[int], x: int) -> int:
    out = 0
    for coefficient in reversed(coefficients):
        out = (out * x + coefficient) % P
    return out


def lagrange(index: int, indices: list[int]) -> int:
    out = 1
    for other in indices:
        if other != index:
            out = out * (-other) * inv(index - other) % P
    return out


def mul_point(point, exponent: int):
    exponent %= P
    result = type(point)()
    addend = point
    while exponent:
        if exponent & 1:
            result = result + addend
        addend = addend + addend
        exponent >>= 1
    return result


def gt_pow(value, exponent: int):
    exponent %= P
    result = GT_ONE
    factor = value
    while exponent:
        if exponent & 1:
            result = result * factor
        factor = factor * factor
        exponent >>= 1
    return result


def gt_inv(value):
    return gt_pow(value, P - 1)


@lru_cache(maxsize=None)
def hash_to_g1(attribute: str) -> G1Element:
    point = py_hash_to_G1(attribute.encode("utf-8"), H1_DST, hashlib.sha256)
    encoded = int(compress_G1(point)).to_bytes(48, "big")
    return G1Element.from_bytes(encoded)


def same_point(left, right) -> bool:
    return bytes(left) == bytes(right)
