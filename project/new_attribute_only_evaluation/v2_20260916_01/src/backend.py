from __future__ import annotations

import hashlib
import random
import struct
from dataclasses import dataclass

from chia_rs import G1Element, G2Element

from . import SCHEMA_VERSION
from .access_tree import AccessTree
from .algebra import G1, G2, P, Z, eval_poly, gt_pow, hash_to_g1, inv, mul_point, scalar
from .user_tree import UserTree

CIPHERTEXT_VERSION = 2
H2_DST = b"FH-CP-ABE-RHO-H2-FPSTAR-V2"
UPDATE_MAGIC = b"FHABE-UPD-V2\0"
GTElement = type(Z)


def h2_to_nonzero_scalar(point: G1Element) -> int:
    encoded = bytes(point)
    digest = hashlib.sha256(H2_DST + len(encoded).to_bytes(2, "big") + encoded).digest()
    return int.from_bytes(digest, "big") % (P - 1) + 1


@dataclass(frozen=True)
class PublicParameters:
    f1: G2Element
    f2: G2Element
    z_alpha: GTElement
    g1_theta: G1Element
    attribute_B: dict[str, G1Element]

    def stable_bytes(self) -> bytes:
        out = [b"PPV2", bytes(self.f1), bytes(self.f2), bytes(self.z_alpha), bytes(self.g1_theta)]
        for attribute, point in sorted(self.attribute_B.items()):
            name = attribute.encode("utf-8")
            out += [len(name).to_bytes(2, "big"), name, bytes(point)]
        return b"".join(out)


@dataclass(frozen=True)
class TAMasterSecret:
    alpha: int
    beta1: int
    beta2: int
    theta: int
    attribute_t: dict[str, int]
    node_v: dict[int, int]


@dataclass(frozen=True)
class AttributeKey:
    K: G1Element
    L: G2Element
    E: dict[int, G2Element]


@dataclass(frozen=True)
class CloudTransformationKey:
    uid: int
    tk_id: str
    D1: G1Element
    D2: G1Element
    attributes: dict[str, AttributeKey]

    def stable_bytes(self) -> bytes:
        out = [b"TKV2", self.uid.to_bytes(4, "big"), bytes(self.D1), bytes(self.D2)]
        for attribute, key in sorted(self.attributes.items()):
            name = attribute.encode("utf-8")
            out += [len(name).to_bytes(2, "big"), name, bytes(key.K), bytes(key.L)]
            for node, value in sorted(key.E.items()):
                out += [node.to_bytes(4, "big"), bytes(value)]
        return b"".join(out)


@dataclass(frozen=True)
class UserPrivateState:
    uid: int
    tau: int
    tk_id: str


@dataclass(frozen=True)
class FileCiphertext:
    C1: GTElement
    C2: G2Element
    C3: G2Element
    C4: G2Element


@dataclass(frozen=True)
class LeafCiphertext:
    attribute: str
    A: G2Element
    B: G1Element


@dataclass(frozen=True)
class CipherState:
    schema: str
    ciphertext_version: int
    ciphertext_id: str
    tree_id: str
    policy_hash: str
    epoch: int
    owner_A: G1Element
    tree: AccessTree
    files: dict[int, FileCiphertext]
    leaves: dict[int, LeafCiphertext]
    headers: dict[str, dict[int, G1Element]]
    covers: dict[str, frozenset[int]]


@dataclass(frozen=True)
class TARevocationState:
    masks: dict[str, int]
    revoked: dict[str, frozenset[int]]


@dataclass(frozen=True)
class TAUpdatePayload:
    tree_id: str
    policy_hash: str
    ciphertext_version: int
    from_epoch: int
    to_epoch: int
    file_eta_factors: dict[int, tuple[GTElement, G2Element, G2Element]]
    leaf_eta_factors: dict[int, tuple[G2Element, G1Element]]
    replacement_headers: dict[str, dict[int, G1Element]]
    replacement_covers: dict[str, frozenset[int]]

    def to_bytes(self) -> bytes:
        out = bytearray(UPDATE_MAGIC)

        def blob(value: bytes) -> None:
            out.extend(struct.pack(">I", len(value)))
            out.extend(value)

        blob(self.tree_id.encode("utf-8"))
        blob(bytes.fromhex(self.policy_hash))
        out.extend(struct.pack(">III", self.ciphertext_version, self.from_epoch, self.to_epoch))
        out.extend(struct.pack(">I", len(self.file_eta_factors)))
        for node, values in sorted(self.file_eta_factors.items()):
            out.extend(struct.pack(">I", node))
            for value in values:
                blob(bytes(value))
        out.extend(struct.pack(">I", len(self.leaf_eta_factors)))
        for node, values in sorted(self.leaf_eta_factors.items()):
            out.extend(struct.pack(">I", node))
            for value in values:
                blob(bytes(value))
        attributes = sorted(self.replacement_headers)
        out.extend(struct.pack(">I", len(attributes)))
        for attribute in attributes:
            blob(attribute.encode("utf-8"))
            cover = sorted(self.replacement_covers[attribute])
            out.extend(struct.pack(">I", len(cover)))
            for node in cover:
                out.extend(struct.pack(">I", node))
            headers = self.replacement_headers[attribute]
            out.extend(struct.pack(">I", len(headers)))
            for node, point in sorted(headers.items()):
                out.extend(struct.pack(">I", node))
                blob(bytes(point))
        return bytes(out)

    @classmethod
    def from_bytes(cls, wire: bytes) -> "TAUpdatePayload":
        if not isinstance(wire, bytes) or not wire.startswith(UPDATE_MAGIC):
            raise ValueError("invalid update magic")
        pos = len(UPDATE_MAGIC)

        def take(size: int) -> bytes:
            nonlocal pos
            if size < 0 or pos + size > len(wire):
                raise ValueError("truncated update")
            value = wire[pos:pos + size]
            pos += size
            return value

        def u32() -> int:
            return struct.unpack(">I", take(4))[0]

        def blob(expected: int | None = None, maximum: int = 1 << 20) -> bytes:
            size = u32()
            if size > maximum or (expected is not None and size != expected):
                raise ValueError("invalid field length")
            return take(size)

        def count() -> int:
            value = u32()
            if value > 1_000_000:
                raise ValueError("unreasonable count")
            return value

        try:
            tree_id = blob(maximum=4096).decode("utf-8")
            policy_hash = blob(expected=32).hex()
            version, from_epoch, to_epoch = u32(), u32(), u32()
            files = {}
            for _ in range(count()):
                node = u32()
                if node in files:
                    raise ValueError("duplicate file node")
                files[node] = (GTElement.from_bytes(blob(expected=576)), G2Element.from_bytes(blob(expected=96)), G2Element.from_bytes(blob(expected=96)))
            leaves = {}
            for _ in range(count()):
                node = u32()
                if node in leaves:
                    raise ValueError("duplicate leaf node")
                leaves[node] = (G2Element.from_bytes(blob(expected=96)), G1Element.from_bytes(blob(expected=48)))
            headers, covers = {}, {}
            for _ in range(count()):
                attribute = blob(maximum=4096).decode("utf-8")
                if attribute in headers:
                    raise ValueError("duplicate attribute")
                cover_values = [u32() for _ in range(count())]
                if len(set(cover_values)) != len(cover_values):
                    raise ValueError("duplicate cover node")
                cover = frozenset(cover_values)
                attr_headers = {}
                for _ in range(count()):
                    node = u32()
                    if node in attr_headers:
                        raise ValueError("duplicate header node")
                    attr_headers[node] = G1Element.from_bytes(blob(expected=48))
                if set(attr_headers) != set(cover):
                    raise ValueError("header/cover mismatch")
                headers[attribute], covers[attribute] = attr_headers, cover
        except (UnicodeDecodeError, ValueError, RuntimeError, struct.error) as exc:
            raise ValueError("invalid update encoding") from exc
        if pos != len(wire):
            raise ValueError("trailing update bytes")
        result = cls(tree_id, policy_hash, version, from_epoch, to_epoch, files, leaves, headers, covers)
        if result.to_bytes() != wire:
            raise ValueError("non-canonical update encoding")
        return result


@dataclass(frozen=True)
class _TAUpdateOracle:
    eta: dict[int, int]
    new_masks: dict[str, int]
    new_revoked: dict[str, frozenset[int]]


@dataclass(frozen=True)
class _CSPUpdateOracle:
    delta: dict[int, int]


@dataclass
class _TestOracleState:
    shares: dict[int, int]
    noises: dict[int, int]
    masks: dict[str, int]
    revoked: dict[str, set[int]]
    file_keys: dict[int, GTElement]


def _share(tree: AccessTree, root: int, rng: random.Random) -> dict[int, int]:
    out = {}
    def visit(node_id: int, constant: int) -> None:
        node = tree.nodes[node_id]; out[node_id] = constant
        if node.is_leaf: return
        coefficients = [constant] + [scalar(rng) for _ in range(node.threshold - 1)]
        for child in node.children: visit(child, eval_poly(coefficients, tree.nodes[child].child_index))
    visit(tree.root_id, root)
    return out


class TrustedAuthority:
    def __init__(self, attributes, users: int = 16, seed: int = 1):
        self.rng = random.Random(seed); self.user_tree = UserTree(users)
        alpha, beta1, beta2, theta = (scalar(self.rng) for _ in range(4))
        attribute_t = {x: scalar(self.rng) for x in sorted(attributes)}
        node_v = {node: scalar(self.rng) for node in range(1, 2 * users)}
        self._ms = TAMasterSecret(alpha, beta1, beta2, theta, attribute_t, node_v)
        self.public = PublicParameters(mul_point(G2, beta1), mul_point(G2, beta2), gt_pow(Z, alpha), mul_point(G1, theta), {x: mul_point(G1, node_v[1] * inv(attribute_t[x])) for x in sorted(attributes)})
        self._hashes = {x: hash_to_g1(x) for x in attributes}

    def keygen(self, uid: int, attributes):
        self.user_tree.path(uid)
        unknown = set(attributes) - set(self._ms.attribute_t)
        if unknown: raise KeyError(f"unknown attributes: {sorted(unknown)}")
        tau, r = scalar(self.rng), scalar(self.rng); keys = {}
        for attribute in sorted(attributes):
            ri = scalar(self.rng)
            keys[attribute] = AttributeKey(mul_point(G1, tau*r) + mul_point(self._hashes[attribute], tau*ri), mul_point(G2, tau*ri), {node: mul_point(G2, tau*self._ms.attribute_t[attribute]*ri*inv(self._ms.node_v[node])) for node in self.user_tree.path(uid)})
        d1 = mul_point(G1, tau*(self._ms.alpha+r)*inv(self._ms.beta1)); d2 = mul_point(G1, tau*r*inv(self._ms.beta2))
        partial = CloudTransformationKey(uid, "", d1, d2, keys); tk_id = hashlib.sha256(partial.stable_bytes()).hexdigest()
        return CloudTransformationKey(uid, tk_id, d1, d2, keys), UserPrivateState(uid, tau, tk_id)

    def initialize_revocation_state(self, state: CipherState) -> TARevocationState:
        rho = h2_to_nonzero_scalar(mul_point(state.owner_A, self._ms.theta))
        return TARevocationState({x: rho for x in self._ms.attribute_t}, {x: frozenset() for x in self._ms.attribute_t})

    def create_update(self, state: CipherState, ta_state: TARevocationState, newly_revoked):
        unknown = set(newly_revoked) - set(self._ms.attribute_t)
        if unknown: raise KeyError(f"unknown attributes: {sorted(unknown)}")
        eta = _share(state.tree, scalar(self.rng), self.rng); masks, revoked, changed = dict(ta_state.masks), dict(ta_state.revoked), set()
        for attribute, users in newly_revoked.items():
            users = set(users); self.user_tree.cover(users)
            merged = frozenset(set(revoked[attribute]) | users)
            if merged != revoked[attribute]:
                changed.add(attribute); new_mask = scalar(self.rng)
                while new_mask == ta_state.masks[attribute]: new_mask = scalar(self.rng)
                masks[attribute] = new_mask
            revoked[attribute] = merged
        covers = {x: self.user_tree.cover(set(revoked[x])) for x in changed}
        file_factors = {node: (gt_pow(self.public.z_alpha, eta[node]), mul_point(G2, eta[node]), mul_point(self.public.f1, eta[node])) for node in state.tree.internal_ids}
        leaf_factors = {}
        for node in state.tree.leaf_ids:
            attribute = state.tree.nodes[node].attribute
            leaf_factors[node] = (mul_point(G2, eta[node]), mul_point(self._hashes[attribute], eta[node]) + mul_point(G1, (masks[attribute]-ta_state.masks[attribute]) % P))
        headers = {attribute: {node: mul_point(G1, masks[attribute]*self._ms.node_v[node]*inv(self._ms.attribute_t[attribute])) for node in covers[attribute]} for attribute in changed}
        payload = TAUpdatePayload(state.tree_id, state.policy_hash, state.ciphertext_version, state.epoch, state.epoch+1, file_factors, leaf_factors, headers, covers)
        return payload, TARevocationState(masks, revoked), _TAUpdateOracle(eta, masks, revoked)


class DataOwnerEncryptor:
    def __init__(self, public: PublicParameters, user_tree: UserTree, seed: int = 1):
        self.public, self.user_tree, self.rng = public, user_tree, random.Random(seed)
    def encrypt(self, tree: AccessTree):
        shares = _share(tree, scalar(self.rng), self.rng); noises = {node: scalar(self.rng) for node in tree.internal_ids}
        rd = scalar(self.rng); owner_A = mul_point(G1, rd); rho = h2_to_nonzero_scalar(mul_point(self.public.g1_theta, rd))
        covers = {x: self.user_tree.cover(set()) for x in self.public.attribute_B}; file_keys = {node: gt_pow(Z, scalar(self.rng)) for node in tree.internal_ids}; files = {}
        for node in tree.internal_ids:
            q = (shares[node]+noises[node]) % P
            files[node] = FileCiphertext(file_keys[node]*gt_pow(self.public.z_alpha,q), mul_point(G2,q), mul_point(self.public.f1,q), mul_point(self.public.f2,noises[node]))
        leaves = {node: LeafCiphertext(tree.nodes[node].attribute, mul_point(G2,shares[node]), mul_point(hash_to_g1(tree.nodes[node].attribute),shares[node])+mul_point(G1,rho)) for node in tree.leaf_ids}
        headers = {x:{1:mul_point(self.public.attribute_B[x],rho)} for x in self.public.attribute_B}
        ciphertext_id = hashlib.sha256(b"CTV2"+tree.digest().encode("ascii")+bytes(owner_A)+b"".join(bytes(files[n].C1) for n in sorted(files))).hexdigest()
        state = CipherState(SCHEMA_VERSION,CIPHERTEXT_VERSION,ciphertext_id,tree.tree_id,tree.digest(),0,owner_A,tree,files,leaves,headers,covers)
        validate_cipher(state)
        return state,_TestOracleState(shares,noises,{x:rho for x in covers},{x:set() for x in covers},file_keys)


class CloudService:
    def __init__(self, public: PublicParameters, user_tree: UserTree, seed: int = 1):
        self.public,self.user_tree,self.rng=public,user_tree,random.Random(seed)
    def apply_serialized_update(self,state:CipherState,wire:bytes):
        return self._apply_decoded_update(state,TAUpdatePayload.from_bytes(wire))
    def _apply_decoded_update(self,state:CipherState,payload:TAUpdatePayload):
        if (payload.tree_id,payload.policy_hash,payload.ciphertext_version,payload.from_epoch,payload.to_epoch)!=(state.tree_id,state.policy_hash,state.ciphertext_version,state.epoch,state.epoch+1): raise ValueError("update binding mismatch")
        if set(payload.file_eta_factors)!=set(state.tree.internal_ids): raise ValueError("file update coverage mismatch")
        if set(payload.leaf_eta_factors)!=set(state.tree.leaf_ids): raise ValueError("leaf update coverage mismatch")
        if set(payload.replacement_headers)!=set(payload.replacement_covers): raise ValueError("replacement mismatch")
        if not set(payload.replacement_headers)<=set(self.public.attribute_B): raise ValueError("unknown replacement attribute")
        for attribute,cover in payload.replacement_covers.items():
            if set(payload.replacement_headers[attribute])!=set(cover): raise ValueError("header/cover mismatch")
            if any(node<1 or node>=2*self.user_tree.users for node in cover): raise ValueError("invalid cover node")
        delta={node:scalar(self.rng) for node in state.tree.internal_ids};files={}
        for node,old in state.files.items():
            za,g2_eta,f1_eta=payload.file_eta_factors[node]
            files[node]=FileCiphertext(old.C1*za*gt_pow(self.public.z_alpha,delta[node]),old.C2+g2_eta+mul_point(G2,delta[node]),old.C3+f1_eta+mul_point(self.public.f1,delta[node]),old.C4+mul_point(self.public.f2,delta[node]))
        leaves={node:LeafCiphertext(old.attribute,old.A+payload.leaf_eta_factors[node][0],old.B+payload.leaf_eta_factors[node][1]) for node,old in state.leaves.items()}
        headers,covers=dict(state.headers),dict(state.covers)
        for attribute in payload.replacement_headers: headers[attribute],covers[attribute]=payload.replacement_headers[attribute],payload.replacement_covers[attribute]
        result=CipherState(state.schema,state.ciphertext_version,state.ciphertext_id,state.tree_id,state.policy_hash,payload.to_epoch,state.owner_A,state.tree,files,leaves,headers,covers)
        validate_cipher(result);return result,_CSPUpdateOracle(delta)
    def cover_node(self,state,tk,attribute): return None if attribute not in tk.attributes else self.user_tree.matching(tk.uid,state.covers[attribute])
    def valid_leaves(self,state,tk): return {node for node,leaf in state.leaves.items() if self.cover_node(state,tk,leaf.attribute) is not None}


def recover_file_key(state,user,node,transformed): return state.files[node].C1*gt_pow(transformed,-inv(user.tau))


def validate_cipher(state):
    if state.schema!=SCHEMA_VERSION or state.ciphertext_version!=CIPHERTEXT_VERSION: raise ValueError("schema/version")
    if state.tree.digest()!=state.policy_hash or not state.ciphertext_id: raise ValueError("cipher binding")
    if set(state.files)!=set(state.tree.internal_ids) or set(state.leaves)!=set(state.tree.leaf_ids): raise ValueError("tree coverage")
    if set(state.headers)!=set(state.covers): raise ValueError("header coverage")
    if not isinstance(state.owner_A,G1Element): raise TypeError("owner A group")
    for value in state.files.values():
        if not isinstance(value.C1,GTElement) or not all(isinstance(x,G2Element) for x in (value.C2,value.C3,value.C4)): raise TypeError("file groups")
    for value in state.leaves.values():
        if not isinstance(value.A,G2Element) or not isinstance(value.B,G1Element): raise TypeError("leaf groups")
    for attribute,headers in state.headers.items():
        if set(headers)!=set(state.covers[attribute]) or not all(isinstance(x,G1Element) for x in headers.values()): raise TypeError("header groups")


def advance_test_oracle(oracle,ta_update,csp_update):
    return _TestOracleState({n:(oracle.shares[n]+ta_update.eta[n])%P for n in oracle.shares},{n:(oracle.noises[n]+csp_update.delta[n])%P for n in oracle.noises},dict(ta_update.new_masks),{x:set(v) for x,v in ta_update.new_revoked.items()},dict(oracle.file_keys))


def rematerialize_for_test(state,ta,oracle):
    """Independent test oracle; never passed to the cloud update interface."""
    files={}
    for node in state.tree.internal_ids:
        q=(oracle.shares[node]+oracle.noises[node])%P
        files[node]=FileCiphertext(oracle.file_keys[node]*gt_pow(ta.public.z_alpha,q),mul_point(G2,q),mul_point(ta.public.f1,q),mul_point(ta.public.f2,oracle.noises[node]))
    leaves={node:LeafCiphertext(state.tree.nodes[node].attribute,mul_point(G2,oracle.shares[node]),mul_point(hash_to_g1(state.tree.nodes[node].attribute),oracle.shares[node])+mul_point(G1,oracle.masks[state.tree.nodes[node].attribute])) for node in state.tree.leaf_ids}
    covers={x:ta.user_tree.cover(set(oracle.revoked[x])) for x in oracle.masks}
    headers={x:{node:mul_point(G1,oracle.masks[x]*ta._ms.node_v[node]*inv(ta._ms.attribute_t[x])) for node in covers[x]} for x in oracle.masks}
    result=CipherState(state.schema,state.ciphertext_version,state.ciphertext_id,state.tree_id,state.policy_hash,state.epoch,state.owner_A,state.tree,files,leaves,headers,covers)
    validate_cipher(result);return result


def cipher_material_bytes(state):
    out=[bytes(state.owner_A)]
    for node in sorted(state.files):
        value=state.files[node];out += [bytes(value.C1),bytes(value.C2),bytes(value.C3),bytes(value.C4)]
    for node in sorted(state.leaves):
        value=state.leaves[node];out += [bytes(value.A),bytes(value.B)]
    for attribute in sorted(state.headers):
        for node in sorted(state.headers[attribute]): out.append(bytes(state.headers[attribute][node]))
    return b"".join(out)
