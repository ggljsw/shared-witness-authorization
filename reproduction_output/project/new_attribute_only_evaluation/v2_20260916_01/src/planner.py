from __future__ import annotations

from dataclasses import dataclass, field
from math import inf

from .access_tree import AccessTree


@dataclass
class Witness:
    leaves: set[int] = field(default_factory=set)
    internals: set[int] = field(default_factory=set)
    selected: dict[int, tuple[int, ...]] = field(default_factory=dict)

    def merge(self, other: "Witness") -> None:
        self.leaves |= other.leaves
        self.internals |= other.internals
        for node_id, children in other.selected.items():
            prior = self.selected.get(node_id)
            if prior is not None and prior != children:
                raise ValueError("inconsistent deterministic witness choices")
            self.selected[node_id] = children


def minimum_witness(tree: AccessTree, root: int, valid: set[int]) -> Witness | None:
    memo: dict[int, tuple[float, Witness | None]] = {}

    def visit(node_id: int) -> tuple[float, Witness | None]:
        if node_id in memo:
            return memo[node_id]
        node = tree.nodes[node_id]
        if node.is_leaf:
            answer = (1.0, Witness(leaves={node_id})) if node_id in valid else (inf, None)
            memo[node_id] = answer
            return answer
        candidates = []
        for child in node.children:
            cost, witness = visit(child)
            if witness is not None:
                candidates.append((cost, child, witness))
        candidates.sort(key=lambda item: (item[0], item[1]))
        if len(candidates) < node.threshold:
            memo[node_id] = (inf, None)
            return memo[node_id]
        chosen = candidates[:node.threshold]
        result = Witness(internals={node_id}, selected={node_id: tuple(x[1] for x in chosen)})
        for _, _, witness in chosen:
            result.merge(witness)
        memo[node_id] = (sum(x[0] for x in chosen), result)
        return memo[node_id]

    return visit(root)[1]


def union_witness(tree: AccessTree, targets: set[int], valid: set[int]) -> tuple[Witness, set[int], list[Witness]]:
    combined = Witness()
    authorized = set()
    per_target = []
    for target in sorted(targets):
        witness = minimum_witness(tree, target, valid)
        if witness is not None:
            combined.merge(witness)
            authorized.add(target)
            per_target.append(witness)
    return combined, authorized, per_target


def cache_key(query_id: str, ciphertext_id: str, tree_id: str, uid: int, attribute: str, cover_node: int,
              epoch: int, tk_id: str, ciphertext_version: int, policy_hash: str) -> tuple:
    return query_id, ciphertext_id, tree_id, uid, attribute, cover_node, epoch, tk_id, ciphertext_version, policy_hash
