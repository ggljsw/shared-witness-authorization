from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass


@dataclass(frozen=True)
class Node:
    node_id: int
    parent: int | None
    child_index: int
    threshold: int
    children: tuple[int, ...]
    attribute: str | None = None

    @property
    def is_leaf(self) -> bool:
        return self.attribute is not None


@dataclass(frozen=True)
class AccessTree:
    tree_id: str
    root_id: int
    nodes: dict[int, Node]

    @property
    def internal_ids(self) -> tuple[int, ...]:
        return tuple(i for i, node in self.nodes.items() if not node.is_leaf)

    @property
    def leaf_ids(self) -> tuple[int, ...]:
        return tuple(i for i, node in self.nodes.items() if node.is_leaf)

    def depth(self, node_id: int) -> int:
        depth = 0
        node = self.nodes[node_id]
        while node.parent is not None:
            depth += 1
            node = self.nodes[node.parent]
        return depth

    def top_branch(self, node_id: int) -> int:
        node = self.nodes[node_id]
        while node.parent not in (None, self.root_id):
            node = self.nodes[node.parent]
        return node.node_id

    def digest(self) -> str:
        rows = [node.__dict__ for _, node in sorted(self.nodes.items())]
        return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def synthetic_tree(internal_count: int, seed: int, fanout: int = 4) -> AccessTree:
    if internal_count < 1:
        raise ValueError("internal_count must be positive")
    rng = random.Random(seed)
    children = {i: [] for i in range(internal_count)}
    parent: dict[int, int | None] = {0: None}
    child_index = {0: 0}
    for i in range(1, internal_count):
        p = (i - 1) // fanout
        children[p].append(i)
        parent[i] = p
        child_index[i] = len(children[p])
    next_id = internal_count
    nodes: dict[int, Node] = {}
    vocabulary = [f"att-{i}" for i in range(32)]
    for i in range(internal_count - 1, -1, -1):
        leaf_id = next_id
        next_id += 1
        attribute = vocabulary[(i * 7 + rng.randrange(4)) % len(vocabulary)]
        nodes[leaf_id] = Node(leaf_id, i, len(children[i]) + 1, 0, (), attribute)
        all_children = tuple(children[i] + [leaf_id])
        nodes[i] = Node(i, parent[i], child_index[i], min(2, len(all_children)), all_children)
    return AccessTree(f"paper-synthetic-{internal_count}-{seed}", 0, nodes)


def threshold_tree(threshold: int, attributes: tuple[str, ...], tree_id: str = "threshold") -> AccessTree:
    children = tuple(range(1, len(attributes) + 1))
    nodes = {0: Node(0, None, 0, threshold, children)}
    nodes.update({i: Node(i, 0, i, 0, (), attribute) for i, attribute in enumerate(attributes, 1)})
    return AccessTree(tree_id, 0, nodes)
