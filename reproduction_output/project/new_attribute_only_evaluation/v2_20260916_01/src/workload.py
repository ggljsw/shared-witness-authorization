from __future__ import annotations

import random

from .access_tree import AccessTree


def choose_targets(tree: AccessTree, count: int, layout: str, rng: random.Random) -> set[int]:
    ids = list(tree.internal_ids)
    root_children = [x for x in tree.nodes[tree.root_id].children if not tree.nodes[x].is_leaf]
    if layout == "Same-Branch":
        branch = rng.choice(root_children) if root_children else tree.root_id
        selected = []
        pool = [x for x in ids if tree.top_branch(x) == branch]
        rng.shuffle(pool)
        selected.extend(pool[:count])
    elif layout == "Disjoint-Branches":
        selected = []
        buckets = [[x for x in ids if tree.top_branch(x) == branch] for branch in root_children[:4]]
        while len(selected) < count and any(buckets):
            for bucket in buckets:
                if bucket and len(selected) < count:
                    value = rng.choice(bucket); bucket.remove(value); selected.append(value)
    else:
        raise ValueError(layout)
    if len(selected) < count:
        fallback = [x for x in ids if x not in selected]
        selected.extend(rng.sample(fallback, count - len(selected)))
    return set(selected)
