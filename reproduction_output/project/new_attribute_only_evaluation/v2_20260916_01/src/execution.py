from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from .algebra import GT_ONE, gt_inv, gt_pow, lagrange
from .backend import CipherState, CloudService, CloudTransformationKey, UserPrivateState, recover_file_key, validate_cipher
from .planner import Witness, cache_key, minimum_witness

METHODS = ("FullTree11", "PT00", "PT01", "Union10", "Union11")


@dataclass
class Counts:
    header_pairings: int = 0
    leaf_specific_pairings: int = 0
    final_pairings: int = 0
    leaf_transforms: int = 0
    internal_interpolations: int = 0
    header_cache_hits: int = 0
    def add(self, other):
        for key in self.__dataclass_fields__: setattr(self, key, getattr(self, key) + getattr(other, key))
    def row(self):
        return {**self.__dict__, "pairings": self.header_pairings + self.leaf_specific_pairings + self.final_pairings}


@dataclass
class Phases:
    planning_ns: int = 0
    header_ns: int = 0
    leaf_ns: int = 0
    interpolation_ns: int = 0
    final_ns: int = 0
    def add(self, other):
        for key in self.__dataclass_fields__: setattr(self, key, getattr(self, key) + getattr(other, key))
    def row_ms(self): return {key[:-3] + "_ms": getattr(self, key) / 1e6 for key in self.__dataclass_fields__}


@dataclass
class Result:
    outputs: dict
    counts: Counts
    metrics: dict
    phases: Phases
    cache_snapshot: dict


class QueryCache:
    def __init__(self, stale_values=None):
        self.query_id = uuid.uuid4().hex
        self.values = dict(stale_values or {})
    def get(self, key): return self.values.get(key)
    def put(self, key, value): self.values[key] = value


def full_plan(tree, valid):
    witness = Witness()
    def visit(node_id):
        node = tree.nodes[node_id]
        if node.is_leaf:
            if node_id in valid: witness.leaves.add(node_id); return True
            return False
        satisfied = [child for child in node.children if visit(child)]
        if len(satisfied) >= node.threshold:
            witness.internals.add(node_id); witness.selected[node_id] = tuple(satisfied); return True
        return False
    visit(tree.root_id)
    return witness


def per_target(tree, targets, valid):
    return {target: witness for target in sorted(targets) if (witness := minimum_witness(tree, target, valid)) is not None}


def merge(witnesses):
    union = Witness()
    for witness in witnesses.values(): union.merge(witness)
    return union


def evaluate(cloud, state, tk, witness, targets, cache):
    values, counts, phases = {}, Counts(), Phases()
    for node in sorted(witness.leaves):
        leaf = state.leaves[node]; cover = cloud.cover_node(state, tk, leaf.attribute); key = tk.attributes[leaf.attribute]
        start = time.perf_counter_ns()
        binding = cache_key(cache.query_id if cache else "no-cache", state.ciphertext_id, state.tree_id, tk.uid, leaf.attribute, cover, state.epoch, tk.tk_id, state.ciphertext_version, state.policy_hash)
        header = cache.get(binding) if cache else None
        if header is None:
            header = state.headers[leaf.attribute][cover].pair(key.E[cover]); counts.header_pairings += 1
            if cache: cache.put(binding, header)
        else: counts.header_cache_hits += 1
        phases.header_ns += time.perf_counter_ns() - start
        start = time.perf_counter_ns(); values[node] = key.K.pair(leaf.A) * header * gt_inv(leaf.B.pair(key.L)); phases.leaf_ns += time.perf_counter_ns() - start
        counts.leaf_specific_pairings += 2; counts.leaf_transforms += 1
    pending = set(witness.internals)
    while pending:
        progress = False
        for node in sorted(tuple(pending), key=state.tree.depth, reverse=True):
            children = witness.selected[node]
            if all(child in values for child in children):
                start = time.perf_counter_ns(); indices = [state.tree.nodes[child].child_index for child in children]; value = GT_ONE
                for child, index in zip(children, indices): value = value * gt_pow(values[child], lagrange(index, indices))
                phases.interpolation_ns += time.perf_counter_ns() - start; values[node] = value; pending.remove(node); counts.internal_interpolations += 1; progress = True
        if not progress: raise ValueError("incomplete witness dependency graph")
    outputs = {}
    for node in sorted(targets):
        if node in values:
            start = time.perf_counter_ns(); ciphertext = state.files[node]
            outputs[node] = tk.D1.pair(ciphertext.C3) * gt_inv(values[node] * tk.D2.pair(ciphertext.C4)); phases.final_ns += time.perf_counter_ns() - start; counts.final_pairings += 2
    return Result(outputs, counts, {}, phases, dict(cache.values) if cache else {})


def execute(method, cloud, state, tk, candidates, collect_metrics=False, stale_cache=None):
    if method not in METHODS: raise ValueError(f"unknown method: {method}")
    validate_cipher(state); targets = set(candidates)
    if not targets <= set(state.tree.internal_ids): raise KeyError("candidate is not a file/internal node")
    cache = QueryCache(stale_cache) if method in {"FullTree11", "PT01", "Union11"} else None
    total, phases, outputs = Counts(), Phases(), {}
    start = time.perf_counter_ns(); valid = cloud.valid_leaves(state, tk)
    if method == "FullTree11":
        witness = full_plan(state.tree, valid); phases.planning_ns += time.perf_counter_ns() - start
        result = evaluate(cloud, state, tk, witness, set(witness.internals), cache); outputs = {n: result.outputs[n] for n in targets if n in result.outputs}; total.add(result.counts); phases.add(result.phases); pt = {}
    else:
        pt = per_target(state.tree, targets, valid)
        if method in {"Union10", "Union11"}: union = merge(pt)
        phases.planning_ns += time.perf_counter_ns() - start
        if method in {"PT00", "PT01"}:
            for node, witness in pt.items():
                result = evaluate(cloud, state, tk, witness, {node}, cache); outputs.update(result.outputs); total.add(result.counts); phases.add(result.phases)
        else:
            result = evaluate(cloud, state, tk, union, set(pt), cache); outputs = result.outputs; total.add(result.counts); phases.add(result.phases)
    metrics = {}
    if collect_metrics and method != "FullTree11":
        denominator = sum(len(w.leaves) + len(w.internals) for w in pt.values()); union = merge(pt); unique = len(union.leaves) + len(union.internals)
        metrics = {"unmerged_witness_nodes": denominator, "union_unique_nodes": unique, "witness_overlap_ratio": 0 if not denominator else 1 - unique / denominator}
    return Result(outputs, total, metrics, phases, dict(cache.values) if cache else {})


def recover_all(state, user, outputs):
    if user.tk_id == "": raise ValueError("unbound user private state")
    return {node: recover_file_key(state, user, node, value) for node, value in outputs.items()}
