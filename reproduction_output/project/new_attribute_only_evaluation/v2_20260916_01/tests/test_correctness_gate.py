from __future__ import annotations

import dataclasses
import inspect
import unittest

from chia_rs import G1Element, G2Element

from new_attribute_only_evaluation.v2_20260916_01.src.access_tree import AccessTree, Node, synthetic_tree, threshold_tree
from new_attribute_only_evaluation.v2_20260916_01.src.backend import (
    CloudService, CloudTransformationKey, DataOwnerEncryptor, PublicParameters, TAUpdatePayload,
    TrustedAuthority, UserPrivateState, advance_test_oracle, cipher_material_bytes,
    rematerialize_for_test,
)
from new_attribute_only_evaluation.v2_20260916_01.src.execution import METHODS, execute, recover_all


def nested_tree(tree_id="nested"):
    nodes = {
        0: Node(0, None, 0, 2, (1, 2, 3)),
        1: Node(1, 0, 1, 2, (5, 6, 7)),
        2: Node(2, 0, 2, 1, (8, 9)),
        3: Node(3, 0, 3, 2, (4, 10)),
        4: Node(4, 3, 1, 1, (11, 12)),
        5: Node(5, 1, 1, 0, (), "A"), 6: Node(6, 1, 2, 0, (), "B"),
        7: Node(7, 1, 3, 0, (), "A"), 8: Node(8, 2, 1, 0, (), "C"),
        9: Node(9, 2, 2, 0, (), "D"), 10: Node(10, 3, 2, 0, (), "F"),
        11: Node(11, 4, 1, 0, (), "A"), 12: Node(12, 4, 2, 0, (), "E"),
    }
    return AccessTree(tree_id, 0, nodes)


def oracle_authorized(tree, candidates, attributes, revoked, uid):
    """Independent recursive threshold evaluator; it does not import planner code."""
    memo = {}
    def satisfies(node_id):
        if node_id in memo: return memo[node_id]
        node = tree.nodes[node_id]
        if node.is_leaf:
            answer = node.attribute in attributes and uid not in revoked.get(node.attribute, set())
        else:
            answer = sum(satisfies(child) for child in node.children) >= node.threshold
        memo[node_id] = answer
        return answer
    return {node for node in candidates if satisfies(node)}


class CorrectnessGateTests(unittest.TestCase):
    def fixture(self, tree, user_attributes, uid=0, seed=100):
        all_attributes = {tree.nodes[n].attribute for n in tree.leaf_ids}
        ta = TrustedAuthority(all_attributes, users=8, seed=seed)
        owner = DataOwnerEncryptor(ta.public, ta.user_tree, seed+1)
        cloud = CloudService(ta.public, ta.user_tree, seed+2)
        tk, user = ta.keygen(uid, user_attributes)
        state, oracle = owner.encrypt(tree)
        return ta, owner, cloud, tk, user, state, oracle

    def assert_methods_match_oracle(self, cloud, tk, user, state, oracle, attributes, revoked, candidates):
        expected = oracle_authorized(state.tree, set(candidates), set(attributes), revoked, tk.uid)
        for method in METHODS:
            result = execute(method, cloud, state, tk, candidates)
            self.assertEqual(set(result.outputs), expected, method)
            recovered = recover_all(state, user, result.outputs)
            self.assertEqual(set(recovered), expected, method)
            for node, key in recovered.items(): self.assertEqual(bytes(key), bytes(oracle.file_keys[node]), (method, node))

    def test_complete_authorization_set_matrix(self):
        tree = nested_tree(); candidates = set(tree.internal_ids)
        cases = [
            ("all", {"A","B","C","D","E","F"}, candidates),
            ("partial", {"A","B"}, candidates), ("none", set(), candidates),
            ("empty", {"A","B","C"}, set()), ("mixed", {"C","F"}, {0,1,2,4}),
            ("repeated-attribute", {"A","F"}, candidates),
        ]
        for index, (_, attributes, selected) in enumerate(cases):
            with self.subTest(case=index):
                ta, owner, cloud, tk, user, state, oracle = self.fixture(tree, attributes, seed=200+index)
                self.assert_methods_match_oracle(cloud, tk, user, state, oracle, attributes, {}, selected)
        for layout_seed in (301, 302):
            tree = synthetic_tree(12, layout_seed)
            attrs = {tree.nodes[n].attribute for n in tree.leaf_ids}
            ta, owner, cloud, tk, user, state, oracle = self.fixture(tree, attrs, seed=layout_seed)
            self.assert_methods_match_oracle(cloud, tk, user, state, oracle, attrs, {}, set(tree.internal_ids))

    def test_revocation_reject_alternative_and_control_user(self):
        tree = threshold_tree(1, ("A", "B"), "alternative")
        ta = TrustedAuthority({"A","B"}, users=8, seed=401); owner = DataOwnerEncryptor(ta.public, ta.user_tree, 402); cloud = CloudService(ta.public, ta.user_tree, 403)
        tk0, user0 = ta.keygen(0, {"A"}); tk1, user1 = ta.keygen(1, {"A"}); tk_alt, user_alt = ta.keygen(2, {"A","B"}); state, oracle = owner.encrypt(tree); ta_state = ta.initialize_revocation_state(state)
        payload, ta_state, tao = ta.create_update(state, ta_state, {"A": {0,2}}); state, cspo = cloud.apply_serialized_update(state, payload.to_bytes()); oracle = advance_test_oracle(oracle, tao, cspo)
        self.assert_methods_match_oracle(cloud, tk0, user0, state, oracle, {"A"}, {"A":{0,2}}, {0})
        self.assert_methods_match_oracle(cloud, tk_alt, user_alt, state, oracle, {"A","B"}, {"A":{0,2}}, {0})
        self.assert_methods_match_oracle(cloud, tk1, user1, state, oracle, {"A"}, {"A":{0,2}}, {0})

    def test_cumulative_revocation_and_independent_rematerialization(self):
        tree = nested_tree("cumulative"); attrs = {tree.nodes[n].attribute for n in tree.leaf_ids}
        ta, owner, cloud, tk0, user0, state, oracle = self.fixture(tree, attrs, uid=0, seed=501)
        tk1, user1 = ta.keygen(1, attrs); ta_state = ta.initialize_revocation_state(state)
        events = [({"A":{0}}, "different-attribute"), ({"B":{0}}, "different-user"), ({"A":{1}}, "duplicate"), ({"A":{0}}, "idempotent-repeat")]
        for event, label in events:
            old_masks = dict(ta_state.masks); payload, ta_state, tao = ta.create_update(state, ta_state, event)
            if label == "idempotent-repeat": self.assertEqual(old_masks["A"], ta_state.masks["A"])
            wire = payload.to_bytes(); state, cspo = cloud.apply_serialized_update(state, wire); oracle = advance_test_oracle(oracle, tao, cspo)
            rebuilt = rematerialize_for_test(state, ta, oracle)
            self.assertEqual(cipher_material_bytes(state), cipher_material_bytes(rebuilt), label)
            for tk, user, uid in ((tk0,user0,0),(tk1,user1,1)):
                self.assert_methods_match_oracle(cloud, tk, user, state, oracle, attrs, oracle.revoked, set(tree.internal_ids))

    def test_cache_scope_actual_stale_entry_injection(self):
        tree = nested_tree("cache"); attrs = {tree.nodes[n].attribute for n in tree.leaf_ids}
        ta, owner, cloud, tk0, user0, state, oracle = self.fixture(tree, attrs, seed=601)
        first = execute("Union11", cloud, state, tk0, {0,1,2}); self.assertTrue(first.cache_snapshot)
        # A new query with the old cache cannot hit because query_id is part of the binding.
        again = execute("Union11", cloud, state, tk0, {0,1,2}, stale_cache=first.cache_snapshot); self.assertEqual(again.counts.header_cache_hits, 0)
        tk1, user1 = ta.keygen(1, attrs); other_user = execute("Union11", cloud, state, tk1, {0}, stale_cache=first.cache_snapshot); self.assertEqual(other_user.counts.header_cache_hits, 0)
        tk0b, user0b = ta.keygen(0, attrs); other_key = execute("Union11", cloud, state, tk0b, {0}, stale_cache=first.cache_snapshot); self.assertEqual(other_key.counts.header_cache_hits, 0)
        state_b, oracle_b = DataOwnerEncryptor(ta.public, ta.user_tree, 999).encrypt(tree); other_cipher = execute("Union11", cloud, state_b, tk0, {0}, stale_cache=first.cache_snapshot); self.assertEqual(other_cipher.counts.header_cache_hits, 0)
        ta_state = ta.initialize_revocation_state(state); payload, ta_state, tao = ta.create_update(state, ta_state, {"A":{7}}); state2, cspo = cloud.apply_serialized_update(state, payload.to_bytes())
        other_epoch = execute("Union11", cloud, state2, tk0, {0}, stale_cache=first.cache_snapshot); self.assertEqual(other_epoch.counts.header_cache_hits, 0)
        for result, user, expected_oracle in ((again,user0,oracle),(other_user,user1,oracle),(other_key,user0b,oracle),(other_cipher,user0,oracle_b)):
            for node,key in recover_all(state_b if result is other_cipher else state, user, result.outputs).items(): self.assertEqual(bytes(key),bytes(expected_oracle.file_keys[node]))

    def test_update_serialization_roundtrip_and_rejection(self):
        tree = nested_tree("serialization"); attrs = {tree.nodes[n].attribute for n in tree.leaf_ids}
        ta, owner, cloud, tk, user, state, oracle = self.fixture(tree, attrs, seed=701); ta_state = ta.initialize_revocation_state(state)
        payload, _, _ = ta.create_update(state, ta_state, {"A":{0}}); wire = payload.to_bytes(); decoded = TAUpdatePayload.from_bytes(wire)
        self.assertEqual(decoded.to_bytes(), wire); self.assertGreater(len(wire), 0)
        self.assertTrue(all(isinstance(x[0], type(next(iter(payload.file_eta_factors.values()))[0])) and isinstance(x[1],G2Element) for x in decoded.file_eta_factors.values()))
        self.assertTrue(all(isinstance(x[0],G2Element) and isinstance(x[1],G1Element) for x in decoded.leaf_eta_factors.values()))
        bad_group = bytearray(wire); encoded_g2 = bytes(next(iter(payload.leaf_eta_factors.values()))[0]); prefix = wire.find(encoded_g2)
        self.assertGreater(prefix, 0); bad_group[prefix:prefix+len(encoded_g2)] = b"\xff"*len(encoded_g2)
        for malformed in (wire[:-1], wire+b"x", b"bad"+wire, bytes(bad_group)):
            with self.subTest(size=len(malformed)): self.assertRaises(ValueError, TAUpdatePayload.from_bytes, malformed)
        self.assertNotIn("apply_update", dir(cloud)); self.assertNotIn("oracle", inspect.signature(cloud.apply_serialized_update).parameters)

    def test_role_and_secret_isolation_interfaces(self):
        tree = nested_tree("roles"); attrs = {tree.nodes[n].attribute for n in tree.leaf_ids}; ta = TrustedAuthority(attrs,8,801)
        owner = DataOwnerEncryptor(ta.public,ta.user_tree,802); saved = ta._ms; ta._ms = None
        state, oracle = owner.encrypt(tree); ta._ms = saved
        cloud = CloudService(ta.public,ta.user_tree,803); tk,user = ta.keygen(0,attrs)
        self.assertNotIn("tau", {f.name for f in dataclasses.fields(CloudTransformationKey)})
        self.assertNotIn(user.tau.to_bytes(32,"big"), tk.stable_bytes())
        self.assertNotIn("alpha", {f.name for f in dataclasses.fields(PublicParameters)})
        self.assertEqual(set(inspect.signature(owner.encrypt).parameters), {"tree"})
        self.assertNotIn("user", inspect.signature(execute).parameters)
        self.assertIn("user", inspect.signature(recover_all).parameters)
        self.assertEqual(set(inspect.signature(cloud.apply_serialized_update).parameters), {"state","wire"})
        result = execute("Union11",cloud,state,tk,{0}); self.assertEqual(bytes(recover_all(state,user,result.outputs)[0]),bytes(oracle.file_keys[0]))


if __name__ == "__main__": unittest.main()
