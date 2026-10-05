import dataclasses,unittest
from new_attribute_only_evaluation.v2_20260916_01.src.access_tree import synthetic_tree
from new_attribute_only_evaluation.v2_20260916_01.src.backend import *
from new_attribute_only_evaluation.v2_20260916_01.src.execution import execute,recover_all
class V2Tests(unittest.TestCase):
 def test_roles_formula_and_update(self):
  tree=synthetic_tree(10,77);attrs={tree.nodes[n].attribute for n in tree.leaf_ids};ta=TrustedAuthority(attrs,16,77);owner=DataOwnerEncryptor(ta.public,ta.user_tree,78);cloud=CloudService(ta.public,ta.user_tree,79);tk,user=ta.keygen(0,attrs);state,oracle=owner.encrypt(tree)
  self.assertNotIn("alpha_g1",[f.name for f in dataclasses.fields(PublicParameters)]);self.assertNotIn("tau",[f.name for f in dataclasses.fields(CloudTransformationKey)]);self.assertNotIn(user.tau.to_bytes(32,"big"),tk.stable_bytes())
  out=execute("Union11",cloud,state,tk,{tree.root_id}).outputs;keys=recover_all(state,user,out);self.assertEqual(bytes(keys[tree.root_id]),bytes(oracle.file_keys[tree.root_id]))
  tas=ta.initialize_revocation_state(state);payload,tas2,tao=ta.create_update(state,tas,{sorted(attrs)[0]:{0}});wire=payload.to_bytes();self.assertGreater(len(wire),0);self.assertFalse(hasattr(payload,"eta"));self.assertFalse(hasattr(payload,"delta"));state2,cspo=cloud.apply_serialized_update(state,wire);oracle2=advance_test_oracle(oracle,tao,cspo);self.assertEqual(tas2.masks,tao.new_masks);self.assertTrue(all(bytes(recover_all(state2,user,execute("Union11",cloud,state2,tk,{tree.root_id}).outputs)[n])==bytes(oracle2.file_keys[n]) for n in execute("Union11",cloud,state2,tk,{tree.root_id}).outputs))
if __name__=="__main__":unittest.main()
