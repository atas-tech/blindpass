# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util, json, unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location('result', Path(__file__).with_name('ai-client-result.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ResultTests(unittest.TestCase):
 def test_actual_final_messages_only(self):
  self.assertEqual(module.artifact_count('claude', json.dumps({'type':'result','result':'{"artifacts":12}'})), 12)
  text='\n'.join(json.dumps(event) for event in [
   {'type':'item.completed','item':{'type':'mcp_tool_call','result':{'artifacts':99}}},
   {'type':'item.completed','item':{'type':'agent_message','text':'{"artifacts":12}'}}])
  self.assertEqual(module.artifact_count('codex', text),12)
 def test_arbitrary_output_and_invalid_answers_fail(self):
  for name,text in [('claude','12'),('claude','{"result":"12"}'),('claude','{"type":"result","result":"{\\"artifacts\\":true}"}'),
   ('codex','{"type":"item.completed","item":{"type":"mcp_tool_call","text":"{\\"artifacts\\":12}"}}'),
   ('claude','{"type":"result","result":"{\\"artifacts\\":12,\\"extra\\":1}"}')]:
   with self.assertRaisesRegex(ValueError,'client_result_invalid'):module.artifact_count(name,text)
class ShapeTests(unittest.TestCase):
 def shape(self,answer,name='claude'):
  text=json.dumps({'type':'result','result':answer}) if name=='claude' else json.dumps({'type':'item.completed','item':{'type':'agent_message','text':answer}})
  return module.answer_shape(name,text)
 def test_each_failure_class_has_one_fixed_name_and_never_reflects_content(self):
  self.assertEqual(self.shape('{"artifacts":12}'),'valid')
  self.assertEqual(self.shape('{"artifacts":12}','codex'),'valid')
  self.assertEqual(self.shape('```json\n{"artifacts":12}\n```'),'fenced')
  self.assertEqual(self.shape('The report lists 12 artifacts.'),'not_json')
  self.assertEqual(self.shape(''),'empty')
  self.assertEqual(self.shape('[12]'),'json_not_object')
  self.assertEqual(self.shape('{"count":12}'),'json_keys')
  self.assertEqual(self.shape('{"artifacts":12,"extra":1}'),'json_keys')
  self.assertEqual(self.shape('{"artifacts":"12"}'),'json_value')
  self.assertEqual(self.shape('{"artifacts":-1}'),'json_value')
  for name,text in [('claude','12'),('claude','not json'),('claude','{"type":"error"}'),('claude','{"type":"result","result":7}'),('codex','{}'),('other','{}')]:
   self.assertEqual(module.answer_shape(name,text),'envelope')
  self.assertEqual(module.answer_shape('claude',None),'envelope')
  # The shape of a canary-bearing answer is still only a fixed name.
  self.assertEqual(self.shape('SECRET-CANARY-123 is the answer'),'not_json')
if __name__=='__main__':unittest.main()
