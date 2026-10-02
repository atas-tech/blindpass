# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util, os, sys, unittest, tomllib
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('task',Path(__file__).with_name('ai-client-task.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class TaskTests(unittest.TestCase):
 def test_codex_mcp_overrides_are_actual_toml_maps_arrays_and_scalars(self):
  with patch.dict(os.environ,{'BLINDPASS_FLEET_SSH_KEY':'/tmp/p05-test-disposable','BLINDPASS_P05_HELPER_SSH_PORT':'22227'},clear=True):
   transport=module.mcp_transport('codex')
  args=module.codex_mcp_overrides(transport,['browser_navigate','browser_snapshot'])
  settings=tomllib.loads('\n'.join(args[i+1] for i in range(0,len(args),2)))['mcp_servers']['p05']
  self.assertEqual(settings['command'],sys.executable)
  self.assertEqual(settings['args'],transport['args']);self.assertEqual(settings['env'],transport['env'])
  self.assertEqual(settings['enabled_tools'],['browser_navigate','browser_snapshot'])
  self.assertEqual(settings['startup_timeout_sec'],15)
  self.assertEqual(settings['default_tools_approval_mode'],'approve')
  with self.assertRaisesRegex(ValueError,'client_transport_failed'):
   module.codex_mcp_overrides({**transport,'env':{**transport['env'],'PRIVATE_EXTRA':'DUMMY'}},[])
 def test_guest_preparation_retry_and_deadline_do_not_consume_client_task_budget(self):
  clock=[0];calls=[]
  def sleep(seconds):clock[0]+=seconds
  def query(*args,**kwargs):
   calls.append(kwargs['timeout'])
   if len(calls)==1:raise module.subprocess.TimeoutExpired('dummy',8)
   if len(calls)==2:return SimpleNamespace(returncode=1,stdout=b'')
   return SimpleNamespace(returncode=0,stdout=b'{"origin":"https://approved.invalid","ready":true,"reportPath":"/report"}')
  with patch.dict(os.environ,{'BLINDPASS_FLEET_SSH_KEY':'/tmp/p05-test-disposable'},clear=True):
   info=module.wait_for_guest_info('codex',deadline_seconds=6,monotonic=lambda:clock[0],sleep=sleep,run=query)
   self.assertEqual(info['reportPath'],'/report');self.assertEqual(calls,[8,8,8])
   with self.assertRaisesRegex(ValueError,'client_guest_not_ready'):
    module.wait_for_guest_info('codex',deadline_seconds=2,monotonic=lambda:clock[0],sleep=sleep,
     run=lambda *args,**kwargs:SimpleNamespace(returncode=1,stdout=b''))
  self.assertEqual(clock[0],6)
 def test_guest_preparation_rejects_dead_process_invalid_info_and_unbounded_wait(self):
  with patch.dict(os.environ,{'BLINDPASS_FLEET_SSH_KEY':'/tmp/p05-test-disposable','BLINDPASS_P05_GUEST_PID':'999999999'},clear=True):
   with self.assertRaisesRegex(ValueError,'client_guest_not_ready'):module.wait_for_guest_info('codex')
  with patch.dict(os.environ,{'BLINDPASS_FLEET_SSH_KEY':'/tmp/p05-test-disposable'},clear=True):
   with self.assertRaisesRegex(ValueError,'client_task_failed'):
    module.wait_for_guest_info('codex',run=lambda *args,**kwargs:SimpleNamespace(returncode=0,stdout=b'{"ready":false}'))
  with self.assertRaisesRegex(ValueError,'client_guest_not_ready'):module.wait_for_guest_info('codex',deadline_seconds=601)
 def test_codex_profile_disables_host_shell_and_unrelated_integrations(self):
  args=module.codex_arguments()
  for name in ['shell_tool','unified_exec','shell_snapshot','multi_agent','apps','remote_plugin','hooks']:
   self.assertIn(['--disable',name], [args[i:i+2] for i in range(len(args)-1)])
  self.assertIn(['--sandbox','read-only'],[args[i:i+2] for i in range(len(args)-1)])
  self.assertIn('web_search="disabled"',args)
  self.assertIn('--ignore-user-config',args);self.assertIn('--ignore-rules',args)
 def test_transport_uses_direct_python_and_explicit_disposable_context_only(self):
  with patch.dict(os.environ,{'BLINDPASS_FLEET_SSH_KEY':'/tmp/p05-test-disposable','BLINDPASS_P05_HELPER_SSH_PORT':'22227','UNRELATED_AUTH':'PRIVATE-DUMMY'},clear=True):
   value=module.mcp_transport('claude')
   self.assertEqual(value['command'],sys.executable)
   self.assertEqual(value['args'][-1],'claude')
   self.assertEqual(set(value['env']),{'BLINDPASS_FLEET_SSH_KEY','BLINDPASS_P05_HELPER_SSH_PORT'})
   self.assertNotIn('PRIVATE-DUMMY',str(value))
 def test_capture_timeout_and_output_bound(self):
  code,output,sizes,timed,over=module.bounded_run([sys.executable,'-c','import time;time.sleep(5)'],Path('/tmp'),0.1)
  self.assertTrue(timed);self.assertFalse(over);self.assertNotEqual(code,0)
  code,output,sizes,timed,over=module.bounded_run([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*3000000)'],Path('/tmp'),5)
  self.assertTrue(over);self.assertLessEqual(sum(map(len,output)),2*1024*1024)
if __name__=='__main__':unittest.main()
