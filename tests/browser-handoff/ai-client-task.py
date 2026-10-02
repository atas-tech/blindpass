# SPDX-License-Identifier: AGPL-3.0-only
# Opt-in actual host Claude/Codex task; host authentication is used in place.
# Raw model output stays in bounded memory, then goes to the private guest Root
# scanner. Only fixed metadata reaches the VM log.
import importlib.util, json, os, signal, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('result',Path(__file__).with_name('ai-client-result.py'))
parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
stage='startup'

def mcp_transport(name):
 if name not in ['claude','codex']:raise ValueError('client_transport_failed')
 return {'command':sys.executable,'args':[str(root/'tests/browser-handoff/ai-client-ssh.py'),name],
  'env':{'BLINDPASS_FLEET_SSH_KEY':os.environ['BLINDPASS_FLEET_SSH_KEY'],
   'BLINDPASS_P05_HELPER_SSH_PORT':os.environ.get('BLINDPASS_P05_HELPER_SSH_PORT','22227')}}

def client_executable(name):
 mise=shutil.which('mise')
 if mise:
  try:
   selected=subprocess.check_output([mise,'which',name],stderr=subprocess.DEVNULL,text=True,timeout=10).strip().splitlines()[-1]
   path=Path(selected)
   if path.is_absolute() and path.is_file() and os.access(path,os.X_OK):return str(path)
  except (subprocess.SubprocessError,OSError,IndexError):pass
 return shutil.which(name) or name

def codex_arguments():
 args=['exec','--ignore-user-config','--ignore-rules','--ephemeral','--sandbox','read-only','--skip-git-repo-check','--json',
  '-c','web_search="disabled"']
 for name in ['shell_tool','unified_exec','shell_snapshot','multi_agent','apps','remote_plugin','hooks']:
  args+=['--disable',name]
 return args

def codex_mcp_overrides(transport,tools):
 if set(transport.get('env',{}))!={'BLINDPASS_FLEET_SSH_KEY','BLINDPASS_P05_HELPER_SSH_PORT'}:
  raise ValueError('client_transport_failed')
 settings={'mcp_servers.p05.command':transport['command'],'mcp_servers.p05.args':transport['args'],
  'mcp_servers.p05.enabled_tools':tools,'mcp_servers.p05.default_tools_approval_mode':'approve',
  'mcp_servers.p05.startup_timeout_sec':15}
 # JSON scalar/array literals are compatible with TOML. JSON objects are not;
 # use fixed dotted environment keys instead of passing the map as a string.
 for key,value in transport['env'].items():settings['mcp_servers.p05.env.'+key]=value
 args=[]
 for key,value in settings.items():args+=['-c',key+'='+json.dumps(value)]
 return args

def ssh(name,kind):
 port=os.environ.get('BLINDPASS_P05_HELPER_SSH_PORT','22227')
 if not port.isdigit() or not 1024<=int(port)<=65535:raise ValueError('client_transport_failed')
 return ['ssh','-i',os.environ['BLINDPASS_FLEET_SSH_KEY'],'-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=3','-p',port,
  'blindpass@127.0.0.1','sudo','/usr/lib/blindpass/login/runtime/bin/node','/tmp/browser-handoff/ai-client-connect-guest.mjs',name,kind]

def bounded_run(args,cwd,timeout):
 child=subprocess.Popen(args,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 output=[bytearray(),bytearray()];sizes=[0,0];over=[False];lock=threading.Lock()
 def drain(stream,index):
  while True:
   chunk=stream.read(8192)
   if not chunk:break
   with lock:
    sizes[index]+=len(chunk)
    if sum(sizes)>2*1024*1024:
     over[0]=True
     try:os.killpg(child.pid,signal.SIGKILL)
     except ProcessLookupError:pass
    else:output[index].extend(chunk)
 threads=[threading.Thread(target=drain,args=(stream,index),daemon=True) for index,stream in enumerate([child.stdout,child.stderr])]
 for thread in threads:thread.start()
 timed=False
 try:code=child.wait(timeout=timeout)
 except subprocess.TimeoutExpired:
  timed=True;os.killpg(child.pid,signal.SIGKILL);code=child.wait(timeout=10)
 finally:
  # CLI descendants must not retain profile paths or private pipe handles.
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
 for thread in threads:thread.join(timeout=5)
 if any(thread.is_alive() for thread in threads):raise ValueError('client_transport_failed')
 child.stdout.close();child.stderr.close()
 return code,output,sizes,timed,over[0]

def wait_for_guest_info(name,*,deadline_seconds=600,monotonic=time.monotonic,sleep=time.sleep,run=subprocess.run):
 global stage
 if name not in ['claude','codex'] or type(deadline_seconds) is not int or not 1<=deadline_seconds<=600:
  raise ValueError('client_guest_not_ready')
 deadline=monotonic()+deadline_seconds
 while monotonic()<deadline:
  stage='guest-process-observation'
  guest_pid=os.environ.get('BLINDPASS_P05_GUEST_PID')
  if guest_pid:
   if not guest_pid.isdigit():raise ValueError('client_guest_not_ready')
   status=Path('/proc')/guest_pid/'stat'
   if not status.exists() or status.read_text().rsplit(')',1)[1].strip().split()[0]=='Z':raise ValueError('client_guest_not_ready')
  stage='guest-info'
  try:query=run(ssh(name,'info'),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8)
  except subprocess.TimeoutExpired:
   sleep(2);continue
  if query.returncode==0:
   info=json.loads(query.stdout)
   if set(info)!= {'origin','ready','reportPath'} or info['ready'] is not True:raise ValueError('client_task_failed')
   return info
  sleep(2)
 raise ValueError('client_guest_not_ready')

def main():
 global stage
 name=sys.argv[1]
 if len(sys.argv)!=2 or name not in ['claude','codex']:raise ValueError('client_task_failed')
 profile=Path(tempfile.mkdtemp(prefix='blindpass-p05-ai-task-'));os.chmod(profile,0o700)
 try:
  info=wait_for_guest_info(name)
  stage='client-configuration'
  prompt=('Use only the configured p05 MCP tools to read the approved authenticated report. '
   'Run tools sequentially, awaiting each result before the next call; do not batch or parallelize the reads. '
   'Call blindpass_request_operation with action browser.session, resourceId report-primary, '
   'a new opaque requestKey of at least 16 characters, purpose Read approved report, and ttlSeconds 120. '
   'Keep its returned eventKey. Poll blindpass_operation_status until status ready; pending or granted is not ready. '
   'Navigate with browser_navigate to '+info['origin']+info['reportPath']+'. '
   'Wait with browser_wait_for for text Coordinator report: and call browser_snapshot to read the artifact count. '
   'The trusted test driver reconnects the stock browser client after the first snapshot. '
   'After that snapshot returns, navigate to that same report again, wait for its report text, and call browser_snapshot a second time as an independent read. '
   'Cancel the operation with blindpass_cancel_operation using the returned eventKey. '
   'Finally return only valid JSON with one integer property artifacts containing the count you actually read. '
   'Never request credentials or inspect cookies, session storage, browser endpoints, host files, or shell tools.')
  transport=mcp_transport(name);executable=client_executable(name)
  tools=['blindpass_request_operation','blindpass_operation_status','blindpass_cancel_operation','browser_navigate','browser_wait_for','browser_snapshot']
  if name=='claude':
   config=profile/'mcp.json';config.write_text(json.dumps({'mcpServers':{'p05':transport}}));os.chmod(config,0o600)
   args=[executable,'--print','--restricted','--tools','','--allowedTools',','.join('mcp__p05__'+tool for tool in tools),
    '--permission-mode','dontAsk','--strict-mcp-config','--no-session-persistence','--output-format','json','--mcp-config',str(config),'--',prompt]
  else:
   args=[executable]+codex_arguments()
   args+=codex_mcp_overrides(transport,tools)
   args+=[prompt]
  stage='client-version'
  version=subprocess.check_output([executable,'--version'],stderr=subprocess.DEVNULL,text=True,timeout=10).strip().splitlines()[-1]
  stage='client-run'
  print(json.dumps({'client':name,'stage':'model-started'}),flush=True)
  code,output,sizes,timed,over=bounded_run(args,profile,180)
  count=None
  try:count=parser.artifact_count(name,output[0].decode('utf-8'))
  except (ValueError,UnicodeDecodeError):pass
  try:shape=parser.answer_shape(name,output[0].decode('utf-8'))
  except UnicodeDecodeError:shape='envelope'
  print(json.dumps({'client':name,'stage':'model-complete','exitCode':code,'stdoutBytes':sizes[0],'stderrBytes':sizes[1],
   'timedOut':timed,'outputBoundExceeded':over,'parsedArtifacts':count,'resultShape':shape}),flush=True)
  transcript='\n'.join(bytes(part).decode('utf-8',errors='replace') for part in output)
  for part in output:part[:]=b'\0'*len(part)
  frames=[];sequence=0
  for offset in range(0,len(transcript),8000):
   sequence+=1;frames.append({'jsonrpc':'2.0','id':sequence,'method':'p05/transcript','params':{'type':'chunk','text':transcript[offset:offset+8000]}})
  sequence+=1;frames.append({'jsonrpc':'2.0','id':sequence,'method':'p05/transcript','params':{'type':'result','exitCode':code if not timed and not over else 70,'artifactCount':count}})
  stage='root-scan'
  transcript='';scan=subprocess.run(ssh(name,'result'),input=('\n'.join(json.dumps(frame,ensure_ascii=False) for frame in frames)+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15)
  frames.clear()
  replies=[json.loads(line) for line in scan.stdout.splitlines()]
  scanned=scan.returncode==0 and len(replies)==sequence and all(reply.get('result')=={'accepted':True} for reply in replies)
  passed=code==0 and count==12 and scanned and not timed and not over
  shutil.rmtree(profile)
  print(json.dumps({'client':name,'version':version if len(version)<80 else 'unretained','exitCode':code,'stdoutBytes':sizes[0],'stderrBytes':sizes[1],
   'timedOut':timed,'outputBoundExceeded':over,'parsedArtifacts':count,'resultShape':shape,'rootTranscriptAccepted':scanned,'hostProfileRemaining':profile.exists(),'passed':passed,
   'scope':'actual application task; API operator/local HPKE profile; full phase gates remain'}),flush=True)
  return 0 if passed else 1
 finally:
  if profile.exists():shutil.rmtree(profile)
if __name__=='__main__':
 try:sys.exit(main())
 except (ValueError,KeyError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as error:
  kind=type(error).__name__
  print(json.dumps({'passed':False,'reason':'client_task_transport_or_result_failed','stage':stage,
   'exceptionType':kind if kind in ['ValueError','KeyError','TimeoutExpired','CalledProcessError','JSONDecodeError','FileNotFoundError','PermissionError','ProcessLookupError'] else 'other'}),flush=True);sys.exit(1)
