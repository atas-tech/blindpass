# SPDX-License-Identifier: AGPL-3.0-only
# Opt-in real model calls; dummy metadata only, never full workflow acceptance.
from pathlib import Path
import os, subprocess, tempfile, json, shutil, sys
root=Path(__file__).resolve().parents[2]
profile=Path(tempfile.mkdtemp(prefix='blindpass-p05-client-readiness-'))
os.chmod(profile,0o700)
try:
 server=profile/'server.mjs'
 server.write_text('''import { Transform } from 'node:stream';
import { appendFileSync } from 'node:fs';
import { runMcpServerStdio } from __MCP_SERVER_MODULE__;
import { clientProtocolMetadata } from __METADATA_MODULE__;
const trace = process.argv[2]; let pending = ''; let count = 0; let records = 0;
function record(value) { if (++records > 32) return; appendFileSync(trace, JSON.stringify(value)+'\\n', {mode:0o600}); }
const input = new Transform({transform(bytes, encoding, next) {
 pending += bytes.toString();
 if (pending.length > 65536) { next(new Error('input_invalid')); return; }
 while (pending.includes('\\n')) {
  const i = pending.indexOf('\\n'); const line = pending.slice(0,i); pending = pending.slice(i+1);
  try { const metadata = clientProtocolMetadata(JSON.parse(line)); if (metadata) record(metadata); } catch {}
 }
 this.push(bytes); next();
}});
process.stdin.pipe(input);
await runMcpServerStdio({tools:[{name:'p05_read_report',description:'Return a dummy metadata-only readiness report.',inputSchema:{type:'object',properties:{},additionalProperties:false},execute:async()=>{
 record({type:'read',count:++count});return {content:[{type:'text',text:'Readiness report: 12 artifacts.'}]};
}}]}, {input});
'''.replace('__MCP_SERVER_MODULE__', json.dumps((root/'packages/mcp-server/src/index.mjs').as_uri())).replace('__METADATA_MODULE__', json.dumps((root/'tests/browser-handoff/client-protocol-metadata.mjs').as_uri())))
 prompt='Call p05_read_report once through the configured p05 MCP server. Return the artifact count from that tool. Do not use any other tool. This is a dummy metadata-only readiness test.'
 clients={
 'claude':['claude','--print','--restricted','--tools','','--allowedTools','mcp__p05__p05_read_report','--permission-mode','dontAsk','--strict-mcp-config','--no-session-persistence','--output-format','json'],
 'codex':['codex','exec','--ignore-user-config','--ignore-rules','--ephemeral','--sandbox','read-only','--skip-git-repo-check','--json']}
 allPassed = True
 for name,args in clients.items():
  trace=profile/(name+'.trace.jsonl')
  if name=='claude':
   config=profile/'claude.json';config.write_text(json.dumps({'mcpServers':{'p05':{'command':subprocess.check_output(['which','node'],text=True).strip(),'args':[str(server),str(trace)]}}}));os.chmod(config,0o600)
   args+=['--mcp-config',str(config),'--',prompt]
  else:
   settings={'mcp_servers.p05.command':subprocess.check_output(['which','node'],text=True).strip(),'mcp_servers.p05.args':[str(server),str(trace)],'mcp_servers.p05.enabled_tools':['p05_read_report'],'mcp_servers.p05.default_tools_approval_mode':'approve','mcp_servers.p05.startup_timeout_sec':10}
   for key,value in settings.items():args+=['-c',key+'='+json.dumps(value)]
   args+=[prompt]
  version=subprocess.check_output([name,'--version'],stderr=subprocess.DEVNULL,text=True).strip()
  result={'client':name,'version':version if len(version)<80 else 'unretained','scope':'dummy MCP readiness, not broker/browser/phase acceptance'}
  try:
   r=subprocess.run(args,cwd=profile,capture_output=True,timeout=120)
   result.update(exitCode=r.returncode,stdoutBytes=len(r.stdout),stderrBytes=len(r.stderr),answerIncludes12=b'12' in r.stdout)
   result['diagnosticFlags']={word:word.encode() in r.stderr.lower() for word in ['config','restricted','permission','unknown option','authentication','credit','billing']}
  except subprocess.TimeoutExpired:
   result.update(timedOut=True)
  events=[json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
  result['events']=events;result['sourceOrApplicationSessionSupplied']=False
  result['passed']=result.get('exitCode')==0 and result.get('answerIncludes12') is True and sum(event.get('type')=='read' for event in events)==1
  allPassed = allPassed and result["passed"]
  print(json.dumps(result),flush=True)
 if not allPassed:sys.exit(1)
finally:shutil.rmtree(profile)
