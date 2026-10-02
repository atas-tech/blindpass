// SPDX-License-Identifier: AGPL-3.0-only
// Root disposable driver. Issuer keys remain in memory; no source is provisioned.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdir, rm, writeFile, readFile, access } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
const base='/run/p05-mcp-gate';const node='/usr/lib/blindpass/login/runtime/bin/node';
const script='/tmp/browser-handoff/broker-mcp-guest-client.mjs';
const invoke=(command,args)=>execFileSync(command,args,{stdio:['ignore','pipe','pipe'],encoding:'utf8'}).trim();
const canonical=value=>JSON.stringify(sort(value));
function sort(value){if(Array.isArray(value))return value.map(sort);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,sort(value[k])]));return value;}
const pair=generateKeyPairSync('ed25519');const publicRaw=pair.publicKey.export({type:'spki',format:'der'}).subarray(-32);const publicText=publicRaw.toString('base64url');const kid=`ed25519-${publicText}`;
function envelope(kind,body){const value={v:1,kind,body,kid,epoch:1};const message=Buffer.concat([Buffer.from('blindpass:fleet-document:v1\0'),Buffer.from(canonical(value))]);return Buffer.from(canonical({...value,sig:sign(null,message,pair.privateKey).toString('base64url')}));}
async function control(frame){return new Promise((resolve,reject)=>{const socket=createConnection({path:'/run/blindpass/control.sock'});const chunks=[];const timer=setTimeout(()=>{socket.destroy();reject(new Error('control_deadline'));},3000);socket.on('connect',()=>socket.end(frame));socket.on('data',b=>chunks.push(b));socket.on('error',()=>{clearTimeout(timer);reject(new Error('control_failed'));});socket.on('end',()=>{clearTimeout(timer);resolve(Buffer.concat(chunks).toString());});});}
async function relay(kind,body){const document=envelope(kind,body);const result=await control(Buffer.concat([Buffer.from(`RELAY ${document.length}\n`),document]));assert.equal(result,`OK document_applied ${kind}\n`);}
async function wait(predicate){const deadline=performance.now()+15000;while(performance.now()<deadline){if(await predicate())return;await new Promise(r=>setTimeout(r,25));}throw new Error('guest_state_deadline');}
function unit(name,args,env=[]){const child=spawn('systemd-run',['--quiet','--wait','--pipe','--collect',`--unit=${name}`,'-p','User=blindpass-mcp','-p','Group=blindpass-mcp','-p','RuntimeMaxSec=60s','-p','TimeoutStopSec=5s','-p','NoNewPrivileges=yes','-p','LimitCORE=0','-p','RestrictAddressFamilies=AF_UNIX','-p','ProtectHome=yes',...env.flatMap(v=>['-E',v]),node,script,...args],{stdio:['ignore','pipe','pipe']});let output='',errors='';child.stdout.on('data',b=>{output+=b;});child.stderr.on('data',b=>{errors+=b;});const ended=new Promise(resolve=>child.once('close',code=>resolve({code,output,errors})));return {child,ended};}
let agent,spoof;
async function run(){
  assert.equal(process.getuid(),0);
  for(const path of ['/etc/blindpass',base,'/run/blindpass/workload.sock']){await assert.rejects(access(path));}
  try{invoke('useradd',['--system','--no-create-home','--shell','/usr/sbin/nologin','blindpass-mcp']);}catch{invoke('id',['blindpass-mcp']);}
  const uid=Number(invoke('id',['-u','blindpass-mcp']));const gid=Number(invoke('id',['-g','blindpass-mcp']));
  await mkdir(base,{mode:0o755});await mkdir(`${base}/agent`,{mode:0o700});invoke('chown',[`${uid}:${gid}`,`${base}/agent`]);await mkdir('/etc/blindpass',{mode:0o700});
  await writeFile('/etc/blindpass/browser-resources.json',canonical({version:1,resources:[{resource_id:'report-primary',workload_ids:['workload-a'],credential_unit:'blindpass-login-helper@.service',credential_name:'primary-password',configuration:{kind:'fixture',origin:'https://fixture.example.invalid',account:'primary',sessionMaxMs:300000}}]}),{mode:0o600});
  agent=unit('p05-mcp-agent',[]);
  await wait(async()=>invoke('systemctl',['show','-p','InvocationID','--value','p05-mcp-agent.service']).length===32);
  const invocation=invoke('systemctl',['show','-p','InvocationID','--value','p05-mcp-agent.service']);
  const brokerArgs=['--browser-resources','--key-directory',`${base}/keys`,'--workload-group','blindpass-mcp','--map','blindpass-login-helper@.service=primary-password','--workload',`node-a:workload-a:p05-mcp-agent.service:${uid}:${invocation}`];
  async function start(initial=true){if(initial)invoke('systemd-run',['--quiet','--collect','--unit=p05-mcp-broker','-p','Type=notify','-p','NotifyAccess=main','-p','RuntimeMaxSec=60s','-p','TimeoutStopSec=5s','-p','LimitCORE=0','/usr/lib/blindpass/login/blindpass-broker',...brokerArgs]);else invoke('systemctl',['restart','p05-mcp-broker.service']);await wait(async()=>{try{await access('/run/blindpass/control.sock');return true;}catch{return false;}});assert.equal(await control(`PIN_ISSUER tenant-a node-a 1 ${kid} ${publicText}\n`),'OK issuer_pinned\n');await relay('registration',{node_id:'node-a',workload_id:'workload-a',unit:'p05-mcp-agent.service',account:`uid:${uid}`,invocation_id:invocation,status:'active',consumption_mode:'browser_session',registration_version:1,policy_version:1,local_ceiling_seconds:120});await relay('policy_snapshot',{policy_version:1,local_ceiling_seconds:120,allowed_actions:['browser.session'],allowed_modes:['browser_session']});const challenge=(await control('TIME_CHALLENGE\n')).trim().slice(5);const time=Date.now();await relay('time_reply',{node_id:'node-a',challenge,challenge_received_at_ms:time,controller_time_ms:time,issuer_epoch:1});}
  await start();
  const publicReply=await control('IDENTITY\n');const brokerPublic=publicReply.match(/signing_pub=([A-Za-z0-9_-]+)/)[1];const brokerKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(brokerPublic,'base64url')]),type:'spki',format:'der'});
  async function events(){const value=JSON.parse((await control('PULL_EVENTS\n')).split('\n')[1]);for(const event of value){const message=Buffer.concat([Buffer.from('blindpass:fleet-node-event:v1\0'),Buffer.from(canonical({node_id:'node-a',idempotency_key:event.idempotency_key,kind:event.kind,body:event.body}))]);assert.ok(verify(null,message,brokerKey,Buffer.from(event.broker_signature,'base64url')));}return value;}
  await writeFile(`${base}/ready`,'ready\n',{mode:0o644});await wait(async()=>{try{await access(`${base}/agent/restart`);return true;}catch{return false;}});
  const first=JSON.parse(await readFile(`${base}/agent/restart`,'utf8'));const before=await events();assert.equal(before.filter(e=>e.kind==='operation_request').length,1);assert.equal(before.find(e=>e.kind==='operation_request').idempotency_key,first.eventKey);assert.equal(before.find(e=>e.kind==='operation_request').body.request_version,2);
  await relay('application_ack',{node_id:'node-a',issuer_epoch:1,acknowledged_at_ms:Date.now(),event_keys:before.map(e=>e.idempotency_key)});
  await start(false);await writeFile(`${base}/restarted`,'ready\n',{mode:0o644});
  const actual=await agent.ended;assert.equal(actual.code,0);assert.ok(actual.output.includes('retry_after_ack_restart=verified'));assert.equal(actual.errors,'');
  const after=await events();assert.equal(after.filter(e=>e.kind==='operation_request').length,1);assert.equal(after.filter(e=>e.kind==='operation_cancel').length,2);assert.ok(after.filter(e=>e.kind==='operation_request').every(e=>e.body.request_version===2));
  spoof=unit('p05-mcp-spoof',['wrong'],[`P05_CLAIMED_INVOCATION=${invocation}`]);const denied=await spoof.ended;assert.equal(denied.code,0);assert.ok(denied.output.includes('denied'));assert.equal((await events()).filter(e=>e.kind==='operation_request').length,1);
  const snapshot=await readFile(`${base}/keys/pending-node-events.jsonl`,'utf8');assert.equal(JSON.parse(snapshot.split('\n')[0]).v,5);
  for(const privateValue of ['fixture.example.invalid','primary-password','P05-PRIVATE-CANARY'])assert.ok(!snapshot.includes(privateValue));
  process.stdout.write('P05-MCP-BROKER-VM packaged_sdk=verified revisions=2 fixed_root_socket=verified kernel_workload_identity=verified same_uid_other_unit=denied signed_request_cancel=verified request_version=2 ack_restart_retry=verified duplicate_requests=none source_provisioned=none scope=metadata_transport\n');
}
try{await run();}catch{process.stderr.write('P05-MCP-BROKER-VM failed\n');process.exitCode=70;}finally{for(const name of ['p05-mcp-agent.service','p05-mcp-spoof.service','p05-mcp-broker.service']){try{invoke('systemctl',['stop',name]);}catch{}}await rm(base,{recursive:true,force:true});await rm('/etc/blindpass',{recursive:true,force:true});await rm('/run/blindpass',{recursive:true,force:true});}
