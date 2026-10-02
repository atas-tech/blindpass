// SPDX-License-Identifier: AGPL-3.0-only
// Disposable systemd workload: real packaged SDK -> fixed Root broker socket.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { access, writeFile } from 'node:fs/promises';
const node='/usr/lib/blindpass/login/runtime/bin/node';
const bundle='/usr/lib/blindpass/login/mcp/mcp-server.mjs';
const base='/run/p05-mcp-gate';
const wrong=process.argv[2]==='wrong';
async function waitFile(path){const limit=performance.now()+40000;while(performance.now()<limit){try{await access(path);return;}catch{}await new Promise(r=>setTimeout(r,25));}throw new Error('guest_wait');}
function connect(revision){
  const child=spawn(node,[bundle],{env:{PATH:'/usr/bin:/bin',HOME:'/nonexistent',BLINDPASS_AUTO_PERSIST:'false',BLINDPASS_FLEET_MCP:'1',BLINDPASS_NODE_ID:'node-a',BLINDPASS_WORKLOAD_ID:'workload-a',BLINDPASS_WORKLOAD_UNIT:'p05-mcp-agent.service',INVOCATION_ID:process.env.P05_CLAIMED_INVOCATION??process.env.INVOCATION_ID},stdio:['pipe','pipe','pipe']});
  let id=0,errors=0;const pending=new Map();const closed=new Promise(resolve=>child.once('close',resolve));child.stderr.on('data',b=>{errors+=b.length;b.fill(0);});
  createInterface({input:child.stdout}).on('line',line=>{try{const message=JSON.parse(line);pending.get(message.id)?.(message);pending.delete(message.id);}catch{child.kill();}});
  return {async call(method,params={}){if(revision==='2026-07-28')params._meta={'io.modelcontextprotocol/protocolVersion':revision,'io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'guest-workload',version:'1'}};const requestId=++id;const result=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('guest_rpc_deadline')),5000);pending.set(requestId,v=>{clearTimeout(timer);resolve(v);});});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:requestId,method,params})+'\n');return result;},notify(method){child.stdin.write(JSON.stringify({jsonrpc:'2.0',method})+'\n');},async close(){child.stdin.end();const timer=setTimeout(()=>child.kill('SIGKILL'),1000);try{assert.equal(await closed,0);}finally{clearTimeout(timer);}assert.equal(errors,0);}};
}
async function run(){
  await waitFile(`${base}/ready`);
  for(const revision of wrong?['2026-07-28']:['2025-11-25','2026-07-28']){
    const client=connect(revision);
    try{
      if(revision==='2025-11-25'){const init=await client.call('initialize',{protocolVersion:revision,capabilities:{},clientInfo:{name:'guest-workload',version:'1'}});assert.equal(init.result.protocolVersion,revision);client.notify('notifications/initialized');}
      const listed=await client.call('tools/list');for(const name of ['blindpass_request_operation','blindpass_operation_status','blindpass_cancel_operation'])assert.ok(listed.result.tools.some(t=>t.name===name));
      const args={action:'browser.session',resourceId:'report-primary',requestKey:`retry_guest_${revision.replaceAll('-','')}`};
      const request=()=>client.call('tools/call',{name:'blindpass_request_operation',arguments:args,context:{nodeId:'spoof',unit:'spoof.service'}});
      const first=await request();
      if(wrong){assert.equal(first.result.isError,true);assert.deepEqual(first.result.content,[{type:'text',text:'Operation failed'}]);continue;}
      const metadata=first.result.structuredContent;assert.equal(metadata.status,'requested');assert.ok(/^event_[A-Za-z0-9_-]{16,100}$/.test(metadata.eventKey));
      assert.deepEqual((await request()).result.structuredContent,metadata);
      if(revision==='2025-11-25'){
        await writeFile(`${base}/agent/restart`,JSON.stringify({eventKey:metadata.eventKey}),{mode:0o600});await waitFile(`${base}/restarted`);
        assert.deepEqual((await request()).result.structuredContent,metadata);
      }
      const status=()=>client.call('tools/call',{name:'blindpass_operation_status',arguments:{eventKey:metadata.eventKey}});
      assert.equal((await status()).result.structuredContent.status,'pending');
      const cancelled=await client.call('tools/call',{name:'blindpass_cancel_operation',arguments:{requestKey:args.requestKey}});assert.equal(cancelled.result.structuredContent.status,'cancellation_requested');
      assert.equal((await status()).result.structuredContent.status,'cancelling');
      assert.equal((await client.call('tools/call',{name:'blindpass_cancel_operation',arguments:{eventKey:metadata.eventKey}})).result.structuredContent.status,'cancellation_requested');
      assert.ok(!JSON.stringify([first,cancelled]).includes('fixture.example.invalid'));
    }finally{await client.close();}
  }
  process.stdout.write(wrong?'P05-MCP-WRONG-UNIT denied\n':'P05-MCP-CLIENT revisions=2 retry_after_ack_restart=verified status=pending cancellation=requested normal_errors=empty\n');
}
run().catch(()=>{process.exitCode=70;});
