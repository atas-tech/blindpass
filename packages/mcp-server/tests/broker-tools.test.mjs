// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { test } from 'node:test';

const names = ['blindpass_request_operation', 'blindpass_operation_status', 'blindpass_cancel_operation'];
function connect(revision) {
  const child = spawn(process.execPath, [new URL('./broker-tools-fixture.mjs', import.meta.url).pathname],
    { env: { PATH: process.env.PATH }, stdio: ['pipe', 'pipe', 'pipe'] });
  let id=0,stderr='';const pending=new Map();const closed=new Promise(resolve=>child.once('close',resolve));
  child.stderr.on('data',bytes=>{stderr+=bytes;});
  createInterface({input:child.stdout}).on('line',line=>{const value=JSON.parse(line);pending.get(value.id)?.(value);pending.delete(value.id);});
  return {
    async request(method,params={}) {
      if(revision==='2026-07-28')params._meta={'io.modelcontextprotocol/protocolVersion':revision,'io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'tool-contract',version:'1'}};
      const requestId=++id;const result=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('tool response deadline')),4000);pending.set(requestId,v=>{clearTimeout(timer);resolve(v);});});
      child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:requestId,method,params})+'\n');return result;
    },
    notify(method,params){child.stdin.write(JSON.stringify({jsonrpc:'2.0',method,params})+'\n');},
    async close(){child.stdin.end();const timer=setTimeout(()=>child.kill('SIGKILL'),1000);try{await closed;}finally{clearTimeout(timer);}assert.equal(stderr,'');},
  };
}
for(const revision of ['2025-11-25','2026-07-28']) {
  test(`P05-I04 official SDK broker request/status/cancel metadata on ${revision}`,{timeout:10000},async()=>{
    const client=connect(revision);
    try{
      if(revision!=='2026-07-28'){await client.request('initialize',{protocolVersion:revision,capabilities:{},clientInfo:{name:'tool-contract',version:'1'}});client.notify('notifications/initialized');}
      const listed=await client.request('tools/list');assert.deepEqual(listed.result.tools.map(t=>t.name),names);
      const requested=await client.request('tools/call',{name:names[0],arguments:{action:'browser.session',resourceId:'report-primary',requestKey:'retry_0123456789abcdef'},context:{nodeId:'spoof',socketPath:'spoof'}});
      assert.deepEqual(requested.result.structuredContent,{status:'requested',requestKey:'retry_0123456789abcdef',eventKey:'event_0123456789abcdef'});
      const status=await client.request('tools/call',{name:names[1],arguments:{eventKey:'event_0123456789abcdef'}});assert.equal(status.result.structuredContent.status,'pending');
      const ready=await client.request('tools/call',{name:names[1],arguments:{eventKey:'event_ready_0123456789abcdef'}});
      assert.deepEqual(ready.result.structuredContent,{status:'ready',contextHandle:'ctx_'+ 'a'.repeat(64),eventKey:'event_ready_0123456789abcdef'});
      const completed=await client.request('tools/call',{name:names[1],arguments:{eventKey:'event_completed_0123456789'}});
      assert.deepEqual(completed.result.structuredContent,{status:'closed',outcome:'completed',eventKey:'event_completed_0123456789'});
      const cancelled=await client.request('tools/call',{name:names[2],arguments:{requestKey:'retry_0123456789abcdef'}});assert.equal(cancelled.result.structuredContent.status,'cancellation_requested');
      const failed=await client.request('tools/call',{name:names[0],arguments:{action:'browser.session',resourceId:'fail',requestKey:'retry_0123456789abcdef'}});assert.equal(failed.result.isError,true);assert.ok(!JSON.stringify(failed).includes('CANARY'));
    }finally{await client.close();}
  });
}

test('P05-I04 SDK rejects runtime/source/raw-link extensions and malformed private results', {timeout:10000}, async()=>{
  const client=connect('2026-07-28');
  try {
    for (const extension of [{nodeId:'spoof'},{origin:'https://P05-PRIVATE-CANARY.test'},{allowRawLink:true},{socketPath:'/tmp/spoof.sock'}]) {
      const value=await client.request('tools/call',{name:names[0],arguments:{action:'browser.session',resourceId:'report-primary',requestKey:'retry_0123456789abcdef',...extension}});
      assert.ok(value.error || value.result?.isError);
      assert.ok(!JSON.stringify(value).includes('P05-PRIVATE-CANARY'));
    }
    const malformed=await client.request('tools/call',{name:names[1],arguments:{eventKey:'event_malformed_0123456789'}});
    assert.equal(malformed.result.isError,true);assert.equal(malformed.result.structuredContent,undefined);assert.ok(!JSON.stringify(malformed).includes('CANARY'));
  } finally { await client.close(); }
});
