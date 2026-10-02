// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
async function waitUntil(predicate) {
  const deadline=performance.now()+3500;
  while(performance.now()<deadline){if(await predicate())return;await new Promise(resolve=>setTimeout(resolve,10));}
  throw new Error('abort fixture deadline');
}
for(const mode of ['notification','EOF']) {
  test(`P05-I04 actual SDK ${mode} withdraws submitted request before exit`,{timeout:6000},async()=>{
    const directory=await mkdtemp(join(tmpdir(),'blindpass-mcp-abort-'));const events=join(directory,'events');
    const child=spawn(process.execPath,[new URL('./broker-abort-fixture.mjs',import.meta.url).pathname],{env:{PATH:process.env.PATH,P05_MCP_EVENT_FILE:events},stdio:['pipe','pipe','pipe']});
    const closed=new Promise(resolve=>child.once('close',resolve));let stderr='',stdout='';child.stderr.on('data',bytes=>{stderr+=bytes;});child.stdout.on('data',bytes=>{stdout+=bytes;});
    try{
      child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:11,method:'tools/call',params:{name:'blindpass_request_operation',arguments:{action:'browser.session',resourceId:'report-primary',requestKey:'retry_0123456789abcdef'},_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'abort-contract',version:'1'}}}})+'\n');
      await waitUntil(async()=>{try{return (await readFile(events,'utf8')).includes('submitted');}catch{return false;}});
      if(mode==='notification')child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/cancelled',params:{requestId:11,reason:'P05-CANCEL-PRIVATE-CANARY'}})+'\n');else child.stdin.end();
      await waitUntil(async()=>{try{return (await readFile(events,'utf8')).includes('withdrawal');}catch{return false;}});
      if(mode==='notification')child.stdin.end();
      const timer=setTimeout(()=>child.kill('SIGKILL'),1000);try{assert.equal(await closed,0);}finally{clearTimeout(timer);}
      assert.equal(stderr,'');assert.ok(!stdout.includes('CANARY'));assert.equal((await readFile(events,'utf8')).trim(),'submitted\nwithdrawal');
    }finally{child.kill('SIGKILL');await closed;await rm(directory,{recursive:true,force:true});}
  });
}
