// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { createMcpServer } from '../src/index.mjs';
test('P05-I04 every registered callback has a bounded safe deadline, including legacy adapters',{timeout:5000},async()=>{
  const child=spawn(process.execPath,[new URL('./deadline-fixture.mjs',import.meta.url).pathname],{env:{PATH:process.env.PATH},stdio:['pipe','pipe','pipe']});
  let stderr='';child.stderr.on('data',b=>{stderr+=b;});const closed=new Promise(resolve=>child.once('close',resolve));const response=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('expected bounded callback response')),1200);createInterface({input:child.stdout}).once('line',line=>{clearTimeout(timer);resolve(JSON.parse(line));});});
  try{
    child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'bounded_legacy',arguments:{},_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'deadline-contract',version:'1'}}}})+'\n');
    const timer=setTimeout(()=>child.kill('SIGKILL'),1500);let result;try{result=await response;}finally{clearTimeout(timer);}
    assert.equal(result.result.isError,true);assert.deepEqual(result.result.content,[{type:'text',text:'Operation failed'}]);assert.ok(!JSON.stringify(result).includes('CANARY'));
  }finally{child.stdin.end();const timer=setTimeout(()=>child.kill('SIGKILL'),1000);try{await closed;}finally{clearTimeout(timer);}assert.equal(stderr,'');}
});
test('P05-I04 callback deadline cannot exceed the production 30s bound',()=>{assert.throws(()=>createMcpServer({toolTimeoutMs:30001}));});
