// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, createConnection } from 'node:net';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';
import { BROKER_SOCKET, brokerIdentityFromEnvironment, createBrokerClient, exchangeWithBroker, verifyBrokerSocket } from '../src/broker-client.mjs';

const identity={nodeId:'node-a',workloadId:'workload-a',unit:'agent.service',invocationId:'a'.repeat(32)};
const args={action:'browser.session',resourceId:'report-primary',requestKey:'retry_0123456789abcdef'};
const timing={now:()=>performance.now(),callTimeoutMs:120,cleanupTimeoutMs:40};
const proof={dev:1,ino:2,gid:1001};
function client(exchange,options={}){return createBrokerClient(identity,{...timing,exchange,...options});}
function operation(frame){return frame.trimEnd().split(' ')[5];}

test('P05-I04 broker runtime identity is fixed and opt-in; arguments cannot replace it',async()=>{
  assert.equal(brokerIdentityFromEnvironment({}),undefined);
  assert.throws(()=>brokerIdentityFromEnvironment({BLINDPASS_FLEET_MCP:'yes'}));
  assert.throws(()=>brokerIdentityFromEnvironment({BLINDPASS_FLEET_MCP:'1'}));
  const env={BLINDPASS_FLEET_MCP:'1',BLINDPASS_NODE_ID:'node-a',BLINDPASS_WORKLOAD_ID:'workload-a',BLINDPASS_WORKLOAD_UNIT:'agent.service',INVOCATION_ID:'a'.repeat(32)};
  assert.deepEqual(brokerIdentityFromEnvironment(env),identity);
  const frames=[];const config={...identity};
  const broker=createBrokerClient(config,{...timing,exchange:async(frame,{onSent})=>{frames.push(frame);onSent();return 'OK operation_request event_0123456789abcdef\n';}});
  config.nodeId='spoof';
  assert.equal((await broker.request(args)).status,'requested');assert.match(frames[0],/^WORK node-a workload-a agent.service a{32} request:/);
  await assert.rejects(broker.request({...args,nodeId:'spoof'}));assert.equal(frames.length,1);
});
test('P05-I04 request frame uses original bounded payload and no source/browser options',async()=>{
  const frames=[];const broker=client(async(frame,{onSent})=>{frames.push(frame);onSent();return 'OK operation_request event_0123456789abcdef\n';});
  await broker.request({...args,purpose:'é'.repeat(256),ttlSeconds:120});
  const payload=JSON.parse(Buffer.from(operation(frames[0]).slice(8),'base64url'));
  assert.deepEqual(Object.keys(payload).sort(),['action','mode','purpose','request_key','resource_id','ttl_seconds']);assert.equal(payload.mode,'browser_session');
  for(const bad of [{...args,requestKey:'short'},{...args,requestKey:1234567890123456},{...args,action:'noop.marker'},{...args,ttlSeconds:121},{...args,purpose:'é'.repeat(257)},{...args,allowRawLink:true},{...args,origin:'https://P05-PRIVATE-CANARY.test'}]) await assert.rejects(broker.request(bad));
  assert.equal(frames.length,1);
});
test('P05-I04 status and cancel return only exact metadata replies',async()=>{
  let reply='OK operation_status granted gr_0123456789abcdef op_0123456789abcdef\n';const frames=[];
  const broker=client(async(frame,{onSent})=>{frames.push(frame);onSent();return reply;});
  assert.deepEqual(await broker.status('event_0123456789abcdef'),{status:'granted',grantId:'gr_0123456789abcdef',operationId:'op_0123456789abcdef',eventKey:'event_0123456789abcdef'});
  reply='OK operation_status closed cancelled\n';assert.equal((await broker.status('event_0123456789abcdef')).outcome,'cancelled');
  reply='OK operation_cancel requested\n';assert.equal((await broker.cancel({requestKey:args.requestKey})).status,'cancellation_requested');assert.equal(operation(frames.at(-1)),`cancel-key:${args.requestKey}`);
  assert.equal((await broker.cancel({eventKey:'event_0123456789abcdef'})).status,'cancellation_requested');
  const count=frames.length;await assert.rejects(broker.cancel({requestKey:args.requestKey,eventKey:'event_0123456789abcdef'}));await assert.rejects(broker.cancel({}));assert.equal(frames.length,count);
});
test('P05-I04 request reply loss triggers bounded independent withdrawal',async()=>{
  const frames=[];const broker=client(async(frame,{onSent})=>{frames.push(frame);onSent();if(operation(frame).startsWith('request:'))throw new Error('P05-PRIVATE-CANARY');return 'OK operation_cancel requested\n';});
  assert.deepEqual(await broker.request(args),{status:'uncertain',requestKey:args.requestKey,cancellation:'requested'});assert.equal(frames.length,2);assert.equal(operation(frames[1]),`cancel-key:${args.requestKey}`);
});
test('P05-I04 aborted submitted request withdraws despite the aborted caller signal',async()=>{
  const controller=new AbortController();const frames=[];let started;
  const ready=new Promise(resolve=>{started=resolve;});
  const broker=client(async(frame,{onSent,signal})=>{frames.push(frame);onSent();if(operation(frame).startsWith('request:')){started();return new Promise(()=>{});}assert.equal(signal.aborted,false);return 'OK operation_cancel requested\n';});
  const result=broker.request(args,controller.signal);await ready;controller.abort();assert.equal((await result).cancellation,'requested');assert.equal(frames.length,2);
});
test('P05-I04 primary timeout and stalled withdrawal stay within the configured call budget',async()=>{
  const frames=[];const broker=client(async(frame,{onSent})=>{frames.push(frame);onSent();return new Promise(()=>{});});
  const start=performance.now();assert.equal((await broker.request(args)).cancellation,'unconfirmed');assert.ok(performance.now()-start<350);assert.equal(frames.length,2);
  assert.throws(()=>createBrokerClient(identity,{callTimeoutMs:30001}));
});
test('P05-I04 pre-aborted calls and definite broker rejection create no withdrawal',async()=>{
  const frames=[];const broker=client(async(frame,{onSent})=>{frames.push(frame);onSent();return 'ERR policy_denied P05-PRIVATE-CANARY\n';});
  const controller=new AbortController();controller.abort();await assert.rejects(broker.request(args,controller.signal));assert.equal(frames.length,0);
  await assert.rejects(broker.request(args));assert.equal(frames.length,1);
});
test('P05-I06 malformed and secret-bearing broker replies never reach status results',async()=>{
  for(const reply of ['OK operation_status ready ws://P05-CANARY.test\n','OK operation_status ready ctx_short\n','OK operation_status ready ctx_'+ 'a'.repeat(64)+' P05-PRIVATE-CANARY\n','OK operation_status granted ws://P05-CANARY.test op_0123456789abcdef\n','OK operation_status closed completed P05-PRIVATE-CANARY\n','OK operation_status closed unknown\n','OK operation_status pending\nP05-CANARY\n','OK operation_status pending','OK operation_status pending\r\n','P05-PRIVATE-CANARY\n']) {
    const broker=client(async()=>reply);await assert.rejects(broker.status('event_0123456789abcdef'),error=>error.message==='broker_operation_failed');
  }
});
test('P05-I04 fixed socket guards reject owners, modes, symlinks and hard links',async()=>{
  const stat=async(path)=>({uid:0,mode:path===BROKER_SOCKET?0o660:path==='/run/blindpass'?0o751:0o755,nlink:1,dev:1,ino:2,gid:1001,isDirectory:()=>path!==BROKER_SOCKET,isSocket:()=>path===BROKER_SOCKET});
  assert.deepEqual(await verifyBrokerSocket(stat),proof);
  for(const override of [{uid:1000},{mode:0o666},{nlink:2},{isSocket:()=>false}]) await assert.rejects(verifyBrokerSocket(async path=>path===BROKER_SOCKET?{...await stat(path),...override}:stat(path)));
  for(const override of [{uid:1000},{mode:0o777},{isDirectory:()=>false}]) await assert.rejects(verifyBrokerSocket(async path=>path==='/run/blindpass'?{...await stat(path),...override}:stat(path)));
});
async function unixFixture(t,reply,io={}){
  const directory=await mkdtemp(join(tmpdir(),'blindpass-mcp-wire-'));const path=join(directory,'workload.sock');const sockets=new Set();const frames=[];
  const server=createServer({allowHalfOpen:true},socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});let frame='';socket.on('data',bytes=>{frame+=bytes;});socket.on('end',()=>{frames.push(frame);if(reply!==null)socket.end(reply);});});
  await new Promise(resolve=>server.listen(path,resolve));
  t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));await rm(directory,{recursive:true,force:true});});
  const exchange=(frame,context)=>exchangeWithBroker(frame,context,{verify:async()=>proof,connect:options=>{assert.equal(options.path,BROKER_SOCKET);return createConnection({path});},...io});
  return {broker:client(exchange,{callTimeoutMs:500,cleanupTimeoutMs:100}),frames,exchange};
}
test('P05-I04 actual Unix transport requires complete frame/EOF and fixed pathname',async t=>{
  const fixture=await unixFixture(t,'OK operation_status pending\n');assert.equal((await fixture.broker.status('event_0123456789abcdef')).status,'pending');assert.equal(fixture.frames.length,1);
});
test('P05-I06 actual Unix transport rejects oversized, invalid UTF8 and partial replies',async t=>{
  for(const reply of [Buffer.from([0xff,0x0a]),'X'.repeat(4097),'OK operation_status pending','OK operation_status pending\nP05-CANARY\n']) {
    const fixture=await unixFixture(t,reply);await assert.rejects(fixture.broker.status('event_0123456789abcdef'));
  }
});
test('P05-I04 socket replacement and stall cannot publish a successful result',async t=>{
  let probes=0;const fixture=await unixFixture(t,'OK operation_status pending\n',{verify:async()=>({...proof,ino:++probes===1?2:3})});await assert.rejects(fixture.broker.status('event_0123456789abcdef'));assert.equal(fixture.frames.length,0);
  const stalled=await unixFixture(t,null);await assert.rejects(stalled.broker.status('event_0123456789abcdef'));
});

test('P05-I04 concurrent ordinary calls are bounded and cancellation has reserved capacity',async()=>{
  const frames=[];const broker=client(async(frame,{onSent})=>{frames.push(frame);onSent();if(operation(frame).startsWith('status:'))return new Promise(()=>{});return 'OK operation_cancel requested\n';},{callTimeoutMs:500,cleanupTimeoutMs:100});
  const pending=Array.from({length:12},()=>broker.status('event_0123456789abcdef').catch(()=>undefined));
  await assert.rejects(broker.status('event_0123456789abcdef'));assert.equal(frames.length,12);
  assert.equal((await broker.cancel({requestKey:args.requestKey})).status,'cancellation_requested');
  broker.abortActive();await Promise.all(pending);assert.equal(frames.length,13);
});
test('P05-I04 independent clock expiry rejects a late reply and withdraws the request',async()=>{
  let time=100,release;const frames=[];const broker=client(async(frame,{onSent})=>{frames.push(frame);onSent();if(operation(frame).startsWith('request:'))return new Promise(resolve=>{release=resolve;});return 'OK operation_cancel requested\n';},{now:()=>time,callTimeoutMs:120,cleanupTimeoutMs:40});
  const pending=broker.request(args);time=190;release('OK operation_request event_0123456789abcdef\n');
  assert.equal((await pending).cancellation,'requested');assert.equal(frames.length,2);
});
test('P05-I04 a delayed path proof after EOF does not discard a valid complete response',async t=>{
  let checks=0;const fixture=await unixFixture(t,'OK operation_status pending\n',{verify:async()=>{if(++checks===3)await new Promise(r=>setTimeout(r,25));return proof;}});
  assert.equal((await fixture.broker.status('event_0123456789abcdef')).status,'pending');assert.equal(checks,3);
});
test('P05-I04 a stalled initial path proof cannot submit after the call timed out',async()=>{
  let release,connects=0;const exchange=(frame,context)=>exchangeWithBroker(frame,context,{verify:()=>new Promise(resolve=>{release=resolve;}),connect:()=>{connects++;throw new Error('unexpected connect');}});
  const broker=client(exchange);await assert.rejects(broker.request(args));release(proof);await new Promise(r=>setTimeout(r,5));assert.equal(connects,0);
});

test('P05-AT01: confirmed browser closure returns bounded completion metadata',async()=>{
  const broker=client(async(frame)=>{
    assert.match(operation(frame),/^status:event_/);
    return 'OK operation_status closed completed\n';
  });
  assert.deepEqual(await broker.status('event_0123456789abcdef'),{status:'closed',outcome:'completed',eventKey:'event_0123456789abcdef'});
});
test('P05-PC04: ready metadata is an opaque context reference without a browser endpoint', async()=>{
  const contextHandle='ctx_'+ 'a'.repeat(64);
  const broker=client(async()=>`OK operation_status ready ${contextHandle}\n`);
  assert.deepEqual(await broker.status('event_0123456789abcdef'),{status:'ready',contextHandle,eventKey:'event_0123456789abcdef'});
});
