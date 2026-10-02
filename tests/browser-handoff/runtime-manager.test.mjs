// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { RuntimeManager, validateRuntimeSelection, runRuntimeManagerCommand } from '../../helpers/login/src/runtime-manager.mjs';
const unit='blindpass-browser@0-123-root.service', invocation='a'.repeat(32), uid=61001;
const selection={kind:'browser',unit,invocation,uid};
test('P05-PC07: systemctl metadata waits for closed pipes after process exit', async () => {
  const child = new EventEmitter(); child.stdout = new EventEmitter(); child.kill = () => {};
  const result = runRuntimeManagerCommand(['show', '--', unit], (path, args, options) => {
    assert.equal(path, '/usr/bin/systemctl'); assert.equal(options.stdio[2], 'ignore');
    assert.equal(args.at(-1), unit);
    queueMicrotask(() => {
      child.emit('exit', 0);
      child.stdout.emit('data', Buffer.from('InvocationID='));
      child.stdout.emit('data', Buffer.from(invocation+'\n'));
      child.emit('close', 0);
    });
    return child;
  });
  assert.equal(await result, 'InvocationID='+invocation+'\n');
});
test('P05-PC07: bounded systemctl pipe failures return only a fixed error', async () => {
  for (const failure of ['exit', 'output', 'error']) {
    const child = new EventEmitter(); child.stdout = new EventEmitter(); let killed = 0; child.kill = () => { killed++; };
    const result = runRuntimeManagerCommand(['show', '--', unit], (_path, _args, options) => {
      assert.deepEqual(options.env, { PATH: '/usr/bin:/bin', LANG: 'C' });
      queueMicrotask(() => {
        if (failure === 'output') child.stdout.emit('data', Buffer.alloc(65537, 'x'));
        if (failure === 'error') child.emit('error', new Error('P05-PRIVATE-CANARY'));
        child.emit('close', 1);
      });
      return child;
    });
    await assert.rejects(result, { message: 'runtime_management_unavailable' });
    assert.equal(killed, 1);
  }
});
function harness() {
  const properties={Id:unit,InvocationID:invocation,LoadState:'loaded',ActiveState:'active',SubState:'running',MainPID:'412',DynamicUser:'yes',PrivateNetwork:'yes',PrivateTmp:'yes',PrivateDevices:'yes',ProtectSystem:'strict',ProtectHome:'yes',ProtectControlGroups:'yes',NoNewPrivileges:'yes',KillMode:'control-group',SendSIGKILL:'yes',LimitCORE:'0',RuntimeDirectory:'blindpass-browser-0-123-root',RuntimeDirectoryMode:'0700',FragmentPath:'/etc/systemd/system/blindpass-browser@.service',ControlGroup:'/system.slice/system-blindpass\\x2dbrowser.slice/'+unit,ExecStart:'{ path=/usr/lib/blindpass/login/runtime/bin/node ; argv[]=/usr/lib/blindpass/login/runtime/bin/node /usr/lib/blindpass/login/src/browser-worker.mjs ; ignore_errors=no ; }'};
  const calls=[]; let stopped=false;
  const inode={isDirectory:()=>true,isFile:()=>false,isSymbolicLink:()=>false,uid,mode:0o40700,dev:20,ino:31};
  const io={command:async(args)=>{calls.push(args);if(args[0]==='stop'){stopped=true;return '';}return Object.entries(properties).map(([k,v])=>`${k}=${v}`).join('\n')+'\n';},lstat:async(path)=>{if(stopped&&path.startsWith('/run/'))throw Object.assign(new Error(),{code:'ENOENT'});if(path===properties.FragmentPath)return {...inode,isDirectory:()=>false,isFile:()=>true,uid:0,mode:0o100644};return inode;},stat:async(path)=>({...inode,ino:path==='/proc/self/ns/net'?1:2}),readFile:async(path)=>{if(path.endsWith('/status'))return `Uid:\t${uid}\t${uid}\t${uid}\t${uid}\n`;if(path.endsWith('/cgroup'))return '0::'+properties.ControlGroup+'\n';if(path.endsWith('/cgroup.events'))return `populated ${stopped?0:1}\n`;throw new Error('unexpected_read');}};
  return {properties,calls,io,manager:new RuntimeManager(io)};
}
test('P05-PC02: installed runtime inspection binds manager/procfs/profile observations',async()=>{const h=harness();const result=await h.manager.inspect(selection);assert.equal(result.unit,unit);assert.equal(result.invocation,invocation);assert.equal(result.uid,uid);assert.equal(result.networkIsolated,true);assert.equal(result.profilePrivate,true);assert.equal(h.calls.length,2);assert.ok(h.calls.every(args=>args.at(-1)===unit));assert.equal(JSON.stringify(result).includes('412'),false);});
test('P05-PC02: changed identity and weakened runtime profiles deny inspection',async()=>{for(const [key,value] of [['InvocationID','b'.repeat(32)],['DynamicUser','no'],['PrivateNetwork','no'],['PrivateTmp','no'],['NoNewPrivileges','no'],['KillMode','process'],['LimitCORE','18446744073709551615'],['RuntimeDirectory','other'],['ExecStart','/bin/sh P05-PRIVATE-CANARY']]){const h=harness();h.properties[key]=value;await assert.rejects(h.manager.inspect(selection),{message:'runtime_management_unavailable'});}});
test('P05-PC02: actual host network, wrong procfs UID/cgroup and nonprivate profile deny',async()=>{for(const variant of ['network','uid','cgroup','profile','fragment']){const h=harness();if(variant==='network')h.io.stat=async()=>({ino:1,dev:20});if(variant==='uid')h.io.readFile=async()=> 'Uid:\t1001\t1001\t1001\t1001\n';if(variant==='cgroup')h.io.readFile=async(path)=>path.endsWith('/status')?`Uid:\t${uid}\t${uid}\t${uid}\t${uid}\n`:'0::/system.slice/other.service\n';if(variant==='profile')h.io.lstat=async()=>({isDirectory:()=>true,isFile:()=>true,isSymbolicLink:()=>false,uid:0,mode:0o755});if(variant==='fragment')h.io.lstat=async()=>({isDirectory:()=>true,isFile:()=>true,isSymbolicLink:()=>true,uid:0,mode:0o777});await assert.rejects(h.manager.inspect(selection));}});
test('P05-PC02: manager revalidation after inspection rejects replacement invocation',async()=>{const h=harness();const command=h.io.command;h.io.command=async(args)=>{const reply=await command(args);if(h.calls.length===1)h.properties.InvocationID='b'.repeat(32);return reply;};await assert.rejects(h.manager.inspect(selection));});
test('P05-PC05: exact managed termination verifies cgroup and profile cleanup',async()=>{const h=harness();await h.manager.inspect(selection);assert.deepEqual(await h.manager.terminate(selection),{terminated:true,profileRemoved:true});assert.ok(h.calls.some(args=>args[0]==='stop'&&args.at(-1)===unit));});
test('P05-PC05: replaced invocation cannot select a termination target',async()=>{const h=harness();await h.manager.inspect(selection);h.properties.InvocationID='b'.repeat(32);await assert.rejects(h.manager.terminate(selection));assert.equal(h.calls.some(args=>args[0]==='stop'),false);});
test('P05-PC07: unit/path/PID/shell substitution and extra fields denied before effects',()=>{for(const bad of [{...selection,unit:'ssh.service'},{...selection,unit:'blindpass-browser@../other.service'},{...selection,unit:'blindpass-browser@x;id.service'},{...selection,pid:412},{...selection,path:'/tmp/profile'},{...selection,uid:0},{...selection,invocation:'claimed'},{...selection,kind:'unknown'}])assert.throws(()=>validateRuntimeSelection(bad));});
test('P05-PC07: private worker rejects extensions and exposes bounded fixed status',async()=>{
  const {runtimeManagementRequest}=await import('../../helpers/login/src/runtime-manager-worker.mjs');
  const h=harness();assert.equal((await runtimeManagementRequest(h.manager,{type:'inspect',version:1,selection})).type,'runtime-verified');
  for(const bad of [{type:'inspect',version:2,selection},{type:'inspect',version:1,selection,source:'P05-PRIVATE-CANARY'},{type:'shell',version:1,selection}])await assert.rejects(runtimeManagementRequest(h.manager,bad));
});

test('P05-PC06: startup recovery stops fixed helper class before browser classes and rejects foreign manager output', async () => {
  const calls = []; const target = 'blindpass-login-helper@0-1-root.service';
  let stopped = false;
  const io = { command: async args => { calls.push(args); if (args[0] === 'stop') { stopped = true; return ''; } return stopped ? '' : `${target} loaded active running helper\n`; },
    lstat: async () => { throw Object.assign(new Error(), { code: 'ENOENT' }); }, readFile: async () => 'populated 0\n', readdir: async () => [], rm: async () => {} };
  const manager = new RuntimeManager(io);
  assert.deepEqual(await manager.recover(), { runtimesStopped: true, backendsRemoved: true });
  assert.ok(calls.some(args => args[0] === 'stop' && args.at(-1) === target));
  const other = new RuntimeManager({ ...io, command: async () => 'ssh.service loaded active running foreign\n' });
  await assert.rejects(other.recover(), { message: 'runtime_management_unavailable' });
});

test('P05-PC06: stale backend recovery rejects nonprivate metadata and never deletes caller paths', async () => {
  let removed = false;
  const io = { command: async () => '', lstat: async () => ({ isDirectory: () => true, isSymbolicLink: () => false, uid: 1000, mode: 0o40700 }), readdir: async () => ['a'.repeat(64)], rm: async () => { removed = true; } };
  await assert.rejects(new RuntimeManager(io).recover()); assert.equal(removed, false);
});
