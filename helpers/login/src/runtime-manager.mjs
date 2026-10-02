// SPDX-License-Identifier: AGPL-3.0-only
// Root metadata service; passwords, cookies and administrator material are not inputs.
import { spawn } from 'node:child_process';
import { lstat, stat, readFile, readdir, rm, rmdir } from 'node:fs/promises';
const fail=()=>new Error('runtime_management_unavailable');
const BROWSER='blindpass-browser', HELPER='blindpass-login-helper';
const PROPERTIES=['Id','InvocationID','LoadState','ActiveState','SubState','MainPID','DynamicUser','User','PrivateNetwork','PrivateTmp','PrivateDevices','ProtectSystem','ProtectHome','ProtectControlGroups','NoNewPrivileges','KillMode','SendSIGKILL','LimitCORE','RuntimeDirectory','RuntimeDirectoryMode','FragmentPath','ControlGroup','ExecStart'];
function validUnit(unit,stem){return typeof unit==='string'&&unit.startsWith(stem+'@')&&unit.endsWith('.service')&&unit.length>stem.length+9&&unit.length<=200&&!unit.includes('..')&&/^[A-Za-z0-9_.:@-]+$/.test(unit);}
export function validateRuntimeSelection(value){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='invocation,kind,uid,unit'||!['browser','helper'].includes(value.kind)||!validUnit(value.unit,value.kind==='browser'?BROWSER:HELPER)||!Number.isSafeInteger(value.uid)||value.uid<=0||value.uid>4294967295||!/^[a-f0-9]{32}$/.test(value.invocation))throw fail();return value;}
export async function runRuntimeManagerCommand(args,launch=spawn){return new Promise((resolve,reject)=>{const child=launch('/usr/bin/systemctl',['--system','--no-pager',...args],{env:{PATH:'/usr/bin:/bin',LANG:'C'},stdio:['ignore','pipe','ignore']});let output='',finished=false;const finish=(error)=>{if(finished)return;finished=true;clearTimeout(timer);if(error){child.kill('SIGKILL');reject(fail());}else resolve(output);};const timer=setTimeout(()=>finish(true),6500);child.stdout.on('data',bytes=>{output+=bytes.toString('utf8');if(output.length>65536)finish(true);});child.once('error',()=>finish(true));child.once('close',code=>finish(code!==0&&!(args[0]==='show'&&code===4)));});}
const absent=async(io,path)=>{try{await io.lstat(path);return false;}catch(error){if(error.code==='ENOENT')return true;throw fail();}};
function profilePath(unit){return '/run/blindpass-browser-'+unit.slice((BROWSER+'@').length,-'.service'.length);}
function cgroupPaths(unit){const stem=unit.split('@')[0];return ['/sys/fs/cgroup/system.slice/'+unit,'/sys/fs/cgroup/system.slice/system-'+stem.replaceAll('-','\\x2d')+'.slice/'+unit];}
function properties(body){if(typeof body!=='string'||body.length>16384)throw fail();const result={};for(const line of body.trimEnd().split('\n')){const separator=line.indexOf('=');if(separator<=0)throw fail();const name=line.slice(0,separator);if(!PROPERTIES.includes(name)||Object.hasOwn(result,name))throw fail();result[name]=line.slice(separator+1);}return result;}
function fixedCgroup(value,unit){return typeof value==='string'&&value.startsWith('/system.slice/')&&value.endsWith('/'+unit)&&value.length<512&&!value.includes('..')&&!value.includes('\0')&&/^[A-Za-z0-9_.:@/\\-]+$/.test(value);}
function fragment(value,stem){return ['/etc/systemd/system/','/usr/lib/systemd/system/','/lib/systemd/system/'].some(prefix=>value===prefix+stem+'@.service');}
function fixedExecutable(value,kind){const expected='/usr/lib/blindpass/login/runtime/bin/node /usr/lib/blindpass/login/src/'+(kind==='browser'?'browser-worker.mjs':'worker.mjs --socket');const match=/\bargv\[\]=(.*?) ;/.exec(value??'');return match?.[1]===expected&&value.includes('path=/usr/lib/blindpass/login/runtime/bin/node ;');}
export class RuntimeManager{
  #io;#observed=new Map();
  constructor(io={command:runRuntimeManagerCommand,lstat,stat,readdir,rm,rmdir,readFile:(path)=>readFile(path,'utf8')}){this.#io=io;}
  async #show(unit){return properties(await this.#io.command(['show','--property='+PROPERTIES.join(','),'--',unit]));}
  async #fragment(p,stem){if(!fragment(p.FragmentPath,stem))throw fail();const info=await this.#io.lstat(p.FragmentPath);if(!info.isFile()||info.isSymbolicLink()||info.uid!==0||(info.mode&0o022)!==0)throw fail();}
  async inspect(input){try{const s=validateRuntimeSelection(input),p=await this.#show(s.unit);if(p.Id!==s.unit||p.InvocationID!==s.invocation||p.LoadState!=='loaded'||p.ActiveState!=='active'||p.SubState!=='running'||!/^[1-9][0-9]{0,9}$/.test(p.MainPID)||!fixedCgroup(p.ControlGroup,s.unit)||!fixedExecutable(p.ExecStart,s.kind))throw fail();await this.#fragment(p,s.kind==='browser'?BROWSER:HELPER);
    for(const [key,value] of Object.entries({PrivateTmp:'yes',PrivateDevices:'yes',ProtectSystem:'strict',ProtectHome:'yes',ProtectControlGroups:'yes',NoNewPrivileges:'yes',KillMode:'control-group',SendSIGKILL:'yes',LimitCORE:'0'}))if(p[key]!==value)throw fail();
    const root='/proc/'+p.MainPID, status=await this.#io.readFile(root+'/status'),uidMatch=/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);if(!uidMatch||uidMatch.slice(1).some(value=>Number(value)!==s.uid)||await this.#io.readFile(root+'/cgroup')!=='0::'+p.ControlGroup+'\n')throw fail();
    const cg=await this.#io.stat('/sys/fs/cgroup'+p.ControlGroup);let profile=null;
    if(s.kind==='browser'){if(p.DynamicUser!=='yes'||p.PrivateNetwork!=='yes'||p.RuntimeDirectory!==profilePath(s.unit).slice('/run/'.length)||p.RuntimeDirectoryMode!=='0700')throw fail();const [host,worker]=await Promise.all([this.#io.stat('/proc/self/ns/net'),this.#io.stat(root+'/ns/net')]);if(host.dev===worker.dev&&host.ino===worker.ino)throw fail();
      for(const path of [profilePath(s.unit),profilePath(s.unit)+'/profile']){const info=await this.#io.lstat(path);if(!info.isDirectory()||info.isSymbolicLink()||info.uid!==s.uid||(info.mode&0o7777)!==0o700)throw fail();if(path.endsWith('/profile'))profile={dev:info.dev,ino:info.ino};}}
    else if(p.User!=='blindpass-login'||p.DynamicUser==='yes')throw fail();
    const after=await this.#show(s.unit);if(after.InvocationID!==s.invocation||after.MainPID!==p.MainPID||after.ControlGroup!==p.ControlGroup||after.ActiveState!=='active')throw fail();
    if(this.#observed.size>=64&&!this.#observed.has(s.unit))throw fail();this.#observed.set(s.unit,{...s,cgroup:p.ControlGroup,cgroupDev:cg.dev,cgroupIno:cg.ino,profile});
    return {unit:s.unit,invocation:s.invocation,uid:s.uid,networkIsolated:s.kind==='browser',profilePrivate:s.kind==='browser'};
  }catch{throw fail();}}
  async #gone(unit,cgroup,kind){for(const path of cgroup?[('/sys/fs/cgroup'+cgroup)]:cgroupPaths(unit)){if(!await absent(this.#io,path)){const body=await this.#io.readFile(path+'/cgroup.events');if(!/^populated 0$/m.test(body))return false;}}
    return kind!=='browser'||await absent(this.#io,profilePath(unit));}
  async recover(){try{
    // Root-only startup, before any new dispatch. Helper termination always
    // precedes later account logout. Never accept caller-selected classes/paths.
    for(const stem of [HELPER,'blindpass-browser-supervisor',BROWSER]){
      const list=await this.#io.command(['list-units','--all','--plain','--no-legend',stem+'@*.service']);
      const units=list.trim()?list.trim().split('\n').map(line=>line.trim().split(/\s+/)[0]):[];
      if(units.length>128||units.some(unit=>!validUnit(unit,stem)))throw fail();
      for(const unit of units){await this.#io.command(['stop','--',unit]);if(!await this.#gone(unit,null,stem===BROWSER?'browser':'helper'))throw fail();}
      const after=await this.#io.command(['list-units','--state=running','--plain','--no-legend',stem+'@*.service']);if(after.trim())throw fail();
    }
    const root='/run/blindpass-backends';
    if(!await absent(this.#io,root)){
      const secureDirectory=info=>info.isDirectory()&&!info.isSymbolicLink()&&info.uid===0&&info.gid===0&&(info.mode&0o7777)===0o700;
      if(!secureDirectory(await this.#io.lstat(root)))throw fail();
      const names=await this.#io.readdir(root);if(names.length>128||names.some(name=>!/^[a-f0-9]{64}$/.test(name)))throw fail();
      for(const name of names){const path=root+'/'+name;if(!secureDirectory(await this.#io.lstat(path)))throw fail();const entries=await this.#io.readdir(path);if(entries.some(name=>name!=='cdp.sock'))throw fail();
        if(entries.length){const socket=await this.#io.lstat(path+'/cdp.sock');if(!socket.isSocket()||socket.isSymbolicLink()||socket.uid!==0||socket.gid!==0||(socket.mode&0o7777)!==0o600||socket.nlink!==1)throw fail();await this.#io.rm(path+'/cdp.sock');}
        await this.#io.rmdir(path);
      }
    }
    return {runtimesStopped:true,backendsRemoved:true};
  }catch{throw fail();}}
  async terminate(input){try{const s=validateRuntimeSelection(input),p=await this.#show(s.unit),observed=this.#observed.get(s.unit);if(observed&&(observed.invocation!==s.invocation||observed.uid!==s.uid||observed.kind!==s.kind))throw fail();
    if(p.LoadState==='not-found'||p.ActiveState==='inactive'){if(!await this.#gone(s.unit,observed?.cgroup,s.kind))throw fail();return {terminated:true,profileRemoved:true};}
    if(p.Id!==s.unit||p.InvocationID!==s.invocation||!fixedCgroup(p.ControlGroup,s.unit)||observed&&observed.cgroup!==p.ControlGroup)throw fail();await this.#fragment(p,s.kind==='browser'?BROWSER:HELPER);if(p.KillMode!=='control-group'||p.SendSIGKILL!=='yes')throw fail();
    if(observed){const cg=await this.#io.stat('/sys/fs/cgroup'+p.ControlGroup);if(cg.dev!==observed.cgroupDev||cg.ino!==observed.cgroupIno)throw fail();}
    await this.#io.command(['stop','--',s.unit]);if(!await this.#gone(s.unit,p.ControlGroup,s.kind))throw fail();this.#observed.delete(s.unit);return {terminated:true,profileRemoved:true};
  }catch{throw fail();}}
}
