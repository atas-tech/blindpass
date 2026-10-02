// SPDX-License-Identifier: AGPL-3.0-only
import { Socket } from 'node:net';
import { fstatSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { attachFramedStream } from './browser-transport.mjs';
import { RuntimeManager } from './runtime-manager.mjs';
export async function runtimeManagementRequest(manager,message){
  if(message&&Object.keys(message).sort().join(',')==='type,version'&&message.version===1&&message.type==='recover')return {type:'runtime-recovered',...await manager.recover()};
  if(!message||Object.keys(message).sort().join(',')!=='selection,type,version'||message.version!==1)throw new Error('runtime_management_unavailable');
  if(message.type==='inspect')return {type:'runtime-verified',...await manager.inspect(message.selection)};
  if(message.type==='terminate')return {type:'runtime-terminated',...await manager.terminate(message.selection)};
  throw new Error('runtime_management_unavailable');
}
function main(){
  if(process.getuid()!==0||process.argv.slice(2).join(' ')!=='--socket'||!fstatSync(0).isSocket()||['NODE_OPTIONS','NODE_PATH','DEBUG','PWDEBUG','LD_PRELOAD','LD_LIBRARY_PATH'].some(name=>process.env[name]))process.exit(64);
  const socket=new Socket({fd:0,readable:true,writable:true}),manager=new RuntimeManager();let busy=false,channel;
  channel=attachFramedStream(socket,{receive:async message=>{if(busy){channel.close();return;}busy=true;try{await channel.send(await runtimeManagementRequest(manager,message));}catch{try{await channel.send({type:'runtime-management-unavailable'});}finally{channel.close();}}finally{busy=false;}},onFailure:()=>socket.destroy()});
  for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>channel.close());
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{main();}catch{process.exit(70);}}
