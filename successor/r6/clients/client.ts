// Public official-SDK client; Node24 performs native TypeScript type stripping.
import fs from 'node:fs';
import readline from 'node:readline';
import {createHash} from 'node:crypto';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {z} from 'zod';
import {bind, canonical, verifyIct, validateDomain, BindingError} from './binding.ts';

const ext='org.example/zti-mcp',protocol='2026-07-28';
const cap={revision:'0.1',profile:'zti-mcp/0.1',mode:'current-online',effect_coupling:'required'};
const statuses=z.enum(['ACTIVE','REVOKED','RESERVED','COMMITTED','CANCELLED','EXPIRED','UNKNOWN','COMPLETED','SUSPENDED']);
const controlSchema=z.object({status:statuses}).passthrough();
const receiptSchema=z.object({profile:z.literal('zti-mcp/0.1'),tenant_id:z.string(),root_mandate_id:z.string(),mandate_id:z.string(),operation_id:z.string(),reservation_id:z.string(),action_hash:z.string().regex(/^[a-f0-9]{64}$/),effect_boundary:z.literal('resource-mutation'),status:z.literal('COMMITTED'),state_revision:z.string().regex(/^(0|[1-9][0-9]*)$/)}).strict();
const write=(value:unknown)=>process.stdout.write(JSON.stringify(value)+'\n');
const arg=(name:string)=>{const i=process.argv.indexOf(name);return i<0?undefined:process.argv[i+1]};

if(arg('--vectors')) {
  const vectors=JSON.parse(fs.readFileSync(arg('--vectors')!,'utf8'));
  write(vectors.map((v:any)=>{try{const row:any={id:v.id,binding:bind(v.input,arg('--mutant'))};try{validateDomain(v.input);row.domain_accepted=true}catch(e){if(e instanceof BindingError)row.domain_error=e.reason;else throw e}return row}catch(e){if(e instanceof BindingError)return{id:v.id,error:e.reason};throw e}}));
} else {
  const settings=JSON.parse(fs.readFileSync(arg('--settings')!,'utf8'));
  const base=new StdioClientTransport({command:settings.python,args:['-I',settings.relay,'--config',settings.config,'--wire',settings.wire,'--lifecycle',settings.lifecycle],stderr:'pipe'});
  let stderr='';base.stderr?.on('data',chunk=>stderr+=chunk.toString());
  const transport:any={onclose:undefined,onerror:undefined,onmessage:undefined,start:()=>base.start(),close:()=>base.close(),send:(message:unknown,options:unknown)=>base.send(message as any,options as any)};
  base.onclose=()=>transport.onclose?.();base.onerror=error=>transport.onerror?.(error);base.onmessage=(message,extra)=>transport.onmessage?.(message,extra);
  const client=new Client(settings.client_info??{name:'zti-r6-typescript',version:'0.3.0'}, {capabilities:{extensions:{[ext]:cap}},versionNegotiation:{mode:{pin:protocol},probe:{timeoutMs:15000,maxRetries:0}},inputRequired:{autoFulfill:false}});
  const asyncErrors:any[]=[];client.onerror=(error:any)=>asyncErrors.push({type:error?.name??'Error',code:error?.code,message:String(error?.message??error)});
  const fileIdentity=(url:URL|string)=>({path:String(url),sha256:createHash('sha256').update(fs.readFileSync(new URL(String(url)))).digest('hex')});
  const loaded={node:process.version,entry:fileIdentity(import.meta.url),binding:fileIdentity(new URL('./binding.ts',import.meta.url)),runtime_lock:fileIdentity(new URL('./runtime-lock.json',import.meta.url)),sdk_entry:fileIdentity(import.meta.resolve('@modelcontextprotocol/client'))};
  const pending=new Set<Promise<void>>();
  try {
    await client.connect(transport);
    if(client.getNegotiatedProtocolVersion()!==protocol)throw Error('Pinned modern protocol was not selected');
    const discovery=await client.discover({timeout:15000});
    if(JSON.stringify(discovery.supportedVersions)!==JSON.stringify([protocol])||canonical(discovery.capabilities?.extensions?.[ext])!==canonical(cap))throw Error('Modern extension discovery is incompatible');
    write({type:'ready',client:'T',protocol:client.getNegotiatedProtocolVersion(),discovery,loaded});
    const execute=async(command:any)=>{
      const reply:any={id:command.id,client:'T'};
      try {
        const {method}=command,params=command.params??{};
        const action=command.binding_action??(method.endsWith('.reserve')?params.action:undefined);
        if(action!==undefined) {try{reply.binding=bind(action,settings.mutant)}catch(e){if(e instanceof BindingError)reply.binding_error=e.reason;else throw e}}
        if(method==='bind') {reply.binding=bind(command.action,settings.mutant);reply.result={bound:true};}
        else if(method==='server/discover')reply.result=await client.discover({timeout:30000});
        else if(method==='tools/list')reply.result=await client.listTools();
        else if(method==='tools/call') {
          const result=await client.callTool(params,{timeout:30000});
          const receipt=receiptSchema.parse(result._meta?.[ext]);
          const structured=z.object({receipt:receiptSchema,result:z.record(z.string(),z.unknown())}).strict().parse(result.structuredContent);
          if(JSON.stringify(structured.receipt)!==JSON.stringify(receipt))throw Error('Tool receipt differs between result surfaces');
          reply.result=result;
        } else {
          reply.result=await client.request({method,params},controlSchema,{timeout:30000});
          if(method.endsWith('.reserve')&&reply.result.ict) {
            try { reply.permit_verification=verifyIct(reply.result.ict,settings.public_keys.KP,settings.context,settings.principal,reply.binding); }
            catch(error) { throw new BindingError('INVALID_TOKEN'); }
          }
        }
        if(method==='tools/call'&&reply.result&&reply.binding&&reply.result._meta[ext].action_hash!==reply.binding.action_hash)throw Error('Receipt differs from client-computed action hash');
      } catch(e:any) {
        if(e instanceof BindingError) {delete reply.result;reply.local_error={type:'BindingError',reason:e.reason};}
        else if(typeof e?.code==='number'&&e?.name!=='SdkError')reply.error={code:e.code,message:e.message,...(e.data!==undefined?{data:e.data}:{})};
        else {delete reply.result;reply.transport_error={type:e?.name??'Error',message:String(e?.message??e)}}
      }
      write(reply);
    };
    const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
    for await(const line of lines) {
      const command=JSON.parse(line);
      if(command.method==='close')break;
      const task=execute(command);pending.add(task);task.finally(()=>pending.delete(task));
    }
    await Promise.all(pending);
  } finally {
    const launcherPid=base.pid;
    try { await client.close(); } finally {
      if(settings.stderr)fs.writeFileSync(settings.stderr,stderr);
      if(settings.client_events)fs.writeFileSync(settings.client_events,JSON.stringify({asyncErrors,transport_launcher_pid:launcherPid,loaded})+'\n');
    }
  }
}
