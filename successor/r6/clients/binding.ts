// Independent client implementation of the explicitly bounded canonical domain.
import {createHash,createPublicKey,verify} from 'node:crypto';

export class BindingError extends Error {
  reason:string;
  constructor(reason:string) { super(reason);this.reason=reason; }
}
const refuse=(reason='BINDING_MISMATCH'):never=>{throw new BindingError(reason)};
function validString(value:string):void {
  for(let i=0;i<value.length;i++) {
    const c=value.charCodeAt(i);
    if(c>=0xd800&&c<=0xdbff) {const n=value.charCodeAt(++i);if(!(n>=0xdc00&&n<=0xdfff))refuse();}
    else if(c>=0xdc00&&c<=0xdfff)refuse();
  }
}
export function canonical(value:unknown):string {
  if(value===null||typeof value==='boolean')return JSON.stringify(value);
  if(typeof value==='number') {if(!Number.isSafeInteger(value))refuse();return JSON.stringify(value);}
  if(typeof value==='string') {validString(value);return JSON.stringify(value);}
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype) {
    const keys=Object.keys(value).sort();
    if(keys.some(k=>!/^[\x00-\x7f]*$/.test(k)))refuse();
    return '{'+keys.map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
  }
  return refuse();
}
export function bind(action:Record<string,any>, mutant?:string):Record<string,unknown> {
  let input=action;
  if(mutant==='M01')input={...action,arguments:{...action.arguments,quantity:String(Number(action.arguments.quantity))}};
  const raw=canonical(input),args=input.arguments;
  if(!args||Array.isArray(args)||typeof args!=='object'||Object.keys(args).sort().join(',')!=='label,quantity,tags')refuse();
  const q=args.quantity;
  if(typeof q!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(q)||BigInt(q)>18446744073709551615n)refuse('CONSTRAINT_VIOLATION');
  if(typeof args.label!=='string'||Buffer.byteLength(args.label,'utf8')>256)refuse('CONSTRAINT_VIOLATION');
  const tags=args.tags;
  if(!Array.isArray(tags)||tags.length>8||tags.some(t=>typeof t!=='string'||!['red','blue','neutral'].includes(t))||new Set(tags).size!==tags.length)refuse('CONSTRAINT_VIOLATION');
  return {canonical_utf8_base64:Buffer.from(raw,'utf8').toString('base64'),action_hash:createHash('sha256').update(raw,'utf8').digest('hex'),
    costs:{ops:{unit:'operation',amount:q},bytes:{unit:'byte',amount:String(Buffer.byteLength(args.label,'utf8'))}},facts:[...tags].sort()};
}

export function validateDomain(action:any):void {
  if(!action||action.method!=='tools/call'||action.tool_name!=='demo.add_record'||action.tool_revision!=='1')throw new BindingError('BINDING_MISMATCH');
}

export function verifyIct(token:string,jwk:any,context:any,principal:string,binding:any):Record<string,unknown> {
  const decode=(segment:string)=>{if(!/^[A-Za-z0-9_-]+$/.test(segment))throw Error('Invalid compact JWS encoding');const raw=Buffer.from(segment,'base64url');if(raw.toString('base64url')!==segment)throw Error('Noncanonical JWS segment');return raw};
  const parts=token.split('.');if(parts.length!==3)throw Error('Invalid compact JWS');
  const [h,p,s]=parts,header=JSON.parse(decode(h).toString('utf8')),claims=JSON.parse(decode(p).toString('utf8')),signature=decode(s);
  if(canonical(header)!==canonical({alg:'ES256',typ:'zti-ict+jwt',kid:context.permit_kid})||signature.length!==64)throw Error('Invalid permit header/signature shape');
  if(!verify('sha256',Buffer.from(h+'.'+p,'ascii'),{key:createPublicKey({key:jwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},signature))throw Error('Invalid permit signature');
  if(claims.iss!==context.permit_issuer||claims.aud!==context.executor_id||claims.sub!==principal)throw Error('Wrong permit key context');
  if(['iat','nbf','exp'].some(k=>!Number.isSafeInteger(claims[k])||claims[k]<0)||!(claims.iat<=claims.nbf&&claims.nbf<claims.exp)||claims.exp-claims.iat>60)throw Error('Invalid permit integer dates');
  if(claims.zti.action_hash!==binding.action_hash||canonical(claims.zti.cost_bounds)!==canonical(binding.costs)||canonical(claims.zti.facts)!==canonical(binding.facts))throw Error('Permit differs from client-computed binding');
  return {signature_valid:true,kid:header.kid,action_hash:claims.zti.action_hash};
}
