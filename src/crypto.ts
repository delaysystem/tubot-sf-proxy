const encoder = new TextEncoder();
export async function digest(value: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
}
export function equalDigest(a:string,b:string):boolean {
  if (a.length !== 64 || b.length !== 64) return false;
  return crypto.subtle.timingSafeEqual(encoder.encode(a),encoder.encode(b));
}
async function key(secret:string):Promise<CryptoKey> {
  if (!secret) throw new Error('proxy_encryption_not_configured');
  const bytes=Uint8Array.from(atob(secret),c=>c.charCodeAt(0));
  if(bytes.length!==32) throw new Error('proxy_encryption_key_invalid');
  return crypto.subtle.importKey('raw',bytes,'AES-GCM',false,['encrypt','decrypt']);
}
export async function seal(secret:string,context:string,value:unknown):Promise<string> {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encoder.encode(context)},await key(secret),encoder.encode(JSON.stringify(value))));
  return JSON.stringify({v:1,iv:Array.from(iv),ct:btoa(String.fromCharCode(...ciphertext))});
}
export async function open<T>(secret:string,context:string,value:string):Promise<T> {
  const envelope=JSON.parse(value);
  if(envelope.v!==1 || !Array.isArray(envelope.iv) || envelope.iv.length!==12 || typeof envelope.ct!=='string') throw new Error('invalid_proxy_envelope');
  const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(envelope.iv),additionalData:encoder.encode(context)},await key(secret),Uint8Array.from(atob(envelope.ct),c=>c.charCodeAt(0)));
  return JSON.parse(new TextDecoder().decode(plaintext));
}
export async function boundedBody(request:Request,max=65536):Promise<string> {
  if(Number(request.headers.get('Content-Length')||0)>max) throw new Error('body_too_large');
  const reader=request.body?.getReader(); if(!reader) return '';
  const chunks:Uint8Array[]=[];let length=0;
  while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>max){await reader.cancel();throw new Error('body_too_large');}chunks.push(value);}
  const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return new TextDecoder('utf-8',{fatal:true,ignoreBOM:false}).decode(bytes);
}
