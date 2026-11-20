import {DurableObject,WorkerEntrypoint} from 'cloudflare:workers';
import {Server} from 'partyserver';
import type {Connection,WSMessage} from 'partyserver';
import {validScope,validConfig,validSessionHandoffState,AGENT_TEXT_MAX,type TenantScope,type ProxyConfig,type Registration,type Broker,type AgentService,type AgentTurnResult} from './contracts';
import {digest,equalDigest,seal,open,boundedBody} from './crypto';
import {ipLimitForEndpoint,normalizeClientIp,rateMinute} from './rate-limit';
import {signedBroker} from './rpc-sign';
import {signedAgent} from './agent-sign';

interface ProxyEnv {
  REGISTRATIONS:DurableObjectNamespace<ProxyRegistration>;
  SF_BROKER:Broker;
  SF_AUTH_CALLER_KEY:string;
  AGENT_RPC_KEY:string;
  PROXY_ENCRYPTION_KEY:string;
  PROXY_PUBLIC_ORIGIN:string;
  AGENTCODE?:AgentService;
  /** Opt-in 202-async accept: '1'/'on'/'true'/'yes' releases the client
   * right after verify+handoff pass and runs the agent turn via the alarm
   * path. Unset/anything else keeps the held inline executor. */
  ASYNC_ACCEPT?:string;
  /** Verify-late accept (async-only): '1'/'on'/'true'/'yes' parks the turn
   * after light checks + handoff WITHOUT the transcript verify, and the
   * alarm executor proves the transcript concurrently with the agent turn,
   * gating the submit on the proof. Requires ASYNC_ACCEPT (inline keeps
   * serial verify). Unset/anything else keeps accept-time verify. */
  VERIFY_LATE?:string;
  /** Verify-late poll budget in ms (ops tuning): how long the executor's
   * tight verify poll waits for a short-transient proof before requeueing.
   * Positive integer; unparseable/absent keeps the default. */
  VERIFY_LATE_BUDGET_MS?:string;
}
// 202-async gate. Opt-IN (inverted vs the kill switches): only an explicit
// on-value changes behavior, so production keeps the held path by default.
const asyncAccept=(env:ProxyEnv)=>typeof env.ASYNC_ACCEPT==='string'&&['1','on','true','yes'].includes(env.ASYNC_ACCEPT.trim().toLowerCase());
// Verify-late gate. Opt-IN like ASYNC_ACCEPT: only explicit on-values move
// the transcript verify to the executor; production keeps accept-time proof.
const verifyLate=(env:ProxyEnv)=>typeof env.VERIFY_LATE==='string'&&['1','on','true','yes'].includes(env.VERIFY_LATE.trim().toLowerCase());
// Late-verify tight poll cadence (ms). The entries-visibility lag p50 is
// 4.1s (Oct-29 baseline, headerCustom SEND_BURST_POLL_MS rationale); 750ms
// lands ~5 probes across it instead of burning exponential client backoffs.
const VERIFY_LATE_POLL_MS=750;
// Late-verify poll budget default (ms): ~3x the 4.1s visibility-lag p50 so
// short-transient proofs (session_pending, transcript_mismatch) resolve
// inside one alarm pass; exhaustion requeues through the normal backoff.
const VERIFY_LATE_BUDGET_DEFAULT_MS=12000;
const verifyLateBudgetMs=(env:ProxyEnv):number=>{
  const raw=typeof env.VERIFY_LATE_BUDGET_MS==='string'?Number(env.VERIFY_LATE_BUDGET_MS.trim()):NaN;
  return Number.isFinite(raw)&&raw>0?Math.floor(raw):VERIFY_LATE_BUDGET_DEFAULT_MS;
};
// Short-transient verify codes: healed within seconds by platform commit
// lag, so the executor overlaps the agent turn with the wait. binding_absent
// is deliberately absent: routing binds minutes after session create, so it
// requeues WITHOUT agent spend. Anything else non-verified is permanent.
const VERIFY_LATE_SHORT_TRANSIENT=new Set(['session_pending','transcript_mismatch']);
const sleep=(ms:number)=>new Promise<void>(done=>setTimeout(done,ms));
type Turn={conversationId:string;messageId:string;text:string;channelId?:string;orgId?:string;linked?:Record<string,string>;
  /** Verify-late marker + visitor reference (sealed at accept when late):
   * the executor proves the transcript before submitting. Absent on legacy
   * rows (accept-verified under previous code) — never re-verified. */
  reference?:string;verifyLate?:true};
type Visitor={token_hash:string;reference:string;conversation_id:string|null;agent_session?:string|null;created_at:number;expires_at:number};
// Per-socket auth state, persisted in the WebSocket attachment so it
// survives hibernation wake-ups (PartyServer rehydrates it per message).
// Only the token hash is kept: every frame re-reads the visitor row, so
// expiry and revocation apply immediately, exactly like a fresh POST.
type WsSocketState={authed:false}|{authed:true;tokenHash:string};
// WebSocket frame protocol version (first-frame auth + turn frames). Bump on
// any wire change; mismatched clients fail closed with protocol_mismatch and
// fall back to POST. Origin: new with the PartyServer conversion.
const WS_PROTOCOL_VERSION=1;
// Maximum inbound WS frame size (bytes). The longest legal turn is 4096 chars
// of text plus envelope and linked context (~2KB); 8KB bounds per-message
// parse work with headroom. Origin: 2x the worst legal turn.
const WS_MAX_FRAME_BYTES=8192;
// Send-hint correlation window (ms). A turn served within this long after a
// hint for the same conversation is marked hinted:true on its accept frame,
// proving the LWC capture fired ahead of the turn. Covers the ~9-11s live
// verify->agent->submit round trip plus slack. Origin: 1.5x the live round.
const HINT_WINDOW_MS=15000;
// Cap for the in-memory hint table (conversationId -> last hint ts). Lossy by
// design: eviction only undercounts hinted marks, never misroutes a turn.
const MAX_HINT_ENTRIES=1000;
/** Client-supplied linked context (headerCustom): bounded string map. Shape
 * only — agentcode re-verifies every value against live Salesforce before
 * it initializes an agent, so spoofed values cannot survive. */
const LINKED_KEY_RE=/^[A-Za-z][A-Za-z0-9_]{0,63}$/;
function parseLinkedContext(raw:unknown):Record<string,string>|undefined{
  if(raw===undefined)return undefined;
  if(typeof raw!=='object'||raw===null||Array.isArray(raw))throw new Error('invalid_linked');
  const entries=Object.entries(raw as Record<string,unknown>);
  if(entries.length>16)throw new Error('invalid_linked');
  let total=0;
  for(const [k,v]of entries){
    if(!LINKED_KEY_RE.test(k)||typeof v!=='string'||!v.length||v.length>256)throw new Error('invalid_linked');
    total+=k.length+v.length;
    if(total>2048)throw new Error('invalid_linked');
  }
  return Object.fromEntries(entries) as Record<string,string>;
}
type EventRow={id:string;fingerprint:string;state:string;payload:string|null;request_id:string|null;attempts:number;next_at:number;created_at:number;error:string|null};
type HandoffReason='agent_verdict'|'escalated'|'queue_mismatch';
const handoffReasonOf=(v:unknown):HandoffReason=>v==='escalated'||v==='queue_mismatch'||v==='agent_verdict'?v:'agent_verdict';
// Accept-side handoff cache window (ms) and size bound. Bounds stale-null
// exposure to one conversation's back-to-back turns; the async executor's
// live re-check is the backstop (mid-window handoffs suppress there), and
// positives latch durably, so a longer window only risks extra suppressed
// passes, never a wrong answer. 30s ≈ one lively turn cluster.
const HANDOFF_ACCEPT_CACHE_MS=30000;
const HANDOFF_ACCEPT_CACHE_MAX=1000;
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
// Visitor session windows (ms). The 30-min idle TTL slides on every
// authenticated /browser/* hit (/session, /sync, /echo); the 8h absolute cap
// never slides. Origin: pre-existing literals in the /session branch below.
const VISITOR_IDLE_TTL_MS=1800000;
const VISITOR_MAX_AGE_MS=28800000;
// Sliding-refresh write amortization: /sync and /echo rewrite expires_at
// only when less than this remains, so steady 2.5s polling costs ~1 write
// per 20 min per visitor instead of 24/min.
const VISITOR_REFRESH_THRESHOLD_MS=600000;
// Optional browser-client version tag (LWC ECHO_CLIENT_VERSION) so cached
// bundle versions stay identifiable in request payloads. Accepted and
// ignored everywhere: old clients omit it, mistyped values 400 like any
// other malformed field.
const clientVersion=/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
// Widget-relay source tag. The E2E harness marks its browser-relay turns
// with X-Tubot-Harness (or the legacy X-Test-Browser marker); the V1 host
// snippet (no LWC relay: it POSTs /browser/echo directly) marks its turns
// with X-Tubot-Relay: snippet. Derived per request from headers only, never
// invented: absent markers mean the live LWC path produced the turn.
type RelaySource='lwc'|'harness'|'snippet';
const relaySourceOf=(request:Request):RelaySource=>{
  if(((request.headers.get('x-tubot-harness')||'').trim()||(request.headers.get('x-test-browser')||'').trim()))return 'harness';
  return (request.headers.get('x-tubot-relay')||'').trim().toLowerCase()==='snippet'?'snippet':'lwc';
};
const reply=(error:string,status:number)=>Response.json({error},{status,headers:{'Cache-Control':'no-store'}});
const sameScope=(a:TenantScope,b:TenantScope)=>a.teamId===b.teamId&&a.orgId===b.orgId&&a.channelId===b.channelId;
const authed=(env:ProxyEnv)=>signedBroker(env.SF_BROKER,env.SF_AUTH_CALLER_KEY);
// Agent-only result shaping, shared by the inline executor and the durable
// alarm. Accepts only the agreed result shape so agent internals can never
// leak into responses or storage; null means invalid (retry, never submit).
const shapeAgentResult=(turn:unknown):{handoff:true;spans:Record<string,number|string>}|{released:true;spans:Record<string,number|string>}|{handoff:false;reply:string;spans:Record<string,number|string>}|null=>{
  const shaped=(turn&&typeof turn==='object'?turn:{}) as Partial<AgentTurnResult>;
  const spans:Record<string,number|string>={};
  if(shaped.spans&&typeof shaped.spans==='object'&&!Array.isArray(shaped.spans))
    for(const [k,v] of Object.entries(shaped.spans)){
      if(Object.keys(spans).length>=8)break;
      // Numeric attribution passes through; the winning-rung ids ride as two
      // allowlisted short strings so fallback wins stay visible in accepts.
      if(typeof v==='number'&&Number.isFinite(v)&&/^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(k))spans[k]=v;
      else if((k==='provider'||k==='model')&&typeof v==='string'&&v.length>0&&v.length<=96&&/^[A-Za-z0-9_.:@/-]+$/.test(v))spans[k]=v;
    }
  if(shaped.handoff===true)return {handoff:true as const,spans};
  if((shaped as {released?:unknown}).released===true)return {released:true as const,spans};
  const shapedReply=typeof shaped.reply==='string'?shaped.reply:'';
  if(!shapedReply.length||shapedReply.length>AGENT_TEXT_MAX)return null;
  return {handoff:false as const,reply:shapedReply,spans};
};
// B4 proxy outbox budget guard. The alarm used to retry every failed agent
// turn until the 24h deadline; a deterministically-failing turn (live proof:
// 8 identical LINKED_BINDING_OR_DEFAULT_INVALID:ContactId retries in
// .scratch/tail/proxy-run60.jsonl) burned a full agentcode turn every 5min.
// TERMINAL_ALARM_CAUSES parks do-not-retry failures on the first alarm pass:
// LINKED_* (agentcode rejects this exact sealed turn against this exact agent
// config, so no retry can ever succeed) plus this worker's own terminal
// validation/auth-shape errors (ingress answers them 4xx/403, never retries;
// a NULL/corrupt sealed payload or a misconfigured static key cannot heal).
const TERMINAL_ALARM_CAUSES=new Set(['missing_encrypted_turn','invalid_proxy_envelope','invalid_linked',
  'proxy_encryption_not_configured','proxy_encryption_key_invalid',
  'rpc_caller_key_not_configured','rpc_org_not_configured',
  // Verify-late permanent proof failure: the sealed turn's visitor text is
  // not service truth (forged or rotated), so no retry can ever submit it.
  'verify_rejected']);
// Attempt budget for transient failures. Backoff (2s doubling from row
// attempts) hits the 5min cap at attempt 8, so 30 attempts span ~2h
// wall-clock: a 30min SF outage consumes ~12 attempts, leaving 2.5x margin,
// while a deterministically-failing turn burns 30 agent turns instead of
// ~288 over the 24h deadline. The deadline stays the backstop. Submitted-row
// status polls are exempt: they are cheap broker reads (no LLM spend) and
// already inflate attempts on the 2s success poll, so a budget there would
// wedge slow confirmations.
const MAX_ALARM_ATTEMPTS=30;

// waitUntil fast path backstop: turns parked by #parkForExecutor run first on
// the hot isolate via ctx.waitUntil (saves ~1.5s of alarm scheduling, measured
// live 2026-10-31). The alarm stays armed at this horizon as the durable
// backstop in case the isolate dies mid-waitUntil. Must exceed any realistic
// hot-isolate turn (agent 8s tail + verify-late + submit leg ~30s worst).
const WAITUNTIL_BACKSTOP_MS=60_000;

// Kept for the existing v1 migration. It has no public endpoint.
export class MyDurableObject extends DurableObject {}

/** Only bound Panel services can invoke this entrypoint. */
export class ProxyAdmin extends WorkerEntrypoint<ProxyEnv> {
  async register(input:TenantScope&ProxyConfig&{secureKeys:string[]}):Promise<{id:string;baseUrl:string}> {
    if(!validScope(input)||!validConfig(input)||!Array.isArray(input.secureKeys)||input.secureKeys.length<1||input.secureKeys.length>3||
      input.secureKeys.some(k=>typeof k!=='string'||k.length<32||k.length>256||/\s/.test(k))) throw new Error('invalid_proxy_registration');
    const origin=new URL(this.env.PROXY_PUBLIC_ORIGIN);
    if(origin.protocol!=='https:'||origin.pathname!=='/'||origin.username||origin.password||origin.search||origin.hash) throw new Error('proxy_origin_not_configured');
    // Exercise encryption before accepting any registration.
    await seal(this.env.PROXY_ENCRYPTION_KEY,'registration-check',{});
    const {scrtOrigin,browser}=await authed(this.env).validate(input,input);
    if(input.browserDeploymentName&&!browser)throw new Error('proxy_broker_browser_config_missing');
    const id=crypto.randomUUID();
    const registration:Registration={id,teamId:input.teamId,orgId:input.orgId,channelId:input.channelId,
      deploymentName:input.deploymentName,...(input.browserDeploymentName?{browserDeploymentName:input.browserDeploymentName,browser}:{}),action:input.action,
      ...(input.agentName!==undefined?{agentName:input.agentName}:{}),...(input.agentMode!==undefined?{agentMode:input.agentMode}:{}),
      ...(input.expectedQueueName!==undefined?{expectedQueueName:input.expectedQueueName}:{}),
      scrtOrigin,createdAt:Date.now(),disabled:false,
      keyHashes:await Promise.all(input.secureKeys.map(k=>digest(`${id}\n${k}`)))};
    try{await this.env.REGISTRATIONS.getByName(id).configure(registration);}catch{throw new Error('proxy_broker_registration_storage_failed');}
    return {id,baseUrl:`${origin.origin}/p/${id}`};
  }
  async inspect(scope:TenantScope,id:string):Promise<unknown> {
    if(!validScope(scope)||!uuid.test(id))throw new Error('invalid_proxy_scope');
    return this.env.REGISTRATIONS.getByName(id).inspect(scope);
  }
  async revoke(scope:TenantScope,id:string):Promise<void> {
    if(!validScope(scope)||!uuid.test(id))throw new Error('invalid_proxy_scope');
    await this.env.REGISTRATIONS.getByName(id).revoke(scope);
  }
}

/** One durable, encrypted outbox per registered tenant channel route. Served
 * HTTP exactly as before plus a PartyServer WebSocket transport on
 * /browser/ws. PartyServer's Server is a DurableObject subclass: ctx, env,
 * alarms, and RPC methods behave identically; only WS upgrades route into
 * super.fetch, so the POST hot path never touches PartyServer init. */
export class ProxyRegistration extends Server<ProxyEnv&Cloudflare.Env> {
  // Hibernate with the isolate: sockets stay connected while idle and the DO
  // wakes per message, so an open-but-quiet widget burns no billable duration.
  static options={hibernate:true};
  // In-memory send-hint table only (no storage: hints are telemetry, and a
  // lost entry merely drops a hinted mark, never a turn).
  #hintTs=new Map<string,number>();
  // Accept-side handoff verdict cache (async paths only — the alarm executor
  // re-checks live, so a stale null here only costs one suppressed pass, and
  // positives latch durably anyway). Resident-memory only: eviction drops to
  // live reads, never to wrong answers.
  #handoffCache=new Map<string,{reason:HandoffReason|null;at:number}>();
  #initialize():void {
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,state TEXT NOT NULL,payload TEXT,request_id TEXT,attempts INTEGER NOT NULL DEFAULT 0,next_at INTEGER NOT NULL,created_at INTEGER NOT NULL,error TEXT)`);
    this.ctx.storage.sql.exec('CREATE INDEX IF NOT EXISTS events_due ON events(state,next_at)');
    this.#ensureRelaySources();
  }
  // Per-turn relay-source marks for browser (widget-relay) outbox rows only.
  // Separate table so pre-existing deployments migrate without ALTER: rows
  // without a mark predate tracking (or arrived via the SCRT inbound path)
  // and inspect reports them honestly as unmarked.
  #ensureRelaySources():void {
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS relay_sources(event_id TEXT PRIMARY KEY,source TEXT NOT NULL,created_at INTEGER NOT NULL)');
  }
  async configure(registration:Registration):Promise<void>{
    if(await this.ctx.storage.get('config'))throw new Error('proxy_already_exists');
    this.#initialize();
    await this.ctx.storage.put('config',registration);
  }
  async #config():Promise<Registration|null>{return await this.ctx.storage.get<Registration>('config')||null;}
  async inspect(scope:TenantScope):Promise<unknown>{
    const config=await this.#config();if(!config||!sameScope(config,scope))throw new Error('proxy_not_found');
    this.#ensureRelaySources();
    const lastOutboxTs=this.ctx.storage.sql.exec<{ts:number|null}>('SELECT MAX(created_at) AS ts FROM events').one().ts??null;
    const relaySource=this.ctx.storage.sql.exec<{source:string}>('SELECT source FROM relay_sources ORDER BY created_at DESC LIMIT 1').toArray()[0]?.source??null;
    return {id:config.id,disabled:config.disabled,createdAt:config.createdAt,
      lastOutboxTs,relaySource,
      suppressedHandoffTurns:(await this.ctx.storage.get<number>('handoff_suppressed_total'))??0,
      handoffLookupUnreachableTotal:(await this.ctx.storage.get<number>('handoff_lookup_unreachable_total'))??0,
      handoffLookupInvalidTotal:(await this.ctx.storage.get<number>('handoff_lookup_invalid_total'))??0,
      counts:this.ctx.storage.sql.exec('SELECT state,COUNT(*) AS count FROM events GROUP BY state').toArray(),
      recent:this.ctx.storage.sql.exec('SELECT e.id,e.state,e.request_id,e.attempts,e.error,e.created_at,r.source AS relay_source FROM events e LEFT JOIN relay_sources r ON r.event_id=e.id ORDER BY e.created_at DESC LIMIT 20').toArray()};
  }
  async revoke(scope:TenantScope):Promise<void>{
    const config=await this.#config();if(!config||!sameScope(config,scope))throw new Error('proxy_not_found');
    await this.ctx.storage.put('config',{...config,disabled:true,keyHashes:[]});
    this.ctx.storage.sql.exec("UPDATE events SET state='revoked',payload=NULL WHERE state IN ('forwarding','echo_pending','agent_pending','submitted')");
    await this.ctx.storage.deleteAlarm();
  }
   #event(id:string):EventRow|undefined{return this.ctx.storage.sql.exec<EventRow>('SELECT * FROM events WHERE id=?',id).toArray()[0];}
  // Alarm-immediacy: default delay 0 (was 1000). Every default-call site
  // parks work that should run NOW (async accept, inline fallback,
  // forwarding transition); the old 1s grace added a full second to every
  // async turn for no batching benefit (alarms coalesce per-DO anyway).
  // Explicit-delay callers (status polls, retries) are untouched, and the
  // end-of-alarm reschedule keeps its +1000 floor against hot loops.
  async #schedule(delay=0):Promise<void>{
    const current=await this.ctx.storage.getAlarm();const due=Date.now()+delay;
    if(current===null||current>due)await this.ctx.storage.setAlarm(due);
  }
  // Handoff guard: a session that left the tubot queue is still routed and
  // read, but never answered. The latch records conversations this route has
  // already seen hand off (agent verdict or a prior suppression); the live
  // lookup covers SF-side-only handoffs via the broker's sessionState RPC.
  // The expected queue comes only from the per-route registration (set at
  // register time per org/route); absent means the queue comparison is
  // skipped. Fail-open is kept ONLY for a genuinely unreachable broker
  // (timeout or RPC throw, logged plus counted below) and for unknown
  // sessions (null: not yet created or unreadable, quiet by design since
  // every fresh session passes through it); only positive handoff evidence
  // suppresses. Malformed broker shapes fail open too but are counted
  // separately so a broker bug can never hide inside the unreachable total.
  #handoffAcceptCached(config:Registration,conversationId:string):Promise<HandoffReason|null>{
    const hit=this.#handoffCache.get(conversationId);
    if(hit&&Date.now()-hit.at<HANDOFF_ACCEPT_CACHE_MS)return Promise.resolve(hit.reason);
    return this.#isHandedOff(config,conversationId).then(reason=>{
      if(this.#handoffCache.size>=HANDOFF_ACCEPT_CACHE_MAX)this.#handoffCache.clear();
      this.#handoffCache.set(conversationId,{reason,at:Date.now()});
      return reason;
    });
  }
  // Sync latch read (local SQLite, no SF): lets executors suppress latched
  // conversations before starting any async work (no agent spend, no SF
  // reads). Single implementation shared with the live check below.
  #handoffLatch(conversationId:string):HandoffReason|null{
    const sql=this.ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS handoffs(conversation_id TEXT PRIMARY KEY,reason TEXT NOT NULL,created_at INTEGER NOT NULL)');
    const latched=sql.exec<{reason:string}>('SELECT reason FROM handoffs WHERE conversation_id=?',conversationId).toArray()[0];
    return latched?handoffReasonOf(latched.reason):null;
  }
  async #isHandedOff(config:Registration,conversationId:string):Promise<HandoffReason|null>{
    const latchedReason=this.#handoffLatch(conversationId);
    if(latchedReason)return latchedReason;
    let supported=false;
    try{supported=typeof (this.env.SF_BROKER as unknown as {sessionState?:unknown}).sessionState==='function';}catch{supported=false;}
    if(!supported)return null;
    try{
      const sessionState=authed(this.env).sessionState;
      if(typeof sessionState!=='function')return null;
      const raced=await Promise.race([
        sessionState(config,conversationId).then(v=>({ok:true as const,v}),e=>({ok:false as const,e})),
        new Promise<null>(resolve=>setTimeout(()=>resolve(null),5000)),
      ]);
      if(raced===null){await this.#countLookup(config,conversationId,'timeout');return null;}
      if(!raced.ok){
        const msg=raced.e instanceof Error?raced.e.message:String(raced.e);
        await this.#countLookup(config,conversationId,msg.includes('rpc_unauthorized')||msg.includes('rpc_caller_key')?'auth':'error',msg);
        return null;
      }
      const state=raced.v;
      if(state===null||state===undefined)return null;
      if(!validSessionHandoffState(state)){await this.#countLookup(config,conversationId,'invalid');return null;}
      if(state.escalated===true)return 'escalated';
      if(config.expectedQueueName&&state.queueName&&state.queueName!==config.expectedQueueName)return 'queue_mismatch';
      return null;
    }catch(e){
      const msg=e instanceof Error?e.message:String(e);
      await this.#countLookup(config,conversationId,msg.includes('rpc_unauthorized')||msg.includes('rpc_caller_key')?'auth':'error',msg);
      return null;
    }
  }
  // Degraded live lookup: bump the durable counter and emit the explicit
  // log. Unreachable covers timeout/RPC-throw (auth failures classified as
  // their own cause); invalid covers malformed broker shapes. No message
  // text; the code is a bounded broker error code, never session content.
  async #countLookup(config:Registration,conversationId:string,cause:'timeout'|'error'|'auth'|'invalid',code?:string):Promise<void>{
    const key=cause==='invalid'?'handoff_lookup_invalid_total':'handoff_lookup_unreachable_total';
    const total=((await this.ctx.storage.get<number>(key))??0)+1;
    await this.ctx.storage.put(key,total);
    console.log(JSON.stringify({event:'handoff_lookup_degraded',route:config.id,org:config.orgId,channel:config.channelId,
      conversationId,cause,...(code?{code:code.slice(0,80)}:{}),total}));
  }
  async #latchHandoff(conversationId:string,reason:HandoffReason):Promise<void>{
    const sql=this.ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS handoffs(conversation_id TEXT PRIMARY KEY,reason TEXT NOT NULL,created_at INTEGER NOT NULL)');
    sql.exec('INSERT OR IGNORE INTO handoffs(conversation_id,reason,created_at) VALUES(?,?,?)',conversationId,reason,Date.now());
  }
  // Parks a suppressed turn: latch the conversation, terminal-park the row
  // (no payload, no request id: nothing was or will be sent), bump the
  // durable counter, and emit the explicit suppression log. No message text.
  async #suppressTurn(config:Registration,rowId:string,conversationId:string,reason:HandoffReason):Promise<void>{
    await this.#latchHandoff(conversationId,reason);
    this.ctx.storage.sql.exec("UPDATE events SET state='handed_off',payload=NULL,error='suppressed_after_handoff' WHERE id=?",rowId);
    const total=((await this.ctx.storage.get<number>('handoff_suppressed_total'))??0)+1;
    await this.ctx.storage.put('handoff_suppressed_total',total);
    console.log(JSON.stringify({event:'handoff_turn_suppressed',route:config.id,org:config.orgId,channel:config.channelId,conversationId,reason,total}));
  }
  // Local rate gates (shared route budget + per-IP endpoint budget). Runs
  // before any cross-worker call so floods never reach the broker. A null
  // request skips the per-IP section (WS frames: the upgrade was already
  // per-IP gated and the socket is authed). Returns false when the caller
  // must reject with rate_limited.
  async #browserRateGate(config:Registration,request:Request|null,path:string,now:number):Promise<boolean>{
    const sql=this.ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS browser_rate(minute INTEGER PRIMARY KEY,count INTEGER NOT NULL)');
    sql.exec('CREATE TABLE IF NOT EXISTS browser_ip_rate(minute INTEGER NOT NULL,ip_hash TEXT NOT NULL,endpoint TEXT NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(minute,ip_hash,endpoint))');
    const minute=rateMinute(now);
    const clientIp=request?normalizeClientIp(request.headers.get('CF-Connecting-IP')):null;
    if(clientIp){
      const limit=ipLimitForEndpoint(path);
      if(limit!==null){
        const ipHash=await digest(`${config.id}\n${clientIp}`);
        const ipCount=sql.exec<{count:number}>('INSERT INTO browser_ip_rate(minute,ip_hash,endpoint,count) VALUES(?,?,?,1) ON CONFLICT(minute,ip_hash,endpoint) DO UPDATE SET count=count+1 RETURNING count',minute,ipHash,path).one().count;
        if(ipCount>limit)return false;
      }
    }
    sql.exec('DELETE FROM browser_ip_rate WHERE minute<?',minute);
    const rate=sql.exec<{count:number}>('INSERT INTO browser_rate(minute,count) VALUES(?,1) ON CONFLICT(minute) DO UPDATE SET count=count+1 RETURNING count',minute).one().count;
    sql.exec('DELETE FROM browser_rate WHERE minute<?',minute);
    return rate<=600;
  }
  // Sliding TTL for authenticated visitor hits (POST /sync|/echo, WS frames):
  // an authenticated hit proves the visitor is alive, so it extends the idle
  // window exactly like /session. Without this, a header that only ever polls
  // /sync loses its visitor row 30 min after mint and orphans its bound
  // conversation (a fresh mint can never re-adopt another reference's session).
  // Visitor table setup + expiry sweep, shared by POST #browser and the WS
  // upgrade path: a socket may be the first-ever hit on a fresh DO, so the
  // tables must exist before any frame is read.
  #ensureVisitorTables(now:number):void{
    const sql=this.ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS visitors(token_hash TEXT PRIMARY KEY,reference TEXT NOT NULL,conversation_id TEXT,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL)');
    sql.exec('DELETE FROM visitors WHERE expires_at<=?',now);
    // Wiring step 2: visitor conversation <-> agentcode session pinning rides
    // the visitor row so it dies with visitor TTL. The pin value is the
    // conversationId, which is the stable agentcode session anchor in the
    // canonical AgentTurn (no separate session id crosses the wire). ALTER is
    // idempotent via duplicate-column swallow; deployments whose visitors
    // table predates the column migrate here.
    try{sql.exec('ALTER TABLE visitors ADD COLUMN agent_session TEXT');}catch(e){
      if(!/duplicate column/i.test(e instanceof Error?e.message:String(e)))throw e;
    }
  }
  #touchVisitor(visitor:Visitor,now:number):void{
    if(visitor.expires_at<now+VISITOR_REFRESH_THRESHOLD_MS){
      const extended=Math.min(now+VISITOR_IDLE_TTL_MS,visitor.created_at+VISITOR_MAX_AGE_MS);
      if(extended>visitor.expires_at){
        this.ctx.storage.sql.exec('UPDATE visitors SET expires_at=? WHERE token_hash=?',extended,visitor.token_hash);
        visitor.expires_at=extended;
      }
    }
  }
  async #browser(request:Request,config:Registration):Promise<Response>{
    if(!config.browser)return reply('not_found',404);
    const rawOrigin=request.headers.get('Origin');
    const origin=rawOrigin!==null?rawOrigin:(()=>{try{const r=request.headers.get('Referer');return r?new URL(r).origin:null;}catch{return null;}})();
    // Exact-match allow-set: the Experience site origin plus the deployment's
    // VF test-page origin for V1 snippet POSTs. Registrations stored before
    // origins existed fall back to the canonical primary, unchanged.
    const allowedOrigins=(config.browser.origins&&config.browser.origins.length?config.browser.origins:[config.browser.origin]);
    if(origin===null||!allowedOrigins.includes(origin))return reply('origin_forbidden',403);
    const cors={'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'true','Vary':'Origin','Cache-Control':'no-store'};
    const result=(body:unknown,status=200,headers:Record<string,string>={})=>Response.json(body,{status,headers:{...cors,...headers}});
    const path=new URL(request.url).pathname.slice(`/p/${config.id}/browser`.length);
    if(!['/session','/echo','/sync'].includes(path))return result({error:'not_found'},404);
    if(config.disabled)return result({error:'proxy_revoked'},403);
    if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{...cors,'Access-Control-Allow-Methods':'POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type, X-Tubot-Visitor, X-Tubot-Harness, X-Test-Browser, X-Tubot-Relay','Access-Control-Max-Age':'300'}});
    if(request.method!=='POST')return result({error:'method_not_allowed'},405);
    if(!/^application\/json(?:;|$)/i.test(request.headers.get('Content-Type')||''))return result({error:'json_required'},415);
    const now=Date.now();const sql=this.ctx.storage.sql;
    this.#ensureRelaySources();
    const relaySource=relaySourceOf(request);
    this.#ensureVisitorTables(now);
    // Local rate gates run before the cross-worker authorize call so floods never reach the broker.
    if(!await this.#browserRateGate(config,request,path,now))return result({error:'rate_limited'},429);
    if(path==='/session'){try{await authed(this.env).authorize(config);}catch{return result({error:'channel_not_authorized'},403);}}
    let body:any;try{body=JSON.parse(await boundedBody(request));}catch{return result({error:'invalid_json'},400);}
    if(!body||typeof body!=='object'||Array.isArray(body))return result({error:'invalid_json'},400);
    const cookieToken=request.headers.get('Cookie')?.split(';').map(c=>c.trim()).find(c=>c.startsWith('__Secure-tubot-echo='))?.slice('__Secure-tubot-echo='.length)||'';
    const headerToken=request.headers.get('X-Tubot-Visitor')?.trim()||'';
    const cookie=cookieToken||(/^[a-f0-9]{64}$/.test(headerToken)?headerToken:'');
    const hash=await digest(`${config.id}\n${cookie}`);
    let visitor=sql.exec<Visitor>('SELECT * FROM visitors WHERE token_hash=? AND expires_at>?',hash,now).toArray()[0];
    if(path==='/session'){
      if(Object.keys(body).some(k=>k!=='newConversation'&&k!=='clientVersion')||(body.newConversation!==undefined&&typeof body.newConversation!=='boolean')||(body.clientVersion!==undefined&&(typeof body.clientVersion!=='string'||!clientVersion.test(body.clientVersion))))return result({error:'invalid_session_request'},400);
      let sessionCookie=cookie;
      if(!visitor||body.newConversation===true){
        if(sql.exec<{count:number}>('SELECT COUNT(*) AS count FROM visitors').one().count>=1000)return result({error:'visitor_capacity'},503);
        sessionCookie=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
        const tokenHash=await digest(`${config.id}\n${sessionCookie}`);
        const reference=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
        visitor={token_hash:tokenHash,reference:await seal(this.env.PROXY_ENCRYPTION_KEY,`${config.id}:visitor:${tokenHash}`,{reference}),conversation_id:null,created_at:now,expires_at:now+VISITOR_IDLE_TTL_MS};
        sql.exec('INSERT INTO visitors(token_hash,reference,created_at,expires_at) VALUES(?,?,?,?)',visitor.token_hash,visitor.reference,now,visitor.expires_at);
      }
      const expires=Math.min(now+VISITOR_IDLE_TTL_MS,visitor.created_at+VISITOR_MAX_AGE_MS);sql.exec('UPDATE visitors SET expires_at=? WHERE token_hash=?',expires,visitor.token_hash);
      const {reference}=await open<{reference:string}>(this.env.PROXY_ENCRYPTION_KEY,`${config.id}:visitor:${visitor.token_hash}`,visitor.reference);
      return result({reference,visitorToken:sessionCookie,expiresAt:expires,parameterName:'echoVisitorRef'},200,{'Set-Cookie':`__Secure-tubot-echo=${sessionCookie}; Path=/p/${config.id}/browser; Max-Age=${Math.floor((expires-now)/1000)}; HttpOnly; Secure; SameSite=None; Partitioned`});
    }
    if(!visitor)return result({error:'visitor_unauthorized'},401);
    this.#touchVisitor(visitor,now);
    if(path==='/sync')return this.#serveBrowserSync(config,body,visitor,relaySource,result);
    return this.#serveEchoTurn(config,body,visitor,relaySource,result);
  }
  // Shared sync core for POST /browser/sync and WS {type:'sync'} frames.
  // Discovery, adoption, idempotency, and inline agent execution are
  // identical; only the result transport differs (HTTP response vs socket
  // frame). The WS builder mirrors the POST status/body contract so socket
  // clients observe the same serve semantics, including the idle
  // {conversationId:null,synced:0} shape.
  async #serveBrowserSync<R>(config:Registration,body:any,visitor:Visitor,relaySource:RelaySource,
      result:(body:unknown,status?:number,headers?:Record<string,string>)=>R):Promise<R>{
    if(!config.browser)return result({error:'not_found'},404);
    const sql=this.ctx.storage.sql;
    if(Object.keys(body).some(k=>!['conversationId','linked','clientVersion'].includes(k))||(body.conversationId!==undefined&&!uuid.test(body.conversationId||''))||(body.clientVersion!==undefined&&(typeof body.clientVersion!=='string'||!clientVersion.test(body.clientVersion))))return result({error:'invalid_sync'},400);
    let linked:Record<string,string>|undefined;
    try{linked=parseLinkedContext(body.linked);}catch{return result({error:'invalid_sync'},400);}
    let reference:string;
    try{
      reference=(await open<{reference:string}>(this.env.PROXY_ENCRYPTION_KEY,`${config.id}:visitor:${visitor.token_hash}`,visitor.reference)).reference;
    }catch{return result({error:'verification_unavailable'},503);}
    if((await this.#config())?.disabled)return result({error:'proxy_revoked'},403);
    const broker=authed(this.env);
    if(typeof broker.browserSync!=='function')return result({error:'sync_unavailable'},503);
    const pinnedConv=visitor.conversation_id||(typeof body.conversationId==='string'&&uuid.test(body.conversationId)?body.conversationId:undefined);
    let synced:import('./contracts').BrowserSyncResult;
    try{
      synced=await broker.browserSync(config,config.browser,{reference,...(pinnedConv?{conversationId:pinnedConv}:{}),sinceMs:visitor.created_at});
    }catch{return result({error:'sync_unavailable'},503);}
    if(synced?.conversationEnded===true){
      sql.exec('UPDATE visitors SET conversation_id=NULL,agent_session=NULL WHERE token_hash=?',visitor.token_hash);
      return result({conversationId:null,conversationEnded:true,synced:0},200);
    }
    const convId=synced?.conversationId;
    if(!convId||!uuid.test(convId))return result({conversationId:null,synced:0},200);
    if(visitor.conversation_id&&visitor.conversation_id!==convId)return result({error:'conversation_forbidden'},403);
    if(typeof visitor.agent_session==='string'&&visitor.agent_session.length>0&&visitor.agent_session!==convId)return result({error:'conversation_forbidden'},403);
    const entries=Array.isArray(synced.entries)?synced.entries:[];
    const processed:Array<{messageId:string;status:number}>=[];
    for(const entry of entries){
      if(!entry||!uuid.test(entry.messageId||'')||typeof entry.text!=='string'||!entry.text.length||entry.text.length>AGENT_TEXT_MAX)continue;
      const id=await digest(`${config.id}\n${convId}\n${entry.messageId}`);
      const existingPre=this.#event(id);
      if(existingPre&&existingPre.state!=='echo_inline')continue;
      const fingerprint=await digest(JSON.stringify({conversationId:convId,messageId:entry.messageId,text:entry.text}));
      const late=asyncAccept(this.env)&&verifyLate(this.env);
      const payload=await seal(this.env.PROXY_ENCRYPTION_KEY,`${config.id}:${id}`,{conversationId:convId,messageId:entry.messageId,text:entry.text,channelId:config.channelId,orgId:config.orgId,...(linked?{linked}:{}),...(late?{reference,verifyLate:true as const}:{})});
      // Pre-pin knowledge (same contract as the echo path): read before the
      // pin UPDATE so this entry's own pin never counts as prior knowledge.
      let knownConv=false;
      const outcome=this.ctx.storage.transactionSync(()=>{
        const active=sql.exec<Visitor>('SELECT * FROM visitors WHERE token_hash=? AND expires_at>?',visitor.token_hash,Date.now()).toArray()[0];
        if(!active||(active.conversation_id&&active.conversation_id!==convId))return 'forbidden';
        const existing=this.#event(id);if(existing&&existing.state==='rejected')return 'rejected';
        if(existing&&existing.state!=='echo_inline')return 'existing';
        if(!existing&&sql.exec<{count:number}>("SELECT COUNT(*) AS count FROM events WHERE state IN ('forwarding','echo_pending','agent_pending','submitted')").one().count>=1000)return 'full';
        knownConv=sql.exec('SELECT 1 FROM visitors WHERE conversation_id=? LIMIT 1',convId).toArray().length>0;
        sql.exec('UPDATE visitors SET conversation_id=? WHERE token_hash=?',convId,visitor.token_hash);
        if(!existing){sql.exec("INSERT INTO events(id,fingerprint,state,payload,next_at,created_at) VALUES(?,?,'echo_inline',?,?,?)",id,fingerprint,payload,Date.now(),Date.now());sql.exec('INSERT OR IGNORE INTO relay_sources(event_id,source,created_at) VALUES(?,?,?)',id,relaySource,Date.now());}
        return 'created';
      });
      if(outcome!=='created')continue;
      const turnRes=await this.#agentEcho(config,{conversationId:convId,messageId:entry.messageId,text:entry.text,...(linked?{linked}:{})},reference,id,visitor.token_hash,(_ignored:unknown,status=200)=>({status}),entries,knownConv);
      processed.push({messageId:entry.messageId,status:turnRes.status});
    }
    return result({conversationId:convId,synced:processed.length,results:processed},processed.length>0?202:200);
  }
  // Shared turn-serving core for POST /browser/echo and WS {type:'turn'}
  // frames. Validation, adoption, idempotency, and agent execution are
  // identical; only the result transport differs (HTTP response vs socket
  // frame). The WS builder mirrors the POST status/body contract so socket
  // clients observe the same accept/reject semantics.
  async #serveEchoTurn<R>(config:Registration,body:any,visitor:Visitor,relaySource:RelaySource,
      result:(body:unknown,status?:number,headers?:Record<string,string>)=>R):Promise<R>{
    const sql=this.ctx.storage.sql;
    if(Object.keys(body).some(k=>!['conversationId','messageId','text','linked','clientVersion'].includes(k))||!uuid.test(body.conversationId||'')||!uuid.test(body.messageId||'')||typeof body.text!=='string'||!body.text.length||body.text.length>4096||(body.clientVersion!==undefined&&(typeof body.clientVersion!=='string'||!clientVersion.test(body.clientVersion))))return result({error:'invalid_message'},400);
    let linked:Record<string,string>|undefined;
    try{linked=parseLinkedContext(body.linked);}catch{return result({error:'invalid_message'},400);}
    // A pin mismatch no longer forbids outright. A visitor whose page session
    // outlives its pinned conversation (missed close event, reload with a
    // new chat, second tab) would 403 every turn of the new conversation
    // forever — and a client rebind cannot heal it, because the new
    // conversation is already stamped with this visitor's reference while
    // the rebound visitor mints a fresh one (verify then fails
    // binding_absent; self-bind refuses to overwrite). Instead the mismatch
    // is adopted below when Salesforce ground truth proves the turn's
    // conversation carries this visitor's reference; anything else still
    // fails closed with conversation_forbidden (spoof turns can never
    // verify against another visitor's reference).
    const pinMismatch=(visitor.conversation_id&&visitor.conversation_id!==body.conversationId)||
      (typeof visitor.agent_session==='string'&&visitor.agent_session.length>0&&visitor.agent_session!==body.conversationId);
    let reference:string;
    try{
      reference=(await open<{reference:string}>(this.env.PROXY_ENCRYPTION_KEY,`${config.id}:visitor:${visitor.token_hash}`,visitor.reference)).reference;
    }catch{return result({error:'verification_unavailable'},503);}
    if((await this.#config())?.disabled)return result({error:'proxy_revoked'},403);
    if(pinMismatch&&!(await this.#adoptConversation(config,visitor,reference,body.conversationId,body.messageId,body.text)))
      return result({error:'conversation_forbidden'},403);
    const id=await digest(`${config.id}\n${body.conversationId}\n${body.messageId}`);const fingerprint=await digest(JSON.stringify({conversationId:body.conversationId,messageId:body.messageId,text:body.text}));
    const late=asyncAccept(this.env)&&verifyLate(this.env);
    const payload=await seal(this.env.PROXY_ENCRYPTION_KEY,`${config.id}:${id}`,{conversationId:body.conversationId,messageId:body.messageId,text:body.text,channelId:config.channelId,orgId:config.orgId,...(linked?{linked}:{}),...(late?{reference,verifyLate:true as const}:{})});
    // Pre-pin knowledge: did a PRIOR turn already serve this conversation on
    // this route? Read inside the txn before the pin UPDATE so this turn's
    // own pin never counts (the late branch skips the live handoff read for
    // unknown conversations; the executor re-checks live before submit).
    let knownConv=false;
    const outcome=this.ctx.storage.transactionSync(()=>{
      const active=sql.exec<Visitor>('SELECT * FROM visitors WHERE token_hash=? AND expires_at>?',visitor.token_hash,Date.now()).toArray()[0];
      if(!active||active.conversation_id&&active.conversation_id!==body.conversationId)return 'forbidden';
      const existing=this.#event(id);if(existing&&existing.state==='rejected')return 'rejected';
      if(existing&&existing.state!=='echo_inline')return 'existing';
      if(!existing&&sql.exec<{count:number}>("SELECT COUNT(*) AS count FROM events WHERE state IN ('forwarding','echo_pending','agent_pending','submitted')").one().count>=1000)return 'full';
      knownConv=sql.exec('SELECT 1 FROM visitors WHERE conversation_id=? LIMIT 1',body.conversationId).toArray().length>0;
      sql.exec('UPDATE visitors SET conversation_id=? WHERE token_hash=?',body.conversationId,visitor.token_hash);
      // echo_inline rows are adopted, never duplicated: a crash between insert
      // and resolve leaves the row behind, and the client's retry re-enters here.
      // The relay mark rides the fresh insert (like /sync) so direct snippet
      // POSTs label their rows instead of leaving them unmarked.
      if(!existing){sql.exec("INSERT INTO events(id,fingerprint,state,payload,next_at,created_at) VALUES(?,?,'echo_inline',?,?,?)",id,fingerprint,payload,Date.now(),Date.now());sql.exec('INSERT OR IGNORE INTO relay_sources(event_id,source,created_at) VALUES(?,?,?)',id,relaySource,Date.now());}
      return 'created';
    });
    if(outcome==='forbidden')return result({error:'conversation_forbidden'},403);
    if(outcome==='rejected')return result({error:'message_rejected'},409);
    if(outcome==='full')return result({error:'outbox_full'},503);
    if(outcome==='existing')return result({accepted:true,requestKey:id},202);
    // Agent-only serving: every turn runs verify -> agentcode turn -> submit
    // of the AGENT REPLY. The retired echo branch (merged verify+submit of
    // visitor text) is gone; no route serves verbatim echo in any mode.
    return this.#agentEcho(config,{conversationId:body.conversationId,messageId:body.messageId,text:body.text,...(linked?{linked}:{})},reference,id,visitor.token_hash,result,undefined,knownConv);
  }
  // Same-reference adoption for a pin-mismatched echo turn. Runs the
  // broker verify as the proof: only a conversation stamped with this
  // visitor's reference verifies, which is exactly the legitimate
  // second-conversation case (same page session, same prechat cycle).
  // Verified turns clear the stale pin and flow through the normal path
  // below (which re-pins the new conversation, and re-anchors the agent
  // session only after a served turn, preserving handoff ordering).
  // Unverified, erroring, or malformed verdicts fail closed (false), as
  // does a route without browser config. Runs on the rare mismatch path
  // only; the transaction's own mismatch re-check stays as the backstop.
  async #adoptConversation(config:Registration,visitor:{token_hash:string;conversation_id:string|null},reference:string,conversationId:string,messageId:string,text:string):Promise<boolean>{
    try{
      const browser=config.browser;
      const broker=authed(this.env);
      if(!browser||typeof broker.browserTurn!=='function')return false;
      const verdict=await broker.browserTurn(config,browser,{reference,conversationId,messageId,text});
      const code=typeof verdict==='string'?verdict:(verdict&&typeof (verdict as {code?:unknown}).code==='string'?(verdict as {code:string}).code:'');
      if(code!=='verified')return false;
      this.ctx.storage.sql.exec('UPDATE visitors SET conversation_id=NULL,agent_session=NULL WHERE token_hash=?',visitor.token_hash);
      console.log(JSON.stringify({event:'browser_conversation_adopted',from:String(visitor.conversation_id||'').slice(0,8),to:conversationId.slice(0,8)}));
      return true;
    }catch{return false;}
  }
  // Agent-only turn executor (the sole serving path). 25s inline race +
  // durable alarm (verify -> agentcode -> submit measures ~9-11s live, so a
  // shorter budget would lose half its races). Executor: broker verify ->
  // signed agentcode agentTurn -> submit of the AGENT REPLY through the
  // existing submitter. Handoff skips the submit and parks the row
  // terminally; the visitor conversation binding stays so humans keep a live
  // conversation. Agent failures never emit text: the row parks as
  // agent_pending and the alarm runs a REAL agent turn later (visitor text is
  // never submitted). The pin write below records the conversationId anchor
  // (read pre-row above); a missing bound agentName still runs.
  async #agentEcho<R>(config:Registration,body:{conversationId:string;messageId:string;text:string;linked?:Record<string,string>},reference:string,requestKey:string,
      visitorToken:string,result:(body:unknown,status?:number,headers?:Record<string,string>)=>R,knownEntries?:import('./contracts').BrowserSyncEntry[],
      // Pre-pin knowledge: a PRIOR turn already served this conversation on
      // this route (callers read it before their pin UPDATE). The verify-late
      // branch skips the live handoff read for unknown conversations; default
      // true preserves the old always-check behavior defensively.
      knownConversation=true):Promise<R>{
    const sql=this.ctx.storage.sql;const t0=Date.now();
    let stage='verify';let verifyMs=0;
    const fallback=async()=>{
      await this.#parkForExecutor(requestKey,'inline_fallback');
      return result({accepted:true,requestKey,inline:false,timings:{roundMs:Date.now()-t0}},202);
    };
    try{
      const browser=config.browser;const binding=this.env.AGENTCODE;
      if(!browser||!binding||typeof binding.agentTurn!=='function')throw new Error('agent_unavailable');
      const agent=signedAgent(binding,this.env.AGENT_RPC_KEY);
      type AgentOutcome={rejected:string;verifyMs:number;handoffMs:number}|{suppressed:HandoffReason;verifyMs:number;handoffMs:number}
        |{asyncAccepted:true;verifyMs:number;handoffMs:number;verifyLate?:true}
        |{handoff:true;verifyMs:number;handoffMs:number;spans:Record<string,number|string>}
        |{released:true;verifyMs:number;handoffMs:number;spans:Record<string,number|string>}
        |{handoff:false;verifyMs:number;handoffMs:number;submitMs:number;spans:Record<string,number|string>;requestId:string;reply:string};
      const outcome=await Promise.race([(async():Promise<AgentOutcome>=>{
        const tVerify=Date.now();
        // Verify-late (async-only): the transcript proof moves to the alarm
        // executor (concurrent with the agent turn, gating the submit), so
        // accept runs light checks only. The pin/session checks already ran
        // in the serving transaction above (local SQLite, no SF read); the
        // handoff guard stays live at accept (fail-open on unknown sessions,
        // so fresh conversations pass without waiting on platform commit).
        // Spend-guard order changes shape but not effect: unverified turns
        // still never SUBMIT (the executor gates on the proof); only the
        // model call overlaps the visibility wait (accepted tradeoff: a
        // forged turn from a bound session burns one agent turn, then parks
        // terminal without submitting).
        if(asyncAccept(this.env)&&verifyLate(this.env)){
          const tHandoff=Date.now();
          // Latch-first (local, ~1ms), then cached verdict for conversations
          // this route served before. Unknown conversations skip the live
          // SF read: no latch can exist for them here, and the executor's
          // mandatory live re-check before submit is the backstop.
          const latched=this.#handoffLatch(body.conversationId);
          const handoffReason=latched??(knownConversation?await this.#handoffAcceptCached(config,body.conversationId):null);
          const handoffMs=Date.now()-tHandoff;
          verifyMs=Date.now()-tVerify;
          if(handoffReason)return {suppressed:handoffReason,verifyMs,handoffMs};
          stage='async_accept';return {asyncAccepted:true as const,verifyMs,handoffMs,verifyLate:true as const};
        }
        // Verify (SF transcript read) and the handoff guard (SF session-state
        // read) are independent: overlap them (~1.5s saved). BOTH stay ahead
        // of the agent turn (spend guards): a rejected verify or a handed-off
        // session still never invokes agentcode. Verify rejection keeps
        // precedence over suppression, exactly as in the serial order.
        let handoffMs=0;const tHandoff=Date.now();
        // Accept-side cache on async only (the executor re-checks live):
        // inline submits straight off this verdict, so it always reads live.
        const handoffCheck=asyncAccept(this.env)
          ?this.#handoffAcceptCached(config,body.conversationId)
          :this.#isHandedOff(config,body.conversationId);
        const [verdict,handoffReason]=await Promise.all([
          authed(this.env).browserTurn(config,browser,{reference,conversationId:body.conversationId,messageId:body.messageId,text:body.text,...(knownEntries?{knownEntries}:{})}),
          handoffCheck.finally(()=>{handoffMs=Date.now()-tHandoff;}),
        ]);
        verifyMs=Date.now()-tVerify;
        // Broker returns {code,recipient?}; bare-string verdicts stay valid
        // for mixed-version brokers. Malformed shapes fail closed (400).
        const code=typeof verdict==='string'?verdict:(verdict&&typeof (verdict as {code?:unknown}).code==='string'?(verdict as {code:string}).code:'invalid_turn');
        const recipient=typeof verdict==='object'&&verdict!==null?(verdict as {recipient?:unknown}).recipient:undefined;
        if(code!=='verified')return {rejected:code,verifyMs,handoffMs};
        // Handoff guard (agent path): verify still proves routing, but a
        // handed-off session skips agentcode entirely and parks silently.
        if(handoffReason)return {suppressed:handoffReason,verifyMs,handoffMs};
        // 202-async accept (flag-gated): verify+handoff passed, so release
        // the client now; the alarm executor runs the same agentTurn+submit
        // the inline path would (with its own handoff re-check), and the
        // client discovers the reply via sync. Spend-guard order kept:
        // unverified/handed-off turns never reach this branch. Tradeoffs vs
        // inline: no flow-route pre-warm and no verify-recipient relay, so
        // the background submit re-resolves both (invisible to the client).
        if(asyncAccept(this.env)){stage='async_accept';return {asyncAccepted:true as const,verifyMs,handoffMs};}
        stage='agentTurn';
        // F5: Flow-route pre-resolve rides alongside the agent turn, off the
        // critical path: the broker warms its cached action resolution while
        // agentcode thinks, so submit's echo() usually finds it warm instead
        // of paying Salesforce discovery serially after the reply. Starts only
        // after verify+handoff pass (spend-guard order kept: rejected or
        // handed-off sessions still never invoke agentcode and never
        // pre-resolve). Fail-open: older brokers lack the RPC and any failure
        // just leaves submit to re-resolve serially, exactly as today.
        let flowRoute:Promise<unknown>|null=null;
        try{
          const broker=authed(this.env);
          if(typeof (this.env.SF_BROKER as unknown as {resolveFlowRoute?:unknown}).resolveFlowRoute==='function'&&typeof broker.resolveFlowRoute==='function')
            flowRoute=broker.resolveFlowRoute(config,config.action).then(v=>({ok:true as const,v}),e=>({ok:false as const,e}));
        }catch{flowRoute=null;}
        const turn=await agent.agentTurn(config,{conversationId:body.conversationId,text:body.text,requestKey,
          messageId:body.messageId,channelId:config.channelId,orgId:config.orgId,...(body.linked?{linked:body.linked}:{})});
        const shaped=shapeAgentResult(turn);
        if(!shaped)throw new Error('agent_reply_invalid');
        if('handoff' in shaped&&shaped.handoff)return {handoff:true as const,verifyMs,handoffMs,spans:shaped.spans};
        if('released' in shaped&&shaped.released)return {released:true as const,verifyMs,handoffMs,spans:shaped.spans};
        const reply=(shaped as {reply:string}).reply;const spans=shaped.spans;
        const tSubmit=Date.now();stage='submit';
        // F5: never submit before the agent reply validates (above), and never
        // pay discovery twice: drain the pre-resolve first so a still-running
        // resolution finishes instead of echo() starting a duplicate one. The
        // wait is fail-open and bounded by the same 25s inline race.
        if(flowRoute){try{await flowRoute;}catch{/* echo() re-resolves on miss */}}
        const submitted=await authed(this.env).echo(config,config.action,
          {conversationId:body.conversationId,text:reply,requestKey,channelId:config.channelId,orgId:config.orgId,
            ...(typeof recipient==='string'&&recipient?{recipient}:{})});
        const submitMs=Date.now()-tSubmit;
        if(!submitted||!/^[A-Za-z0-9]{15,18}$/.test(submitted.requestId||''))throw new Error('agent_submit_unconfirmed');
        return {handoff:false as const,verifyMs,handoffMs,submitMs,spans,requestId:submitted.requestId,reply};
      })(),new Promise<never>((_,reject)=>setTimeout(()=>reject(new Error('merged_timeout')),25000))]);
      if('rejected' in outcome){
        sql.exec('DELETE FROM events WHERE id=?',requestKey);
        sql.exec('UPDATE visitors SET conversation_id=NULL,agent_session=NULL WHERE token_hash=? AND conversation_id=?',visitorToken,body.conversationId);
        return result({error:outcome.rejected},outcome.rejected==='invalid_turn'?400:outcome.rejected==='session_pending'?503:403);
      }
      // Guard suppression parks before the agent pin: no agentcode session was
      // touched, so there is no anchor to record. The visitor conversation
      // binding stays, so humans keep a live conversation.
      if('suppressed' in outcome){
        await this.#suppressTurn(config,requestKey,body.conversationId,outcome.suppressed);
        return result({accepted:true,requestKey,inline:true,handoff:true,suppressed:true,
          timings:{verifyMs:outcome.verifyMs,roundMs:Date.now()-t0}},202);
      }
      // 202-async release: durably park the sealed turn (the alarm stays
      // armed as the backstop) and return before the agent turn runs; the
      // first turn attempt starts immediately on the hot isolate via
      // waitUntil instead of waiting out alarm scheduling. The visitor
      // agent_session pin is intentionally NOT written here: the executor
      // writes it after a served turn (preserving handoff ordering),
      // exactly like the fallback path.
      if('asyncAccepted' in outcome){
        await this.#parkForExecutor(requestKey,'async_accepted');
        return result({accepted:true,requestKey,inline:false,...(outcome.verifyLate?{verifyLate:true as const}:{}),
          timings:{verifyMs:outcome.verifyMs,handoffMs:outcome.handoffMs,roundMs:Date.now()-t0}},202);
      }
      sql.exec('UPDATE visitors SET agent_session=? WHERE token_hash=?',body.conversationId,visitorToken);
      if('handoff' in outcome&&outcome.handoff){
        sql.exec("UPDATE events SET state='handed_off',payload=NULL,error=NULL WHERE id=?",requestKey);
        // Agent-verdict handoffs latch the conversation so follow-up turns
        // suppress without re-invoking agentcode (whose session is paused).
        await this.#latchHandoff(body.conversationId,'agent_verdict');
        return result({accepted:true,requestKey,inline:true,handoff:true,
          timings:{...outcome.spans,verifyMs:outcome.verifyMs,roundMs:Date.now()-t0}},202);
      }
      if('released' in outcome){
        // Over-cap agentforce release: park silently without submit or latch.
        // Native Agentforce routing proceeds; follow-up turns re-derive the
        // release in agentcode (cheap usage re-check, no session, no count).
        sql.exec("UPDATE events SET state='released',payload=NULL,error=NULL WHERE id=?",requestKey);
        return result({accepted:true,requestKey,inline:true,released:true,
          timings:{...outcome.spans,verifyMs:outcome.verifyMs,roundMs:Date.now()-t0}},202);
      }
      sql.exec("UPDATE events SET state='submitted',request_id=?,attempts=attempts+1,next_at=?,error=NULL WHERE id=?",outcome.requestId,Date.now()+2000,requestKey);
      await this.#schedule(2000);
      return result({accepted:true,requestKey,requestId:outcome.requestId,inline:true,
        timings:{...outcome.spans,verifyMs:outcome.verifyMs,handoffMs:outcome.handoffMs,submitMs:outcome.submitMs,roundMs:Date.now()-t0}},202);
    }catch(cause){console.warn(JSON.stringify({event:'agent_inline_fallback',requestKey,roundMs:Date.now()-t0,stage,verifyMs,cause:String((cause as Error)?.message??cause).slice(0,200)}));return fallback();}
  }
  // Browser WebSocket transport: GET /p/{id}/browser/ws with Upgrade.
  // Same preconditions as #browser (browser config, enabled route, exact
  // Origin allow-list, local rate gates incl. the tight '/ws' per-IP
  // budget), then the upgrade delegates to PartyServer, which accepts the
  // socket and dispatches onConnect/onMessage/onClose. Browsers always send
  // Origin on the WS handshake, so no CORS headers are needed on rejections.
  async #browserWs(request:Request,config:Registration):Promise<Response>{
    if(!config.browser)return reply('not_found',404);
    if(config.disabled)return reply('proxy_revoked',403);
    if(request.method!=='GET')return reply('method_not_allowed',405);
    if(request.headers.get('Upgrade')?.toLowerCase()!=='websocket')return reply('upgrade_required',426);
    const rawOrigin=request.headers.get('Origin');
    const origin=rawOrigin!==null?rawOrigin:(()=>{try{const r=request.headers.get('Referer');return r?new URL(r).origin:null;}catch{return null;}})();
    const allowedOrigins=(config.browser.origins&&config.browser.origins.length?config.browser.origins:[config.browser.origin]);
    if(origin===null||!allowedOrigins.includes(origin))return reply('origin_forbidden',403);
    if(!await this.#browserRateGate(config,request,'/ws',Date.now()))return reply('rate_limited',429);
    this.#ensureVisitorTables(Date.now());
    return super.fetch(request);
  }
  #wsSend(connection:Connection,frame:unknown):void{
    try{connection.send(JSON.stringify(frame));}catch{/* A dead socket needs no reply; close/error hooks follow. */}
  }
  // Ops-telemetry push: the visitor's live socket(s) receive executor
  // progress markers (accept/agent-start/agent-done/submit, worker clock)
  // for latency attribution. Clients ignore unknown frame kinds; there is
  // no rendered output from pushes (fake bubbles removed — the native
  // bubble is the only path). Addressing is by bound visitor row: only
  // sockets authed as a visitor bound to this conversation receive the
  // frame, so a push can never leak across visitors. No socket (POST-only
  // client) or no bound visitor = silent no-op. Callers push ONLY
  // post-submit (requestId in hand).
  async #pushToConversation(conversationId:string,frame:Record<string,unknown>):Promise<void>{
    let hashes:Set<string>;
    try{
      hashes=new Set(this.ctx.storage.sql.exec<{token_hash:string}>('SELECT token_hash FROM visitors WHERE conversation_id=? AND expires_at>?',conversationId,Date.now()).toArray().map(r=>r.token_hash));
    }catch{return;}
    if(!hashes.size)return;
    let conns:Connection[];
    try{conns=[...this.getConnections()];}catch{return;}
    for(const conn of conns){
      try{
        const st=(conn as Connection<WsSocketState>).state;
        if(st&&st.authed===true&&hashes.has(st.tokenHash))this.#wsSend(conn,frame);
      }catch{/* dead socket */}
    }
  }
  // First-frame auth: browsers cannot set WS handshake headers, and a token
  // in the URL would leak into access logs, so the visitor token arrives in
  // the first message. A non-auth first frame closes the socket; sockets that
  // never speak die on the platform idle timeout (no timer is kept).
  async #wsAuth(connection:Connection,config:Registration,frame:unknown):Promise<void>{
    const fail=(code:string)=>{this.#wsSend(connection,{type:'error',code});connection.close(4401,code);};
    if(!frame||typeof frame!=='object'||(frame as {type?:unknown}).type!=='auth')return fail('auth_required');
    const f=frame as {protocol?:unknown;visitorToken?:unknown};
    if(f.protocol!==WS_PROTOCOL_VERSION)return fail('protocol_mismatch');
    if(typeof f.visitorToken!=='string'||!/^[a-f0-9]{64}$/.test(f.visitorToken))return fail('visitor_unauthorized');
    const tokenHash=await digest(`${config.id}\n${f.visitorToken}`);
    const visitor=this.ctx.storage.sql.exec<Visitor>('SELECT * FROM visitors WHERE token_hash=? AND expires_at>?',tokenHash,Date.now()).toArray()[0];
    if(!visitor)return fail('visitor_unauthorized');
    connection.setState({authed:true,tokenHash} satisfies WsSocketState);
    this.#wsSend(connection,{type:'authed'});
  }
  async onConnect(connection:Connection):Promise<void>{
    connection.setState({authed:false} satisfies WsSocketState);
    this.#wsSend(connection,{type:'hello',protocol:WS_PROTOCOL_VERSION});
  }
  async onMessage(connection:Connection,message:WSMessage):Promise<void>{
    const config=await this.#config();
    if(!config||!config.browser||config.disabled){connection.close(4403,'proxy_unavailable');return;}
    let text:string;
    if(typeof message==='string')text=message;
    else if(message instanceof ArrayBuffer)text=new TextDecoder().decode(message);
    else if(ArrayBuffer.isView(message))text=new TextDecoder().decode(message as Uint8Array);
    else{this.#wsSend(connection,{type:'error',code:'invalid_frame'});return;}
    if(text.length>WS_MAX_FRAME_BYTES){this.#wsSend(connection,{type:'error',code:'frame_too_large'});return;}
    let frame:unknown;
    try{frame=JSON.parse(text);}catch{this.#wsSend(connection,{type:'error',code:'invalid_frame'});return;}
    const raw=(connection.state??null) as unknown as WsSocketState|null;
    const tokenHash=raw&&raw.authed===true?raw.tokenHash:null;
    if(typeof tokenHash!=='string'){await this.#wsAuth(connection,config,frame);return;}
    const frameType=frame&&typeof frame==='object'?(frame as {type?:unknown}).type:null;
    if(frameType!=='turn'&&frameType!=='hint'&&frameType!=='sync'){
      this.#wsSend(connection,{type:'error',code:'unknown_frame'});return;
    }
    const f=frame as {type:string;conversationId?:unknown;messageId?:unknown;text?:unknown;linked?:unknown;clientVersion?:unknown;clientTurnId?:unknown;requestId?:unknown};
    const now=Date.now();
    const visitor=this.ctx.storage.sql.exec<Visitor>('SELECT * FROM visitors WHERE token_hash=? AND expires_at>?',tokenHash,now).toArray()[0];
    if(!visitor){this.#wsSend(connection,{type:'error',code:'visitor_unauthorized'});connection.close(4401,'visitor_unauthorized');return;}
    this.#touchVisitor(visitor,now);
    // Sync frames ride their own budget (POST /sync parity): discovering
    // turns must never starve behind turn traffic or vice versa.
    if(f.type==='sync'){
      const reqId=typeof f.requestId==='string'?f.requestId.slice(0,64):'';
      if(!await this.#browserRateGate(config,null,'/sync',now)){this.#wsSend(connection,{type:'error',...(reqId?{requestId:reqId}:{}),code:'rate_limited'});return;}
      const syncBody:any={};
      if(f.conversationId!==undefined)syncBody.conversationId=f.conversationId;
      if(f.linked!==undefined)syncBody.linked=f.linked;
      if(f.clientVersion!==undefined)syncBody.clientVersion=f.clientVersion;
      const send=(body:unknown,status=200)=>{
        const b=body as Record<string,unknown>;
        if(b&&typeof b.error==='string')this.#wsSend(connection,{type:'error',...(reqId?{requestId:reqId}:{}),code:b.error,status});
        else this.#wsSend(connection,{type:'synced',...(reqId?{requestId:reqId}:{}),...(b as Record<string,unknown>)});
      };
      await this.#serveBrowserSync(config,syncBody,visitor,'lwc',send);
      return;
    }
    if(!await this.#browserRateGate(config,null,'/echo',now)){this.#wsSend(connection,{type:'error',code:'rate_limited'});return;}
    if(f.type==='hint')return this.#wsHint(connection,visitor,now,f);
    const turnBody:any={conversationId:f.conversationId,messageId:f.messageId,text:f.text};
    if(f.linked!==undefined)turnBody.linked=f.linked;
    if(f.clientVersion!==undefined)turnBody.clientVersion=f.clientVersion;
    // A WS turn IS the live LWC path, so it carries the lwc relay mark like
    // its POST twin; frames echo transport:'ws' for measurement and the
    // messageId (bounded: it may be client garbage on invalid turns) so the
    // client can correlate acknowledgments to in-flight turns.
    const frameId=typeof turnBody.messageId==='string'?turnBody.messageId.slice(0,64):'';
    const hintAge=typeof turnBody.conversationId==='string'?this.#hintAgeMs(turnBody.conversationId,now):null;
    const send=(body:unknown,status=200)=>{
      if(status===202)this.#wsSend(connection,{type:'accepted',transport:'ws',messageId:frameId,...(hintAge!==null?{hinted:true,hintAgeMs:hintAge}:{}),...(body as Record<string,unknown>)});
      else this.#wsSend(connection,{type:'error',messageId:frameId,code:typeof (body as {error?:unknown})?.error==='string'?(body as {error:string}).error:'echo_failed',status});
    };
    await this.#serveEchoTurn(config,turnBody,visitor,'lwc',send);
  }
  // Send-hint intake: the LWC signals a send gesture ahead of the turn. The
  // hint costs one local TTL touch and an in-memory stamp — no cross-worker
  // calls, so stray Enters burn nothing. The stamp lets the next turn's
  // accept frame prove the capture fired (hinted:true + age).
  #wsHint(connection:Connection,visitor:Visitor,now:number,f:{clientTurnId?:unknown;conversationId?:unknown}):void{
    if(typeof f.clientTurnId!=='string'||!f.clientTurnId.length||f.clientTurnId.length>64){
      this.#wsSend(connection,{type:'error',code:'invalid_hint'});return;
    }
    const conv=typeof f.conversationId==='string'&&uuid.test(f.conversationId)?f.conversationId:null;
    this.#touchVisitor(visitor,now);
    if(conv){
      if(this.#hintTs.size>=MAX_HINT_ENTRIES)this.#hintTs.delete(this.#hintTs.keys().next().value!);
      this.#hintTs.set(conv,now);
    }
    this.#wsSend(connection,{type:'hint-ack',clientTurnId:f.clientTurnId.slice(0,64)});
  }
  // Age (ms) of the last hint for a conversation, or null when none is in
  // window. Stale entries are dropped lazily on read.
  #hintAgeMs(conversationId:string,now:number):number|null{
    const ts=this.#hintTs.get(conversationId);
    if(ts===undefined)return null;
    if(now-ts>HINT_WINDOW_MS){this.#hintTs.delete(conversationId);return null;}
    return now-ts;
  }
  // Socket errors carry no durable state to reconcile (the attachment dies
  // with the socket); log one bounded line instead of PartyServer's noisy
  // default. onClose needs nothing and keeps the default no-op.
  async onError(connection:Connection,error:unknown):Promise<void>{
    console.warn(JSON.stringify({event:'browser_ws_error',id:connection.id,cause:String((error as Error)?.message??error).slice(0,120)}));
  }
  async fetch(request:Request):Promise<Response>{
    const config=await this.#config();if(!config)return reply('not_found',404);
    const pathname=new URL(request.url).pathname;
    if(pathname===`/p/${config.id}/browser/ws`)return this.#browserWs(request,config);
    if(pathname.startsWith(`/p/${config.id}/browser/`))return this.#browser(request,config);
    if(config.disabled)return reply('proxy_revoked',403);
    const key=request.headers.get('X-Tubot-Proxy-Key')||'';
    if(key.length<32||key.length>256)return reply('unauthorized',401);
    const hash=await digest(`${config.id}\n${key}`);
    if(!config.keyHashes.some(h=>equalDigest(h,hash)))return reply('unauthorized',401);
    try{await authed(this.env).authorize(config);}catch{return reply('channel_not_authorized',403);}
    const orgHeader=request.headers.get('X-Org-Id');
    if(orgHeader && orgHeader.slice(0,15)!==config.orgId.slice(0,15))return reply('org_mismatch',403);
    const incoming=new URL(request.url);const prefix=`/p/${config.id}`;
    const path=incoming.pathname.slice(prefix.length);
    if(!incoming.pathname.startsWith(prefix+'/')||/[\\%\u0000-\u001f]/.test(path)||path.includes('//'))return reply('not_found',404);
    const allowed=path.startsWith('/iamessage/api/v2/')||path==='/eventrouter/v1/sse'||path==='/embeddedservice/v1/embedded-service-config';
    if(!allowed||!['GET','POST','PATCH','DELETE','HEAD'].includes(request.method))return reply('not_found',404);
    if(path==='/embeddedservice/v1/embedded-service-config'&&(incoming.searchParams.get('orgId')!==config.orgId||incoming.searchParams.get('esConfigName')!==config.deploymentName))return reply('deployment_mismatch',403);
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_rate(minute INTEGER PRIMARY KEY,count INTEGER NOT NULL)');
    const minute=Math.floor(Date.now()/60000);
    const count=this.ctx.storage.sql.exec<{count:number}>('INSERT INTO request_rate(minute,count) VALUES(?,1) ON CONFLICT(minute) DO UPDATE SET count=count+1 RETURNING count',minute).one().count;
    this.ctx.storage.sql.exec('DELETE FROM request_rate WHERE minute<?',minute);
    if(count>600)return reply('rate_limited',429);
    let body:string|undefined;let parsed:any;
    if(!['GET','HEAD'].includes(request.method)){
      try{body=await boundedBody(request);parsed=body?JSON.parse(body):{};}catch{return reply('invalid_or_oversized_json',413);}
      if(parsed.orgId!==undefined&&parsed.orgId!==config.orgId)return reply('org_mismatch',403);
      if(parsed.esDeveloperName!==undefined&&parsed.esDeveloperName!==config.deploymentName)return reply('deployment_mismatch',403);
      if(path.includes('/access-token')&&(parsed.orgId!==config.orgId||parsed.esDeveloperName!==config.deploymentName))return reply('deployment_required',403);
    }
    const message=path.match(/^\/iamessage\/api\/v2\/conversation\/([^/]+)\/message$/);
    let eventId:string|undefined;
    if(message&&request.method==='POST'){
      const value=parsed?.message;
      if(!uuid.test(message[1])||!uuid.test(value?.id||'')||parsed.esDeveloperName!==config.deploymentName)return reply('invalid_message_identity',400);
      if(value.messageType!=='StaticContentMessage'||value.staticContent?.formatType!=='Text')return reply('unsupported_echo_content',422);
      const text=value.staticContent.text;
      if(typeof text!=='string'||!text.length||text.length>4096)return reply('invalid_message_text',400);
      eventId=await digest(`${config.id}\n${message[1]}\n${value.id}`);
      const fingerprint=await digest(body!);
      const existing=this.#event(eventId);
      if(existing&&existing.fingerprint!==fingerprint)return reply('message_id_conflict',409);
      if(!existing || existing.state==='rejected'){
        const payload=await seal(this.env.PROXY_ENCRYPTION_KEY,`${config.id}:${eventId}`,{conversationId:message[1],messageId:value.id,text,channelId:config.channelId,orgId:config.orgId} satisfies Turn);
        const pending=this.ctx.storage.sql.exec<{count:number}>("SELECT COUNT(*) AS count FROM events WHERE state IN ('forwarding','echo_pending','agent_pending','submitted')").one().count;
        if(pending>=1000&&!this.#event(eventId))return reply('outbox_full',503);
        this.ctx.storage.sql.exec("INSERT OR IGNORE INTO events(id,fingerprint,state,payload,next_at,created_at) VALUES(?,?,'forwarding',?,?,?)",eventId,fingerprint,payload,Date.now()+30000,Date.now());
        if(existing?.state==='rejected')this.ctx.storage.sql.exec("UPDATE events SET state='forwarding',payload=?,next_at=?,error=NULL WHERE id=? AND state='rejected'",payload,Date.now()+30000,eventId);
      }
      const saved=this.#event(eventId);
      if(saved?.fingerprint!==fingerprint)return reply('message_id_conflict',409);
      await this.#schedule(30000);
    }
    const headers=new Headers(request.headers);
    for(const name of ['X-Tubot-Proxy-Key','Cookie','Host','Origin','Referer','CF-Connecting-IP','X-Forwarded-For','Forwarded'])headers.delete(name);
    const destination=new URL(path+incoming.search,config.scrtOrigin);
    let upstream:Response;
    try{
      upstream=await fetch(destination.toString(),{method:request.method,headers,body,redirect:'manual',
        signal:path==='/eventrouter/v1/sse'?request.signal:AbortSignal.timeout(30000)});
    }catch{return reply('scrt_unavailable',502);}
    try{if(eventId){
      const existing=this.#event(eventId);
      if(existing?.state==='forwarding'){
        if(upstream.ok){this.ctx.storage.sql.exec("UPDATE events SET state='agent_pending',next_at=? WHERE id=? AND state='forwarding'",Date.now(),eventId);await this.#schedule();}
        else if(upstream.status>=400&&upstream.status<500&&upstream.status!==409){this.ctx.storage.sql.exec("UPDATE events SET state='rejected',payload=NULL,error=? WHERE id=? AND state='forwarding'",`scrt_${upstream.status}`,eventId);}
      }
    }}catch{ /* The durable forwarding record and alarm reconcile an unconfirmed outcome. */ }
    // Return SCRT's response, including streaming bodies, without consuming or replacing it.
    return upstream;
  }
  // Verify-late executor: prove the sealed turn's transcript concurrently
  // with the agent turn, gating the submit on the proof. First pass overlaps
  // generously (agent + tight poll + handoff join): short-transient AND
  // binding_absent proofs ride concurrently, because binds typically heal in
  // ~10s and the agent result is used, not wasted. Permanent codes park
  // terminal WITHOUT invoking agentcode. Retry passes (attempts>0) probe
  // ONCE and requeue on transient (no budget burn: the backoff spacing
  // already covers the wait), so a never-healing row costs one speculative
  // agent turn total plus one cheap probe per pass — never an agent turn or
  // a full poll budget per pass. The handoff re-check also rides
  // concurrently; suppression still wins over submit. Throws transient
  // (requeue via the budget guard) or verify_rejected (terminal park, in
  // TERMINAL_ALARM_CAUSES).
  async #serveLateTurn(config:Registration,row:EventRow,turn:Turn&{reference:string}):Promise<void>{
    const sql=this.ctx.storage.sql;
    // Latched conversations suppress before any proof or agent work.
    const latched=this.#handoffLatch(turn.conversationId);
    if(latched){await this.#suppressTurn(config,row.id,turn.conversationId,latched);return;}
    const browser=config.browser!;
    const broker=authed(this.env);
    const proof={reference:turn.reference,conversationId:turn.conversationId,messageId:turn.messageId,text:turn.text};
    const normCode=(v:unknown)=>typeof v==='string'?v:(v&&typeof (v as {code?:unknown}).code==='string'?(v as {code:string}).code:'invalid_turn');
    const normRecipient=(v:unknown)=>typeof v==='object'&&v!==null&&(v as {recipient?:unknown}).recipient;
    const attempt=async()=>{
      let v:unknown;
      try{v=await broker.browserTurn(config,browser,proof);}
      catch{throw new Error('verify_unavailable');}
      return {code:normCode(v),recipient:normRecipient(v)};
    };
    const reject=(code:string):never=>{
      console.warn(JSON.stringify({event:'verify_late_rejected',requestKey:row.id,code:code.slice(0,80)}));
      throw new Error('verify_rejected');
    };
    const binding=this.env.AGENTCODE;
    const bindingOk=!!binding&&typeof binding.agentTurn==='function';
    // agentCall is invoked only where bindingOk holds (the speculative start
    // below is bindingOk-guarded; the retry path throws first), so the cast
    // never fires on a missing binding.
    const agentCall=()=>signedAgent(binding as AgentService,this.env.AGENT_RPC_KEY).agentTurn(config,
      {conversationId:turn.conversationId,text:turn.text,requestKey:row.id,
        ...(turn.messageId?{messageId:turn.messageId}:{}),channelId:turn.channelId??config.channelId,orgId:turn.orgId??config.orgId,
        ...(turn.linked?{linked:turn.linked}:{})});
    // Executor markers (worker clock, same span): accept->agent-start is the
    // drive head on first passes (speculative start, below) and head plus
    // the serial first probe on retry passes; agent-start->done is the
    // agent RPC; done->submit is proof-residual + submit. Shipped on the
    // progress frame.
    let tAgentStart=Date.now();let tAgentDone=0;
    const agentTimed=()=>agentCall().then(v=>{tAgentDone=Date.now();return v;},e=>{tAgentDone=Date.now();throw e;});
    // Speculative agent start (first passes only): the agent turn overlaps
    // the FIRST verify probe (~1.5-2s SF read, measured live as the
    // accept->agent-start span), not just the poll. Retry passes keep the
    // serial probe (proof-only on known-suspect rows). Cost: a forged first
    // turn burns one agent turn before the probe rejects it (the
    // pre-accepted verify-late tradeoff); submits stay proof-gated as
    // before, and a missing binding still throws below with identical
    // precedence (the deferred throw after the branch).
    const earlyAgent=row.attempts===0&&bindingOk?agentTimed():null;
    if(earlyAgent)earlyAgent.catch(()=>{/* Rejection surfaces at the join; this only quiets the orphan window when the probe rejects first. */});
    const first=await attempt();
    console.warn(JSON.stringify({event:'verify_late_first',requestKey:row.id,attempts:row.attempts,code:first.code}));
    const shortTransient=VERIFY_LATE_SHORT_TRANSIENT.has(first.code);
    const bindWait=first.code==='binding_absent';
    if(first.code!=='verified'&&!shortTransient&&!bindWait)reject(first.code);
    // Retry pass: the single probe above is the whole budget. Unproven →
    // requeue through the backoff (no agent, no poll loop).
    if(row.attempts>0&&first.code!=='verified')
      throw new Error(bindWait?'verify_binding_pending':'verify_pending');
    // Deferred binding throw: identical precedence to the pre-speculation
    // order (a forged turn still rejects above before this fires).
    if(!bindingOk)throw new Error('agent_unavailable');
    // F5 pre-resolve rides free alongside the agent turn (fail-open mirror of
    // the inline path): the late submit usually finds the route warm instead
    // of paying Salesforce discovery serially after the reply.
    let flowRoute:Promise<unknown>|null=null;
    try{
      if(typeof (this.env.SF_BROKER as unknown as {resolveFlowRoute?:unknown}).resolveFlowRoute==='function'&&typeof broker.resolveFlowRoute==='function')
        flowRoute=broker.resolveFlowRoute(config,config.action).then(v=>({ok:true as const,v}),e=>({ok:false as const,e}));
    }catch{flowRoute=null;}
    const pollProof=async()=>{
      if(first.code==='verified')return {recipient:first.recipient};
      // First pass only (retry passes never reach here unproven): tight poll
      // across short-transient AND bind-wait codes; anything else permanent.
      const tPoll=Date.now();const budget=verifyLateBudgetMs(this.env);
      for(;;){
        await sleep(VERIFY_LATE_POLL_MS);
        let v:{code:string;recipient:unknown};
        try{v=await attempt();}
        catch{
          if(Date.now()-tPoll>=budget)throw new Error('verify_poll_exhausted');
          continue;
        }
        if(v.code==='verified')return {recipient:v.recipient};
        if(v.code!=='binding_absent'&&!VERIFY_LATE_SHORT_TRANSIENT.has(v.code))reject(v.code);
        if(Date.now()-tPoll>=budget)throw new Error('verify_poll_exhausted');
      }
    };
    let proofRes:{recipient:unknown};let agentRaw:unknown;let handoffReason:HandoffReason|null;
    if(row.attempts>0){
      // Retry pass: proven by the single probe above; serve without polling.
      // The agent starts here (after the serial probe), so re-stamp the
      // marker: the pre-probe stamp above only fits speculative first passes.
      tAgentStart=Date.now();
      proofRes={recipient:first.recipient};
      [agentRaw,handoffReason]=await Promise.all([agentTimed(),this.#isHandedOff(config,turn.conversationId)]);
    }else{
      // First pass: the agent started speculatively above (bindingOk held,
      // else the deferred throw fired), so join it — never start a second.
      [proofRes,agentRaw,handoffReason]=await Promise.all([pollProof(),earlyAgent!,this.#isHandedOff(config,turn.conversationId)]);
    }
    if(handoffReason){await this.#suppressTurn(config,row.id,turn.conversationId,handoffReason);return;}
    const agentResult=shapeAgentResult(agentRaw);
    if(!agentResult)throw new Error('agent_reply_invalid');
    if('handoff' in agentResult&&agentResult.handoff){
      sql.exec("UPDATE events SET state='handed_off',payload=NULL,error=NULL WHERE id=?",row.id);
      await this.#latchHandoff(turn.conversationId,'agent_verdict');
      return;
    }
    if('released' in agentResult&&agentResult.released){
      sql.exec("UPDATE events SET state='released',payload=NULL,error=NULL WHERE id=?",row.id);
      return;
    }
    if(flowRoute){try{await flowRoute;}catch{/* echo() re-resolves on miss */}}
    const recipient=typeof proofRes.recipient==='string'&&proofRes.recipient?proofRes.recipient:undefined;
    const result=await broker.echo(config,config.action,{conversationId:turn.conversationId,text:(agentResult as {reply:string}).reply,requestKey:row.id,
      channelId:turn.channelId??config.channelId,orgId:turn.orgId??config.orgId,...(recipient?{recipient}:{})});
    if(!result||!/^[A-Za-z0-9]{15,18}$/.test(result.requestId||''))throw new Error('agent_submit_unconfirmed');
    sql.exec("UPDATE events SET state='submitted',request_id=?,next_at=?,error=NULL WHERE id=?",result.requestId,Date.now()+2000,row.id);
    const tSubmit=Date.now();
    // Executor markers for latency attribution (clients ignore the frame).
    await this.#pushToConversation(turn.conversationId,{type:'progress',requestKey:row.id,
      tAccept:row.created_at,tAgentStart,tAgentDone,tSubmit});
    sql.exec('UPDATE visitors SET agent_session=? WHERE conversation_id=?',turn.conversationId,turn.conversationId);
  }
  async alarm():Promise<void>{
    const config=await this.#config();if(!config||config.disabled)return;
    const now=Date.now();
    const due=this.ctx.storage.sql.exec<EventRow>("SELECT * FROM events WHERE (state IN ('forwarding','echo_pending','agent_pending','submitted') AND next_at<=?) OR (state='echo_inline' AND next_at<=?) ORDER BY next_at LIMIT 10",now,now-60000).toArray();
    for(const row of due){await this.#driveRow(config,row,now);}
    await this.#rearm();
  }
  // Alarm re-arm + retention sweep, shared by the alarm loop and the
  // waitUntil fast path: after any drive pass, the alarm tracks the true
  // next due row (poll/backoff horizon), never an immediate spurious fire.
  async #rearm():Promise<void>{
    const now=Date.now();
    this.ctx.storage.sql.exec("DELETE FROM events WHERE created_at<? AND state NOT IN ('forwarding','echo_pending','agent_pending','submitted')",now-7*86400000);
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS handoffs(conversation_id TEXT PRIMARY KEY,reason TEXT NOT NULL,created_at INTEGER NOT NULL)');
    this.ctx.storage.sql.exec('DELETE FROM handoffs WHERE created_at<?',now-7*86400000);
    const next=this.ctx.storage.sql.exec<{due:number|null}>("SELECT MIN(next_at) AS due FROM events WHERE state IN ('forwarding','echo_pending','agent_pending','submitted')").one().due;
    const stuck=this.ctx.storage.sql.exec<{due:number|null}>("SELECT MIN(next_at+60000) AS due FROM events WHERE state='echo_inline'").one().due;
    const cleanup=this.ctx.storage.sql.exec<{due:number|null}>("SELECT MIN(created_at+604800000) AS due FROM events WHERE state NOT IN ('forwarding','echo_pending','agent_pending','submitted')").one().due;
    const deadline=Math.min(next??Infinity,stuck??Infinity,cleanup??Infinity);
    if(Number.isFinite(deadline))await this.ctx.storage.setAlarm(Math.max(Date.now()+1000,deadline));
  }
  // Single-row executor: deadline, submitted-status poll, verify-late /
  // legacy serve, and the budget guard. Shared by the alarm loop (durable
  // backstop) and the waitUntil fast path (first attempt runs on the hot
  // isolate instead of waiting out alarm scheduling). Races between the
  // two are safe: agent turns replay by requestKey and submits dedup by
  // claim, so a double-run wastes work but never double-sends.
  async #driveRow(config:Registration,row:EventRow,now:number):Promise<void>{
    try{
        if(now-row.created_at>86400000){this.ctx.storage.sql.exec("UPDATE events SET state='needs_attention',payload=NULL,error='retry_deadline' WHERE id=?",row.id);return;}
        if(row.state==='submitted'&&row.request_id){
          const status=await authed(this.env).status(config,row.request_id);
          if(status.state!=='pending'){
            this.ctx.storage.sql.exec('UPDATE events SET state=?,payload=NULL,error=? WHERE id=?',status.state,status.errors?.join(',').slice(0,500)||null,row.id);
            return;
          }
        }else{
          if(!row.payload)throw new Error('missing_encrypted_turn');
          const turn=await open<Turn>(this.env.PROXY_ENCRYPTION_KEY,`${config.id}:${row.id}`,row.payload);
          // Verify-late rows (async accept without transcript proof): prove
          // the transcript here, overlapping the agent turn with the
          // visibility wait. Legacy rows (no sealed reference) were
          // accept-verified under previous code; forwarding rows keep their
          // confirmInbound proof. Neither re-verifies.
          if(turn.verifyLate===true&&typeof turn.reference==='string'&&turn.reference&&row.state!=='forwarding'&&config.browser){
            await this.#serveLateTurn(config,row,turn as Turn&{reference:string});
            return;
          }
          // Handoff guard (retry path): a row that went durable before the
          // handoff must not answer once the session is handed off. Latched
          // conversations suppress BEFORE any async work (no agent spend);
          // the live re-check otherwise rides concurrently with the agent
          // turn (suppression still wins over submit; the live read is
          // fail-open so it never throws into the join).
          const latched=this.#handoffLatch(turn.conversationId);
          if(latched){await this.#suppressTurn(config,row.id,turn.conversationId,latched);return;}
          const handoffPromise=this.#isHandedOff(config,turn.conversationId);
          if(row.state==='forwarding'&&!await authed(this.env).confirmInbound(config,turn.conversationId,turn.messageId,turn.text))throw new Error('scrt_acceptance_unconfirmed');
          // Agent-only durable executor: run a REAL agentcode turn for the
          // sealed visitor turn, then submit the AGENT REPLY. Visitor text is
          // never submitted (legacy pre-retirement echo_pending rows drain
          // through this same path). Failures throw into the budget guard
          // below (deterministic park, attempt cap, else backoff); the 24h
          // deadline stays the backstop and parks honestly as needs_attention.
          const binding=this.env.AGENTCODE;
          if(!binding||typeof binding.agentTurn!=='function')throw new Error('agent_unavailable');
          const tAgentStart=Date.now();let tAgentDone=0;
          const agentTimed=signedAgent(binding,this.env.AGENT_RPC_KEY).agentTurn(config,
            {conversationId:turn.conversationId,text:turn.text,requestKey:row.id,
              ...(turn.messageId?{messageId:turn.messageId}:{}),channelId:turn.channelId??config.channelId,orgId:turn.orgId??config.orgId,
              ...(turn.linked?{linked:turn.linked}:{})}).then(v=>{tAgentDone=Date.now();return v;},e=>{tAgentDone=Date.now();throw e;});
          const [handoffReason,agentRaw]=await Promise.all([handoffPromise,agentTimed]);
          if(handoffReason){await this.#suppressTurn(config,row.id,turn.conversationId,handoffReason);return;}
          const agentResult=shapeAgentResult(agentRaw);
          if(!agentResult)throw new Error('agent_reply_invalid');
          if('handoff' in agentResult&&agentResult.handoff){
            this.ctx.storage.sql.exec("UPDATE events SET state='handed_off',payload=NULL,error=NULL WHERE id=?",row.id);
            await this.#latchHandoff(turn.conversationId,'agent_verdict');
            return;
          }
          if('released' in agentResult&&agentResult.released){
            this.ctx.storage.sql.exec("UPDATE events SET state='released',payload=NULL,error=NULL WHERE id=?",row.id);
            return;
          }
          const result=await authed(this.env).echo(config,config.action,{conversationId:turn.conversationId,text:(agentResult as {reply:string}).reply,requestKey:row.id,channelId:turn.channelId??config.channelId,orgId:turn.orgId??config.orgId});
          if(!result||!/^[A-Za-z0-9]{15,18}$/.test(result.requestId||''))throw new Error('agent_submit_unconfirmed');
          this.ctx.storage.sql.exec("UPDATE events SET state='submitted',request_id=?,next_at=?,error=NULL WHERE id=?",result.requestId,Date.now()+2000,row.id);
          const tSubmit=Date.now();
          await this.#pushToConversation(turn.conversationId,{type:'progress',requestKey:row.id,
            tAccept:row.created_at,tAgentStart,tAgentDone,tSubmit});
          this.ctx.storage.sql.exec('UPDATE visitors SET agent_session=? WHERE conversation_id=?',turn.conversationId,turn.conversationId);
        }
        this.ctx.storage.sql.exec('UPDATE events SET attempts=attempts+1,next_at=? WHERE id=?',Date.now()+2000,row.id);
      }catch(cause){
        const message=String((cause as Error)?.message??cause);
        const attempts=row.attempts+1;
        // Deterministic failures never heal: park on the first alarm pass
        // with the cause preserved, payload NULLed as the deadline path does.
        if(message.startsWith('LINKED_')||TERMINAL_ALARM_CAUSES.has(message)){
          this.ctx.storage.sql.exec("UPDATE events SET state='needs_attention',payload=NULL,attempts=attempts+1,error=? WHERE id=?",message.slice(0,200),row.id);
          console.warn(JSON.stringify({event:'agent_alarm_parked',requestKey:row.id,state:row.state,attempts,cause:message.slice(0,200),reason:'deterministic'}));
          return;
        }
        // Transient failures keep backoff, bounded by the attempt budget. The
        // submitted branch (cheap status poll, no agent turn) is exempt.
        if(attempts>=MAX_ALARM_ATTEMPTS&&!(row.state==='submitted'&&row.request_id)){
          this.ctx.storage.sql.exec("UPDATE events SET state='needs_attention',payload=NULL,attempts=attempts+1,error=? WHERE id=?",'retry_attempts_exhausted:'+message.slice(0,200),row.id);
          console.warn(JSON.stringify({event:'agent_alarm_parked',requestKey:row.id,state:row.state,attempts,cause:message.slice(0,200),reason:'attempts_exhausted'}));
          return;
        }
        const delay=Math.min(300000,2000*2**Math.min(row.attempts,8));
        this.ctx.storage.sql.exec("UPDATE events SET attempts=attempts+1,next_at=?,error='broker_retry_pending' WHERE id=?",Date.now()+delay,row.id);
        console.warn(JSON.stringify({event:'agent_alarm_retry',requestKey:row.id,state:row.state,attempts,cause:message.slice(0,200)}));
      }
  }
  async #driveParked(config:Registration,requestKey:string):Promise<void>{
    // waitUntil fast path: re-read fresh (the row may have resolved) and
    // drive only still-pending agent work. Throws into the caller's catch
    // (the alarm backstop replays); never throws for resolved rows.
    const row=this.#event(requestKey);
    if(!row||row.state!=='agent_pending')return;
    await this.#driveRow(config,row,Date.now());
    await this.#rearm();
  }
  // Park + immediate execute: the turn is durably parked with a backstop
  // horizon, the alarm stays armed AT that horizon (no spurious immediate
  // fire), and the first attempt runs NOW on the hot isolate via waitUntil
  // instead of waiting out ~1.5s of alarm scheduling (measured live).
  // Backstop races are safe (see #driveRow); a dead waitUntil replays from
  // the alarm at horizon. Bounded legs (verify-late poll 12s, agent 8s
  // tail, handoff race 5s) total ~25s serial, far below the horizon; only
  // a hung platform callout past 60s overlaps the backstop, and that
  // corner stays send-safe (agent replay + submit claim dedup).
  async #parkForExecutor(requestKey:string,error:string):Promise<void>{
    this.ctx.storage.sql.exec("UPDATE events SET state='agent_pending',next_at=?,error=? WHERE id=?",Date.now()+WAITUNTIL_BACKSTOP_MS,error,requestKey);
    await this.#schedule(WAITUNTIL_BACKSTOP_MS);
    const config=await this.#config();
    if(!config||config.disabled)return;
    this.ctx.waitUntil(this.#driveParked(config,requestKey).catch((cause:unknown)=>{
      console.warn(JSON.stringify({event:'agent_waituntil_failed',requestKey,cause:String((cause as Error)?.message??cause).slice(0,200)}));
    }));
  }
}
export default {
  async fetch(request:Request,env:ProxyEnv):Promise<Response>{
    const match=new URL(request.url).pathname.match(/^\/p\/([^/]+)\//);
    if(!match||!uuid.test(match[1]))return reply('not_found',404);
    try{return await env.REGISTRATIONS.getByName(match[1]).fetch(request);}catch(cause){console.error(JSON.stringify({event:'proxy_do_fetch_failed',route:match[1],cause:String((cause as Error)?.message??cause).slice(0,300)}));return reply('proxy_unavailable',503);}
  }
} satisfies ExportedHandler<ProxyEnv>;
