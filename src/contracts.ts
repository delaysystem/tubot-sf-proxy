export interface TenantScope { teamId: string; orgId: string; channelId: string }
export interface EchoAction {
  name: string;
  definitionName: string;
  inputMapping: { definition: string; recipients: string; parameters: string };
  outputMapping: { requestId: string };
}
export type AgentMode = 'echo' | 'agent';
export interface ProxyConfig {
  deploymentName: string; browserDeploymentName?: string; action: EchoAction;
  /** Cached agent name for the channel, bound at registration. Absent on legacy routes. */
  agentName?: string;
  /** Stored routing mode. Serving is agent-only regardless of this value:
   * legacy 'echo'/absent routes run the agent executor too. Kept for stored
   * registrations; new registrations always write 'agent'. */
  agentMode?: AgentMode;
  /** Expected tubot queue (Salesforce Group.DeveloperName) for live sessions on
   * this route, bound at registration per org/route. Absent on legacy routes:
   * the handoff guard then skips the queue comparison and only honors the
   * escalated flag plus the per-conversation handoff latch. */
  expectedQueueName?: string;
}
export interface BrowserConfig {
  /** Canonical primary: the Experience site origin serving the widget. */
  origin: string;
  /** Exact-match allow-set for the browser Origin gate (primary + VF test-page
   * origin). Absent on registrations stored before the V1 snippet path: the
   * gate falls back to [origin] so those routes keep working unchanged. */
  origins?: string[];
  apiVersion: string; visitorField: string; visitorFields?: string[];
}
export interface Registration extends TenantScope, ProxyConfig {
  id: string; scrtOrigin: string; keyHashes: string[]; createdAt: number; disabled: boolean;
  browser?: BrowserConfig;
}
/** Retired: echo serving is agent-only now; verify (browserTurn) + agentTurn +
 * submit (echo of the AGENT REPLY) replaced the merged verify+submit path. */
/** Verify verdict for a browser turn. On 'verified', recipient carries the
 * server-resolved MessagingEndUser id so the later echo submit can skip its
 * duplicate session query (agent path); absent otherwise. */
export interface BrowserVerifyResult {code:string;recipient?:string}
export interface BrowserSyncEntry {
  messageId: string;
  text: string;
  timestamp: number;
}
export interface BrowserSyncResult {
  conversationId: string | null;
  conversationEnded?: boolean;
  entries: BrowserSyncEntry[];
}
export interface EchoTurn {conversationId:string;text:string;requestKey:string;channelId?:string;orgId?:string;
  /** Recipient relayed from the verify result. Echo format-validates it and
   * falls back to its session query when absent or malformed. */
  recipient?:string}
export interface AgentTurn {conversationId:string;text:string;requestKey:string;messageId?:string;channelId?:string;orgId?:string}
/** Verify input. knownEntries carries transcript entries the proxy already
 * fetched via Salesforce in this same serve (sync discovery), so verify can
 * skip its duplicate entries fetch; the session-binding check always stays
 * live. Server-side only: never populated from client input. Absent on the
 * echo path and alarm retries, which verify with a fresh fetch. */
export interface BrowserTurnInput {reference:string;conversationId:string;messageId:string;text:string;knownEntries?:BrowserSyncEntry[]}
export interface AgentTurnResult {reply:string;handoff:boolean;released?:boolean;spans:{agentMs:number;[k:string]:number|string|undefined}}
/** Live session handoff state, resolved by the broker from MessagingSession
 * handoff fields and/or PendingServiceRouting QueueId. Null means the session
 * is unknown (not yet created or unreadable): callers fail open. */
export interface SessionHandoffState {
  /** In-flight escalation signal (Escalate_To_Human__c). */
  escalated: boolean;
  /** Current queue DeveloperName, or null when the session has no live routing. */
  queueName: string | null;
  /** Current queue/route target id, or null when unknown. Informational only. */
  queueId: string | null;
}
export interface Broker {
  authorize(scope: TenantScope): Promise<void>;
  validate(scope: TenantScope, config: ProxyConfig): Promise<{ scrtOrigin: string; browser?: BrowserConfig }>;
  browserTurn(scope: TenantScope, config: BrowserConfig, turn: BrowserTurnInput): Promise<BrowserVerifyResult>;
  browserSync?(scope: TenantScope, config: BrowserConfig, input: {reference:string;conversationId?:string;sinceMs?:number}): Promise<BrowserSyncResult>;
  echo(scope: TenantScope, action: EchoAction, turn: EchoTurn): Promise<{ requestId: string }>;
  status(scope: TenantScope, requestId: string): Promise<{ state: 'pending' | 'delivered' | 'failed'; errors?: string[] }>;
  confirmInbound(scope: TenantScope, conversationId: string, messageId: string, text?: string): Promise<boolean>;
  /** Live handoff lookup. Optional: older brokers lack it and the guard
   * degrades to the per-conversation latch. Scope-first like every method. */
  sessionState?(scope: TenantScope, conversationId: string): Promise<SessionHandoffState | null>;
  /** Flow-route pre-resolve (F5). Read-only: warms the broker's cached Flow
   * action resolution so a later submit finds it warm. Optional: older
   * brokers lack it and submit re-resolves serially as today. Scope-first
   * like every method. */
  resolveFlowRoute?(scope: TenantScope, action: EchoAction): Promise<{ok:true}>;
}
export interface ProxyAdminService {
  register(input: TenantScope & ProxyConfig & { secureKeys: string[] }): Promise<{ id: string; baseUrl: string }>;
  inspect(scope: TenantScope, id: string): Promise<unknown>;
  revoke(scope: TenantScope, id: string): Promise<void>;
}
/** Agentcode turn service. Served by the AGENTCODE binding; signed per the agent RPC contract. */
export interface AgentService {
  agentTurn(scope: TenantScope, turn: AgentTurn): Promise<AgentTurnResult>;
}
const ORG_RE = /^00D[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?$/;
const CHANNEL_RE = /^0Mj[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?$/;
export const validOrgId = (v: unknown): v is string => typeof v === 'string' && ORG_RE.test(v);
export const validChannelId = (v: unknown): v is string => typeof v === 'string' && CHANNEL_RE.test(v);
export function validScope(scope: TenantScope): boolean {
  return !!scope && typeof scope.teamId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(scope.teamId)
    && validOrgId(scope.orgId)
    && validChannelId(scope.channelId);
}
/** A turn's echoed scope must be absent (derived from RPC scope) or exactly match it. */
export function turnScopeMatches(scope: TenantScope, turn: { channelId?: unknown; orgId?: unknown }): boolean {
  if (turn.channelId !== undefined && (!validChannelId(turn.channelId) || turn.channelId !== scope.channelId)) return false;
  if (turn.orgId !== undefined && (!validOrgId(turn.orgId) || turn.orgId !== scope.orgId)) return false;
  return true;
}
export function validConfig(config: ProxyConfig): boolean {
  const a = config?.action;
  const name = (v: unknown) => typeof v === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,159}$/.test(v);
  return !!a && name(config.deploymentName) && (config.browserDeploymentName===undefined||name(config.browserDeploymentName)) && name(a.name) && name(a.definitionName)
    && !!a.inputMapping && !!a.outputMapping
    && ['definition', 'recipients', 'parameters'].every(k => name(a.inputMapping[k as keyof EchoAction['inputMapping']]))
    && new Set(Object.values(a.inputMapping)).size === 3
    && name(a.outputMapping.requestId)
    && (config.agentName===undefined||validAgentName(config.agentName))
    && (config.agentMode===undefined||config.agentMode==='echo'||config.agentMode==='agent')
    && (config.expectedQueueName===undefined||validQueueName(config.expectedQueueName));
}
/** Queue DeveloperNames: letter-led, letters/digits/underscores, max 80 chars. */
export const validQueueName = (v: unknown): v is string =>
  typeof v === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,79}$/.test(v);
/** Accept only the agreed live-state shape; anything else fails open upstream. */
export function validSessionHandoffState(v: unknown): v is SessionHandoffState {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const s = v as Record<string, unknown>;
  return (s.escalated === true || s.escalated === false)
    && (s.queueName === null || validQueueName(s.queueName))
    && (s.queueId === null || (typeof s.queueId === 'string' && /^[A-Za-z0-9]{15,18}$/.test(s.queueId)));
}
/** Agent display names are flow free-text, so any non-blank string up to 160 chars passes. */
export const validAgentName = (v: unknown): v is string =>
  typeof v === 'string' && v.trim().length >= 1 && v.length <= 160;
export const AGENT_TEXT_MAX = 4096;
export function validAgentTurn(turn: AgentTurn): boolean {
  return !!turn && typeof turn.conversationId === 'string' && turn.conversationId.length >= 1
    && typeof turn.text === 'string' && turn.text.length >= 1 && turn.text.length <= AGENT_TEXT_MAX
    && typeof turn.requestKey === 'string' && turn.requestKey.length >= 1
    && (turn.messageId===undefined||(typeof turn.messageId==='string'&&turn.messageId.length>=1));
}
