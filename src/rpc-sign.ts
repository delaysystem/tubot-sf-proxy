import type {Broker} from './contracts';

/** Caller id this repo signs as. Must match the frozen RPC-signing contract. */
export const RPC_CALLER_ID = 'proxy' as const;

export interface RpcSignedEnvelope {
  caller: typeof RPC_CALLER_ID;
  org: string;
  timestamp: string;
  nonce: string;
  signature: string;
}

export function stableJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (v instanceof Uint8Array) return JSON.stringify(Array.from(v));
  if (Array.isArray(v)) return '[' + v.map(stableJson).join(',') + ']';
  const o = v as Record<string, unknown>;
  return '{' + Object.keys(o).sort().map(k => JSON.stringify(k) + ':' + stableJson(o[k])).join(',') + '}';
}

function base64url(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function sha256Hex(data: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return Array.from(new Uint8Array(d), b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacBase64url(keyBytes: Uint8Array, data: string): Promise<string> {
  const k = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  return base64url(new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(data))));
}

/** Fail-fast key check: throws when the caller key is missing or short. Never returns an unusable key. */
export function assertCallerKey(key: unknown): string {
  if (typeof key !== 'string' || key.length < 32) throw new Error('rpc_caller_key_not_configured');
  return key;
}

const ORG_RE = /^[A-Za-z0-9]{15,18}$/;

/** Fail-fast org check: throws on a malformed Salesforce org id. */
export function assertOrgId(org: unknown): string {
  if (typeof org !== 'string' || !ORG_RE.test(org)) throw new Error('rpc_org_not_configured');
  return org;
}

/** Per-org HMAC key: HKDF-SHA256(masterKey, "tubot-rpc-org-v1", caller + "\n" + orgId). */
export async function deriveOrgKey(masterKey: string, orgId: string): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey('raw', new TextEncoder().encode(masterKey), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('tubot-rpc-org-v1'),
     info: new TextEncoder().encode(`${RPC_CALLER_ID}\n${orgId}`)},
    ikm, 256);
  return new Uint8Array(bits);
}

export async function signRpcArgs(key: string, org: string, method: string, businessArgs: unknown[], opts?: {timestamp?: string; nonce?: string}): Promise<RpcSignedEnvelope> {
  assertCallerKey(key);
  assertOrgId(org);
  const timestamp = opts?.timestamp ?? Math.floor(Date.now() / 1000).toString();
  const nonce = opts?.nonce ?? base64url(crypto.getRandomValues(new Uint8Array(18)));
  const argsDigest = await sha256Hex(stableJson(businessArgs));
  const canonical = `${RPC_CALLER_ID}\n${org}\n${method}\n${timestamp}\n${nonce}\n${argsDigest}`;
  const signature = await hmacBase64url(await deriveOrgKey(key, org), canonical);
  return {caller: RPC_CALLER_ID, org, timestamp, nonce, signature};
}

/**
 * Single choke point for SF_BROKER RPC. Every method signs its positional
 * business args and appends the envelope as the trailing 'signed' arg.
 * Throws synchronously on a missing/short key, so no unsigned RPC can be sent.
 * The envelope org is bound to the scope-first arg every broker method takes.
 */
export function signedBroker(broker: Broker, key: string): Broker {
  assertCallerKey(key);
  const wire = broker as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
  const call = <T>(method: string, businessArgs: unknown[]): Promise<T> => {
    const scope = businessArgs[0] as {orgId?: unknown} | undefined;
    const org = assertOrgId(scope?.orgId);
    return signRpcArgs(key, org, method, businessArgs)
      .then(signed => wire[method](...businessArgs, signed) as Promise<T>);
  };
  return {
    authorize: scope => call<void>('authorize', [scope]),
    validate: (scope, config) => call<{scrtOrigin: string; browser?: import('./contracts').BrowserConfig}>('validate', [scope, config]),
    browserTurn: (scope, config, turn) => call<import('./contracts').BrowserVerifyResult>('browserTurn', [scope, config, turn]),
    browserSync: (scope, config, input) => call<import('./contracts').BrowserSyncResult>('browserSync', [scope, config, input]),
    echo: (scope, action, turn) => call<{requestId: string}>('echo', [scope, action, turn]),
    status: (scope, requestId) => call<{state: 'pending' | 'delivered' | 'failed'; errors?: string[]}>('status', [scope, requestId]),
    confirmInbound: (scope, conversationId, messageId, text) => call<boolean>('confirmInbound', [scope, conversationId, messageId, text]),
    sessionState: (scope, conversationId) => call<import('./contracts').SessionHandoffState | null>('sessionState', [scope, conversationId]),
    resolveFlowRoute: (scope, action) => call<{ok:true}>('resolveFlowRoute', [scope, action]),
  };
}
