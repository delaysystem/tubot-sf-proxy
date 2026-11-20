import type {AgentService} from './contracts';
import {assertCallerKey, assertOrgId, stableJson} from './rpc-sign';

/** Caller id the proxy signs proxy→agentcode RPC with. Distinct from the
 *  SF_BROKER caller id so per-org keys and envelopes never cross services. */
export const AGENT_RPC_CALLER_ID = 'proxy-agent' as const;

export interface AgentRpcSignedEnvelope {
  caller: typeof AGENT_RPC_CALLER_ID;
  org: string;
  timestamp: string;
  nonce: string;
  signature: string;
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

/** Per-org HMAC key: HKDF-SHA256(masterKey, "tubot-rpc-org-v1", caller + "\n" + orgId). */
export async function deriveAgentOrgKey(masterKey: string, orgId: string): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey('raw', new TextEncoder().encode(masterKey), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('tubot-rpc-org-v1'),
     info: new TextEncoder().encode(`${AGENT_RPC_CALLER_ID}\n${orgId}`)},
    ikm, 256);
  return new Uint8Array(bits);
}

export async function signAgentRpcArgs(key: string, org: string, method: string, businessArgs: unknown[], opts?: {timestamp?: string; nonce?: string}): Promise<AgentRpcSignedEnvelope> {
  assertCallerKey(key);
  assertOrgId(org);
  const timestamp = opts?.timestamp ?? Math.floor(Date.now() / 1000).toString();
  const nonce = opts?.nonce ?? base64url(crypto.getRandomValues(new Uint8Array(18)));
  const argsDigest = await sha256Hex(stableJson(businessArgs));
  const canonical = `${AGENT_RPC_CALLER_ID}\n${org}\n${method}\n${timestamp}\n${nonce}\n${argsDigest}`;
  const signature = await hmacBase64url(await deriveAgentOrgKey(key, org), canonical);
  return {caller: AGENT_RPC_CALLER_ID, org, timestamp, nonce, signature};
}

/**
 * Single choke point for AGENTCODE RPC. Every method signs its positional
 * business args and appends the envelope as the trailing 'signed' arg.
 * Throws synchronously on a missing/short key, so no unsigned RPC can be sent.
 * The envelope org is bound to the scope-first arg every agent method takes.
 * Plain explicit-method object: never wrap a Workers RPC stub in a Proxy.
 */
export function signedAgent(agent: AgentService, key: string): AgentService {
  assertCallerKey(key);
  const wire = agent as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
  const call = <T>(method: string, businessArgs: unknown[]): Promise<T> => {
    const scope = businessArgs[0] as {orgId?: unknown} | undefined;
    const org = assertOrgId(scope?.orgId);
    return signAgentRpcArgs(key, org, method, businessArgs)
      .then(signed => wire[method](...businessArgs, signed) as Promise<T>);
  };
  return {
    agentTurn: (scope, turn) => call<import('./contracts').AgentTurnResult>('agentTurn', [scope, turn]),
  };
}
