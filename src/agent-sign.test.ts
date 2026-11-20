import {describe, expect, it} from 'bun:test';
import {AGENT_RPC_CALLER_ID, deriveAgentOrgKey, signAgentRpcArgs, signedAgent, type AgentRpcSignedEnvelope} from './agent-sign';
import {deriveOrgKey} from './rpc-sign';
import type {AgentService, AgentTurnResult} from './contracts';

const KEY32 = 'fixed-test-key-0123456789abcdef01';
const SCOPE = {teamId: 'team_1', orgId: '00Dxx0000000001AAA', channelId: '0Mjxx0000000001AAA'};
const TURN = {conversationId: 'c1', text: 'hello', requestKey: 'k1'};

describe('agent-sign envelope shape', () => {
  it('emits caller proxy-agent with org, a 10-digit timestamp and 24-char nonce', async () => {
    const env = await signAgentRpcArgs(KEY32, SCOPE.orgId, 'agentTurn', [SCOPE, TURN]);
    expect(AGENT_RPC_CALLER_ID).toBe('proxy-agent');
    expect(Object.keys(env).sort()).toEqual(['caller', 'nonce', 'org', 'signature', 'timestamp']);
    expect(env.caller).toBe('proxy-agent');
    expect(env.org).toBe(SCOPE.orgId);
    expect(env.timestamp).toMatch(/^\d{10}$/);
    expect(env.nonce).toMatch(/^[A-Za-z0-9_-]{24}$/);
    expect(env.signature).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it('uses a fresh nonce per call', async () => {
    const a = await signAgentRpcArgs(KEY32, SCOPE.orgId, 'agentTurn', [SCOPE, TURN]);
    const b = await signAgentRpcArgs(KEY32, SCOPE.orgId, 'agentTurn', [SCOPE, TURN]);
    expect(a.nonce).not.toBe(b.nonce);
  });
  it('derives keys distinct from the broker caller id for the same org', async () => {
    const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
    const agent = hex(await deriveAgentOrgKey(KEY32, SCOPE.orgId));
    expect(hex(await deriveAgentOrgKey(KEY32, SCOPE.orgId))).toBe(agent);
    expect(hex(await deriveAgentOrgKey(KEY32, '00Dxx0000000002AAA'))).not.toBe(agent);
    expect(hex(await deriveOrgKey(KEY32, SCOPE.orgId))).not.toBe(agent);
  });
});

describe('agent-sign fixed vector', () => {
  it('matches an independent inline WebCrypto recomputation', async () => {
    const method = 'agentTurn';
    const timestamp = '1700000000';
    const nonce = 'ABCDEFGHIJKLMNOPQRSTUVWX';
    const args = [SCOPE, TURN];
    // Independent reimplementation: no shared code with agent-sign below this line.
    const j: (v: any) => any = (v: any) => {
      if (v === null || typeof v !== 'object') return JSON.stringify(v);
      if (v instanceof Uint8Array) return JSON.stringify(Array.from(v));
      if (Array.isArray(v)) return '[' + v.map(j).join(',') + ']';
      return '{' + Object.keys(v).sort().map((k: string) => JSON.stringify(k) + ':' + j(v[k])).join(',') + '}';
    };
    const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(j(args))));
    const digest = Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
    const canonical = ['proxy-agent', SCOPE.orgId, method, timestamp, nonce, digest].join('\n');
    const ikm = await crypto.subtle.importKey('raw', new TextEncoder().encode(KEY32), 'HKDF', false, ['deriveBits']);
    const ok = new Uint8Array(await crypto.subtle.deriveBits(
      {name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('tubot-rpc-org-v1'),
       info: new TextEncoder().encode('proxy-agent\n' + SCOPE.orgId)}, ikm, 256));
    const k = await crypto.subtle.importKey('raw', ok, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
    const expected = b64u(new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(canonical))));
    const actual = await signAgentRpcArgs(KEY32, SCOPE.orgId, method, args, {timestamp, nonce});
    expect(actual).toEqual({caller: 'proxy-agent', org: SCOPE.orgId, timestamp, nonce, signature: expected});
    const again = await signAgentRpcArgs(KEY32, SCOPE.orgId, method, args, {timestamp, nonce});
    expect(again.signature).toBe(expected);
  });
});

describe('agent-sign fail fast', () => {
  it('rejects missing and short keys, and malformed orgs', async () => {
    await expect(signAgentRpcArgs('', SCOPE.orgId, 'agentTurn', [])).rejects.toThrow('rpc_caller_key_not_configured');
    await expect(signAgentRpcArgs('x'.repeat(31), SCOPE.orgId, 'agentTurn', [])).rejects.toThrow('rpc_caller_key_not_configured');
    await expect(signAgentRpcArgs(KEY32, 'bad', 'agentTurn', [SCOPE])).rejects.toThrow('rpc_org_not_configured');
  });
  it('signedAgent throws synchronously before any RPC can be sent', () => {
    let called = 0;
    const fake = {agentTurn: async () => { called++; return {} as AgentTurnResult; }} as unknown as AgentService;
    expect(() => signedAgent(fake, '')).toThrow('rpc_caller_key_not_configured');
    expect(() => signedAgent(fake, 'short')).toThrow('rpc_caller_key_not_configured');
    expect(called).toBe(0);
  });
});

describe('agent-sign service wrapper', () => {
  it('appends a trailing signed envelope bound to scope.orgId and preserves business args', async () => {
    const calls: unknown[][] = [];
    const fake = {agentTurn: async (...a: unknown[]) => { calls.push(a); return {reply: 'hi', handoff: false, spans: {agentMs: 1}}; }} as unknown as AgentService;
    const wrapped = signedAgent(fake, KEY32);
    const out = await wrapped.agentTurn(SCOPE, TURN);
    expect(out).toEqual({reply: 'hi', handoff: false, spans: {agentMs: 1}});
    expect(calls).toHaveLength(1);
    expect(calls[0].slice(0, -1)).toEqual([SCOPE, TURN]);
    const signed = calls[0][calls[0].length - 1] as AgentRpcSignedEnvelope;
    expect(signed.caller).toBe('proxy-agent');
    expect(signed.org).toBe(SCOPE.orgId);
    expect(signed.timestamp).toMatch(/^\d{10}$/);
    expect(signed.nonce).toMatch(/^[A-Za-z0-9_-]{24}$/);
    expect(signed.signature).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(() => wrapped.agentTurn({teamId: 't', channelId: 'c'} as never, TURN))
      .toThrow('rpc_org_not_configured');
  });
});
