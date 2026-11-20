import {describe, expect, it} from 'bun:test';
import {RPC_CALLER_ID, assertCallerKey, assertOrgId, deriveOrgKey, signRpcArgs, signedBroker, stableJson, type RpcSignedEnvelope} from './rpc-sign';
import type {Broker} from './contracts';

const KEY32 = 'fixed-test-key-0123456789abcdef01';
const SCOPE = {teamId: 'team_1', orgId: '00Dxx0000000001AAA', channelId: '0Mjxx0000000001AAA'};

describe('rpc-sign stableJson', () => {
  it('sorts object keys recursively', () => {
    expect(stableJson({b: 1, a: {d: 4, c: 3}})).toBe('{"a":{"c":3,"d":4},"b":1}');
  });
  it('preserves array order and encodes Uint8Array as a list', () => {
    expect(stableJson([{b: 1, a: 2}, null, 'x'])).toBe('[{"a":2,"b":1},null,"x"]');
    expect(stableJson(new Uint8Array([1, 2, 250]))).toBe('[1,2,250]');
  });
  it('passes scalars through JSON encoding', () => {
    expect(stableJson(null)).toBe('null');
    expect(stableJson(42)).toBe('42');
    expect(stableJson('s')).toBe('"s"');
  });
});

describe('rpc-sign envelope shape', () => {
  it('emits caller proxy with org, a 10-digit timestamp and 24-char nonce', async () => {
    const env = await signRpcArgs(KEY32, SCOPE.orgId, 'echo', [SCOPE]);
    expect(RPC_CALLER_ID).toBe('proxy');
    expect(Object.keys(env).sort()).toEqual(['caller', 'nonce', 'org', 'signature', 'timestamp']);
    expect(env.caller).toBe('proxy');
    expect(env.org).toBe(SCOPE.orgId);
    expect(env.timestamp).toMatch(/^\d{10}$/);
    expect(Math.abs(Date.now() / 1000 - Number(env.timestamp))).toBeLessThan(60);
    expect(env.nonce).toMatch(/^[A-Za-z0-9_-]{24}$/);
    expect(env.signature).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it('uses a fresh nonce per call', async () => {
    const a = await signRpcArgs(KEY32, SCOPE.orgId, 'echo', [SCOPE]);
    const b = await signRpcArgs(KEY32, SCOPE.orgId, 'echo', [SCOPE]);
    expect(a.nonce).not.toBe(b.nonce);
  });
  it('derives distinct keys per org', async () => {
    const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
    const a = hex(await deriveOrgKey(KEY32, SCOPE.orgId));
    expect(hex(await deriveOrgKey(KEY32, SCOPE.orgId))).toBe(a);
    expect(hex(await deriveOrgKey(KEY32, '00Dxx0000000002AAA'))).not.toBe(a);
  });
});

describe('rpc-sign fixed vector', () => {
  it('matches an independent inline WebCrypto recomputation', async () => {
    const method = 'echo';
    const timestamp = '1700000000';
    const nonce = 'ABCDEFGHIJKLMNOPQRSTUVWX';
    const args = [SCOPE, {conversationId: 'c1', text: 'hello', requestKey: 'k1'}];
    // Independent reimplementation: no shared code with rpc-sign below this line.
    const j: (v: any) => any = (v: any) => {
      if (v === null || typeof v !== 'object') return JSON.stringify(v);
      if (v instanceof Uint8Array) return JSON.stringify(Array.from(v));
      if (Array.isArray(v)) return '[' + v.map(j).join(',') + ']';
      return '{' + Object.keys(v).sort().map((k: string) => JSON.stringify(k) + ':' + j(v[k])).join(',') + '}';
    };
    const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(j(args))));
    const digest = Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
    const canonical = ['proxy', SCOPE.orgId, method, timestamp, nonce, digest].join('\n');
    const ikm = await crypto.subtle.importKey('raw', new TextEncoder().encode(KEY32), 'HKDF', false, ['deriveBits']);
    const ok = new Uint8Array(await crypto.subtle.deriveBits(
      {name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('tubot-rpc-org-v1'),
       info: new TextEncoder().encode('proxy\n' + SCOPE.orgId)}, ikm, 256));
    const k = await crypto.subtle.importKey('raw', ok, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
    const expected = b64u(new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(canonical))));
    const actual = await signRpcArgs(KEY32, SCOPE.orgId, method, args, {timestamp, nonce});
    expect(actual).toEqual({caller: 'proxy', org: SCOPE.orgId, timestamp, nonce, signature: expected});
    const again = await signRpcArgs(KEY32, SCOPE.orgId, method, args, {timestamp, nonce});
    expect(again.signature).toBe(expected);
  });
});

describe('rpc-sign fail fast', () => {
  it('rejects missing and short keys, accepts a 32-char key', async () => {
    expect(() => assertCallerKey(undefined)).toThrow('rpc_caller_key_not_configured');
    expect(() => assertCallerKey('')).toThrow('rpc_caller_key_not_configured');
    expect(() => assertCallerKey('x'.repeat(31))).toThrow('rpc_caller_key_not_configured');
    expect(assertCallerKey(KEY32)).toBe(KEY32);
    await expect(signRpcArgs('', SCOPE.orgId, 'echo', [])).rejects.toThrow('rpc_caller_key_not_configured');
    await expect(signRpcArgs('x'.repeat(31), SCOPE.orgId, 'echo', [])).rejects.toThrow('rpc_caller_key_not_configured');
  });
  it('rejects malformed orgs and binds the wrapper envelope to scope.orgId', async () => {
    expect(() => assertOrgId(undefined)).toThrow('rpc_org_not_configured');
    expect(() => assertOrgId('00Dshort')).toThrow('rpc_org_not_configured');
    await expect(signRpcArgs(KEY32, 'bad', 'echo', [SCOPE])).rejects.toThrow('rpc_org_not_configured');
    const calls: unknown[][] = [];
    const fake = {echo: async (...a: unknown[]) => { calls.push(a); return {}; }} as unknown as Broker;
    const wrapped = signedBroker(fake, KEY32);
    await wrapped.echo(SCOPE, {} as never, {} as never);
    expect((calls[0][calls[0].length - 1] as RpcSignedEnvelope).org).toBe(SCOPE.orgId);
    expect(() => wrapped.echo({teamId: 't', channelId: 'c'} as never, {} as never, {} as never))
      .toThrow('rpc_org_not_configured');
  });
  it('signedBroker throws synchronously before any RPC can be sent', () => {
    let called = 0;
    const fake = {authorize: async () => { called++; }} as unknown as Broker;
    expect(() => signedBroker(fake, '')).toThrow('rpc_caller_key_not_configured');
    expect(() => signedBroker(fake, 'short')).toThrow('rpc_caller_key_not_configured');
    expect(called).toBe(0);
  });
});

describe('rpc-sign broker wrapper', () => {
  const recording = () => {
    const calls: {method: string; args: unknown[]}[] = [];
    const rec = (method: string) => async (...args: unknown[]) => { calls.push({method, args}); return method === 'confirmInbound' ? true : {}; };
    const fake = {
      authorize: rec('authorize'), validate: rec('validate'), browserTurn: rec('browserTurn'),
      browserSync: rec('browserSync'), echo: rec('echo'), status: rec('status'), confirmInbound: rec('confirmInbound'),
      sessionState: rec('sessionState'), resolveFlowRoute: rec('resolveFlowRoute'),
    } as unknown as Broker;
    return {calls, wrapped: signedBroker(fake, KEY32)};
  };
  const envelopeOf = (args: unknown[]): RpcSignedEnvelope => {
    const signed = args[args.length - 1] as RpcSignedEnvelope;
    expect(signed.caller).toBe('proxy');
    expect(signed.org).toBe(SCOPE.orgId);
    expect(signed.timestamp).toMatch(/^\d{10}$/);
    expect(signed.nonce).toMatch(/^[A-Za-z0-9_-]{24}$/);
    expect(signed.signature).toMatch(/^[A-Za-z0-9_-]+$/);
    return signed;
  };
  it('appends a trailing signed envelope and preserves business args', async () => {
    const {calls, wrapped} = recording();
    const turn = {conversationId: 'c1', text: 'hi', requestKey: 'k1'};
    await wrapped.echo(SCOPE, {name: 'N', definitionName: 'D', inputMapping: {definition: 'a', recipients: 'b', parameters: 'c'}, outputMapping: {requestId: 'r'}} as never, turn);
    expect(calls).toHaveLength(1);
    expect(calls[0].args.slice(0, -1)).toEqual([SCOPE, expect.anything(), turn]);
    envelopeOf(calls[0].args);
  });
  it('signs every Broker method (echo retired: no merged turn RPC)', async () => {
    const {calls, wrapped} = recording();
    await wrapped.authorize(SCOPE);
    await wrapped.validate(SCOPE, {} as never);
    await wrapped.browserTurn(SCOPE, {} as never, {} as never);
    await wrapped.echo(SCOPE, {} as never, {} as never);
    await wrapped.status(SCOPE, 'req-1');
    await wrapped.confirmInbound(SCOPE, 'c1', 'm1', 'hi');
    await wrapped.sessionState!(SCOPE, 'c1');
    await wrapped.resolveFlowRoute!(SCOPE, {} as never);
    expect(calls.map(c => c.method)).toEqual(['authorize', 'validate', 'browserTurn', 'echo', 'status', 'confirmInbound', 'sessionState', 'resolveFlowRoute']);
    for (const c of calls) envelopeOf(c.args);
  });
});
