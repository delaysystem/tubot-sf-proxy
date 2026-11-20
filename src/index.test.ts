import { describe, expect, mock, test } from "bun:test";
// Wiring step 2: proxy executor swap. The Durable Object is exercised through
// its real fetch() surface with a bun:sqlite-backed storage shim (same engine
// family as workerd) and fake SF_BROKER / AGENTCODE bindings.
mock.module("cloudflare:workers", () => ({
  DurableObject: class { ctx: unknown; env: unknown; constructor(ctx: unknown, env: unknown) { this.ctx = ctx; this.env = env; } },
  WorkerEntrypoint: class { ctx: unknown; env: unknown; constructor(ctx: unknown, env: unknown) { this.ctx = ctx; this.env = env; } },
  // partyserver imports { DurableObject, env }: env is only a default-arg
  // fallback for routePartykitRequest (never called here), so {} suffices.
  env: {},
}));
import { Database } from "bun:sqlite";

const { ProxyRegistration, ProxyAdmin } = await import("./index");

const ORG = "00Dxx0000000001AAA";
const CHANNEL = "0Mjxx0000000001AAA";
const ORIGIN = "https://site.example";
const CALLER_KEY = "k".repeat(32);
// Step 4 dedicated agent key: deliberately distinct from CALLER_KEY so the
// choke-point assertion below proves the agent signer reads AGENT_RPC_KEY.
const AGENT_KEY = "a".repeat(32);
const { signAgentRpcArgs } = await import("./agent-sign");
const ECHO_REQUEST_ID = "1sr000000000002AA";

const flowAction = () => ({
  name: "Tubot_Proxy_Send_Notification", definitionName: "Tubot_Proxy_Echo",
  inputMapping: { definition: "definitionName", recipients: "recipients", parameters: "parameters" },
  outputMapping: { requestId: "requestId" },
});

function makeCtx() {
  const db = new Database(":memory:");
  const sql = {
    exec(query: string, ...params: unknown[]) {
      const rows = db.query(query).all(...params) as Record<string, unknown>[];
      return {
        toArray: () => rows,
        one: () => {
          if (rows.length !== 1) throw new Error(`expected one row, got ${rows.length}`);
          return rows[0];
        },
      };
    },
  };
  const kv = new Map<string, unknown>();
  let alarm: number | null = null;
  // waitUntil capture (production DurableObject ctx always provides it):
  // promises run eagerly like on workerd, but tests settle them explicitly
  // via flush() for determinism — awaiting an alarm pass does NOT settle an
  // in-flight drive. Capture count pins the park contract (exactly one
  // immediate drive per parked turn).
  const waitings: Promise<unknown>[] = [];
  const ctx = {
    storage: {
      sql,
      transactionSync: (fn: () => unknown) => fn(),
      get: async (k: string) => kv.get(k) ?? null,
      put: async (k: string, v: unknown) => { kv.set(k, v); },
      getAlarm: async () => alarm,
      setAlarm: async (t: number) => { alarm = t; },
      deleteAlarm: async () => { alarm = null; },
    },
    waitUntil: (p: Promise<unknown>) => { waitings.push(p); },
  };
  const flush = async () => { while (waitings.length) { await Promise.all(waitings.splice(0)); } };
  return { ctx, sql, alarm: () => alarm, flush, waitings: () => waitings.length };
}

function makeBroker(over: Record<string, (...a: never[]) => Promise<unknown>> = {}) {
  const calls: { method: string; args: unknown[] }[] = [];
  const broker = {
    authorize: async (...a: never[]) => { calls.push({ method: "authorize", args: a }); },
    validate: async (...a: never[]) => { calls.push({ method: "validate", args: a }); return { scrtOrigin: "https://x" }; },
    browserTurn: async (...a: never[]) => { calls.push({ method: "browserTurn", args: a }); return "verified"; },
    browserSync: async (...a: never[]) => { calls.push({ method: "browserSync", args: a }); return { conversationId: null, entries: [] }; },
    echo: async (...a: never[]) => { calls.push({ method: "echo", args: a }); return { requestId: ECHO_REQUEST_ID }; },
    status: async (...a: never[]) => { calls.push({ method: "status", args: a }); return { state: "pending" }; },
    confirmInbound: async (...a: never[]) => { calls.push({ method: "confirmInbound", args: a }); return true; },
    ...over,
  };
  return { broker, calls };
}

function baseReg(id: string) {
  return {
    id, teamId: "team_1", orgId: ORG, channelId: CHANNEL, deploymentName: "ApiDeployment",
    action: flowAction(),
    scrtOrigin: "https://example.scrt", createdAt: Date.now(), disabled: false, keyHashes: [],
    browser: { origin: ORIGIN, apiVersion: "v59.0", visitorField: "Proxy_Echo_Visitor_Ref__c" },
  };
}

type AgentImpl = (t: Record<string, unknown>) => unknown;

async function setup(opts: {
  reg?: Record<string, unknown>;
  broker?: Record<string, (...a: never[]) => Promise<unknown>>;
  agent?: AgentImpl | null;
  env?: Record<string, unknown>;
} = {}) {
  const { ctx, sql, alarm, flush, waitings } = makeCtx();
  const { broker, calls } = makeBroker(opts.broker);
  const turns: { scope: Record<string, unknown>; turn: Record<string, unknown>; signed: unknown }[] = [];
  const agentBinding = opts.agent === null || opts.agent === undefined ? undefined : {
    agentTurn: async (scope: unknown, turn: unknown, signed: unknown) => {
      turns.push({ scope: scope as Record<string, unknown>, turn: turn as Record<string, unknown>, signed });
      return opts.agent!(turn as Record<string, unknown>);
    },
  };
  const env = {
    REGISTRATIONS: {}, SF_BROKER: broker, SF_AUTH_CALLER_KEY: CALLER_KEY, AGENT_RPC_KEY: AGENT_KEY,
    PROXY_ENCRYPTION_KEY: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64"),
    PROXY_PUBLIC_ORIGIN: "https://proxy.example",
    ...(agentBinding ? { AGENTCODE: agentBinding } : {}),
    ...(opts.env ?? {}),
  };
  const reg = { ...baseReg(crypto.randomUUID()), ...(opts.reg ?? {}) };
  const stub = new ProxyRegistration(ctx as never, env as never);
  await stub.configure(reg as never);
  return { stub, sql, calls, turns, alarm, reg, flush, waitings };
}

async function mint(stub: { fetch(r: Request): Promise<Response> }, reg: { id: string }) {
  const res = await stub.fetch(new Request(`https://proxy/p/${reg.id}/browser/session`, {
    method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" }, body: "{}",
  }));
  const json = (await res.json()) as Record<string, unknown>;
  return { res, json, cookie: (res.headers.get("Set-Cookie") ?? "").split(";")[0] };
}

async function postEcho(stub: { fetch(r: Request): Promise<Response> }, reg: { id: string }, cookie: string, body: unknown) {
  const res = await stub.fetch(new Request(`https://proxy/p/${reg.id}/browser/echo`, {
    method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json", Cookie: cookie }, body: JSON.stringify(body),
  }));
  return { res, json: (await res.json()) as Record<string, unknown> };
}

const agentReg = { agentMode: "agent", agentName: "Support Agent" };
const methods = (calls: { method: string }[]) => calls.map((c) => c.method);

describe("agent executor (wiring step 2)", () => {
  test("multi-turn pinning: first turn writes the anchor, later turns re-assert it, agent reply is echoed", async () => {
    const s = await setup({
      reg: agentReg,
      agent: (t) => ({ reply: "AGENT SAYS HI", handoff: false, spans: { agentMs: 7 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const msg = crypto.randomUUID();
    const first = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: msg, text: "hello human" });
    expect(first.res.status).toBe(202);
    expect(first.json.accepted).toBe(true);
    expect(first.json.inline).toBe(true);
    expect(first.json.requestId).toBe(ECHO_REQUEST_ID);
    expect(first.json.requestKey).toMatch(/^[a-f0-9]{64}$/);
    const timings = first.json.timings as Record<string, unknown>;
    for (const k of ["verifyMs", "agentMs", "submitMs", "roundMs"]) expect(typeof timings[k]).toBe("number");
    expect(timings.agentMs).toBe(7);
    expect(JSON.stringify(first.json)).not.toContain("AGENT SAYS HI");
    // Canonical agentTurn(scope, turn): scope carries org/channel, turn carries the message.
    expect(s.turns.length).toBe(1);
    expect(s.turns[0].scope.teamId).toBe("team_1");
    expect(s.turns[0].scope.orgId).toBe(ORG);
    expect(s.turns[0].scope.channelId).toBe(CHANNEL);
    expect(s.turns[0].turn).toEqual({
      conversationId: conv, text: "hello human", requestKey: first.json.requestKey,
      messageId: msg, channelId: CHANNEL, orgId: ORG,
    });
    // Signed through the agent choke point, never unsigned, and under the
    // DEDICATED agent key: the captured envelope recomputes byte-identical
    // with AGENT_RPC_KEY (and would differ under SF_AUTH_CALLER_KEY).
    const signed = s.turns[0].signed as Record<string, unknown>;
    expect(signed.caller).toBe("proxy-agent");
    expect(signed.org).toBe(ORG);
    const recomputed = await signAgentRpcArgs(AGENT_KEY, ORG, "agentTurn", [s.turns[0].scope, s.turns[0].turn], {
      timestamp: signed.timestamp as string, nonce: signed.nonce as string,
    });
    expect(recomputed.signature).toBe(signed.signature);
    // Broker verify ran with the visitor turn.
    const verify = s.calls.find((c) => c.method === "browserTurn")!;
    expect(verify).toBeDefined();
    expect(verify.args[1]).toEqual(s.reg.browser);
    expect(verify.args[2]).toEqual({
      reference: expect.stringMatching(/^[a-f0-9]{64}$/), conversationId: conv, messageId: msg, text: "hello human",
    });
    // The AGENT REPLY (not visitor text) went through the echo submitter.
    const submitted = s.calls.find((c) => c.method === "echo")!;
    expect(submitted.args[2]).toEqual({
      conversationId: conv, text: "AGENT SAYS HI", requestKey: first.json.requestKey, channelId: CHANNEL, orgId: ORG,
    });
    expect(s.sql.exec("SELECT agent_session AS x FROM visitors").one().x).toBe(conv);
    const row = s.sql.exec("SELECT state, request_id AS r FROM events").one();
    expect(row.state).toBe("submitted");
    expect(row.r).toBe(ECHO_REQUEST_ID);
    // Second turn re-asserts the same pinned anchor; pin stays put.
    const second = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "second" });
    expect(second.res.status).toBe(202);
    expect(second.json.inline).toBe(true);
    expect(s.turns.length).toBe(2);
    expect(s.turns[1].turn.conversationId).toBe(conv);
    expect(s.sql.exec("SELECT agent_session AS x FROM visitors").one().x).toBe(conv);
  });

  test("winning-rung ids ride the accept timings; other strings never leak", async () => {
    const s = await setup({
      reg: agentReg,
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1, provider: "google-direct", model: "gemini-3.5-flash-lite", note: "<drop me>" } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    const timings = r.json.timings as Record<string, unknown>;
    expect(timings.provider).toBe("google-direct");
    expect(timings.model).toBe("gemini-3.5-flash-lite");
    expect("note" in timings).toBe(false);
  });

  test("agent mode without a bound name still runs the agent path", async () => {
    const s = await setup({ reg: { agentMode: "agent" }, agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }) });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(true);
    expect(s.turns.length).toBe(1);
  });

  test("retries dedup without re-running the agent", async () => {
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }) });
    const { cookie } = await mint(s.stub, s.reg);
    const body = { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" };
    const first = await postEcho(s.stub, s.reg, cookie, body);
    expect(first.json.inline).toBe(true);
    const retry = await postEcho(s.stub, s.reg, cookie, body);
    expect(retry.res.status).toBe(202);
    expect(retry.json).toEqual({ accepted: true, requestKey: first.json.requestKey });
    expect(s.turns.length).toBe(1);
  });

  test("stale pin mismatch forbids before any row is created", async () => {
    const convA = crypto.randomUUID();
    // Faithful broker: only the known conversation verifies (a real broker
    // never verifies a random unknown conversation), so the adoption probe
    // fails and the mismatch still fails closed.
    const s = await setup({
      reg: agentReg,
      broker: {
        browserTurn: async (...a: never[]) => {
          const t = (a[2] ?? {}) as { conversationId?: unknown };
          return t.conversationId === convA ? "verified" : "binding_absent";
        },
      },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const first = await postEcho(s.stub, s.reg, cookie, { conversationId: convA, messageId: crypto.randomUUID(), text: "one" });
    expect(first.json.inline).toBe(true);
    // Simulate a stale pin against a cleared binding (only reachable via
    // direct storage surgery; the conversation binding normally gates first).
    s.sql.exec("UPDATE visitors SET conversation_id=NULL WHERE agent_session IS NOT NULL");
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "two" });
    expect(r.res.status).toBe(403);
    expect(r.json).toEqual({ error: "conversation_forbidden" });
    expect(s.turns.length).toBe(1);
    expect(s.sql.exec("SELECT COUNT(*) AS n FROM events").one().n).toBe(1);
  });

  test("same-reference second conversation adopts instead of forbidding", async () => {
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }) });
    const { cookie } = await mint(s.stub, s.reg);
    const convA = crypto.randomUUID();
    const first = await postEcho(s.stub, s.reg, cookie, { conversationId: convA, messageId: crypto.randomUUID(), text: "one" });
    expect(first.json.inline).toBe(true);
    // Second conversation under the same page session (missed close event,
    // reload with a new chat): the broker proves the same reference, so the
    // stale pin adopts instead of 403ing every turn forever (default stub
    // verifies, mirroring a same-reference conversation).
    const convB = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: convB, messageId: crypto.randomUUID(), text: "two" });
    expect(r.res.status).toBe(202);
    expect(r.json.accepted).toBe(true);
    expect(s.turns.length).toBe(2);
    expect(s.sql.exec("SELECT conversation_id AS c, agent_session AS a FROM visitors").one()).toEqual({ c: convB, a: convB });
  });

  test("handoff skips the echo, parks the row, and keeps the conversation live", async () => {
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "SHOULD NOT ECHO", handoff: true, spans: { agentMs: 3 } }) });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "help me human" });
    expect(r.res.status).toBe(202);
    expect(r.json.accepted).toBe(true);
    expect(r.json.inline).toBe(true);
    expect(r.json.handoff).toBe(true);
    expect(r.json.requestId).toBeUndefined();
    expect(JSON.stringify(r.json)).not.toContain("SHOULD NOT ECHO");
    expect(methods(s.calls)).not.toContain("echo");
    const row = s.sql.exec("SELECT state, payload, request_id AS r FROM events").one();
    expect(row.state).toBe("handed_off");
    expect(row.payload).toBeNull();
    expect(row.r).toBeNull();
    const visitor = s.sql.exec("SELECT conversation_id AS c, agent_session AS x FROM visitors").one();
    expect(visitor.c).toBe(conv);
    expect(visitor.x).toBe(conv);
    // The agent verdict latches the conversation for the handoff guard.
    expect(s.sql.exec("SELECT reason AS r FROM handoffs").one().r).toBe("agent_verdict");
    // Conversation stays live: a later visitor turn is accepted, not
    // forbidden — but the guard suppresses it without re-invoking agentcode.
    const next = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "still here" });
    expect(next.res.status).toBe(202);
    expect(next.json.accepted).toBe(true);
    expect(next.json.handoff).toBe(true);
    expect(next.json.suppressed).toBe(true);
    expect(next.json.requestId).toBeUndefined();
    expect(s.turns.length).toBe(1);
    expect(methods(s.calls)).not.toContain("echo");
    const rows = s.sql.exec("SELECT state, error AS e FROM events ORDER BY created_at").toArray();
    expect(rows).toHaveLength(2);
    expect(rows[1].state).toBe("handed_off");
    expect(rows[1].e).toBe("suppressed_after_handoff");
  });

  test("released skips the echo and parks without latching, so follow-ups re-derive", async () => {
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "", handoff: false, released: true, spans: { agentMs: 3 } }) });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "over the cap" });
    expect(r.res.status).toBe(202);
    expect(r.json.accepted).toBe(true);
    expect(r.json.released).toBe(true);
    expect(r.json.requestId).toBeUndefined();
    expect(methods(s.calls)).not.toContain("echo");
    const row = s.sql.exec("SELECT state, payload, request_id AS r FROM events").one();
    expect(row.state).toBe("released");
    expect(row.payload).toBeNull();
    expect(row.r).toBeNull();
    // No latch: native routing proceeds, and the next turn re-invokes
    // agentcode (which re-derives release while the team stays over cap).
    expect(s.sql.exec("SELECT reason AS r FROM handoffs").toArray()).toHaveLength(0);
    const next = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "still here" });
    expect(next.res.status).toBe(202);
    expect(next.json.released).toBe(true);
    expect(s.turns.length).toBe(2);
    expect(methods(s.calls)).not.toContain("echo");
  });

  test("legacy registrations serve agent-only: echo/absent agentMode still runs real agentcode", async () => {
    for (const reg of [{}, { agentMode: "echo" }, { agentMode: "echo", agentName: "Support Agent" }]) {
      const s = await setup({ reg, agent: () => ({ reply: "AGENT REPLY", handoff: false, spans: { agentMs: 5 } }) });
      const { cookie } = await mint(s.stub, s.reg);
      const conv = crypto.randomUUID(); const msg = crypto.randomUUID();
      const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: msg, text: "hi" });
      expect(r.res.status).toBe(202);
      expect(r.json.accepted).toBe(true);
      expect(r.json.inline).toBe(true);
      expect(r.json.requestId).toBe(ECHO_REQUEST_ID);
      expect(s.turns.length).toBe(1);
      expect(s.turns[0].turn.text).toBe("hi");
      // The AGENT REPLY (never visitor text) went through the submitter.
      const submitted = s.calls.find((c) => c.method === "echo")!;
      expect((submitted.args[2] as Record<string, unknown>).text).toBe("AGENT REPLY");
      expect(s.sql.exec("SELECT agent_session AS x FROM visitors").one().x).toBe(conv);
    }
  });

  test("agent throw degrades to 202 + immediate retry with no agent text", async () => {
    const s = await setup({ reg: agentReg, agent: () => { throw new Error("boom exploded internals"); } });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json).toEqual({
      accepted: true, requestKey: expect.stringMatching(/^[a-f0-9]{64}$/),
      inline: false, timings: { roundMs: expect.any(Number) },
    });
    expect(JSON.stringify(r.json)).not.toContain("boom");
    expect(s.waitings()).toBe(1);
    expect(s.alarm()).not.toBeNull();
    // The immediate drive is the retry: one inline attempt + one drive
    // attempt, transiently parked, nothing submitted, no leak.
    await s.flush();
    expect(s.turns.length).toBe(2);
    expect(methods(s.calls)).not.toContain("echo");
    const row = s.sql.exec("SELECT state, error AS e, attempts AS n FROM events").one();
    expect(row.state).toBe("agent_pending");
    expect(row.e).toBe("broker_retry_pending");
    expect(row.n).toBe(1);
    expect(s.alarm()).not.toBeNull();
  });

  test("malformed agent results fall back without emitting", async () => {
    const bad = ["", "x".repeat(4097), 42, null, undefined];
    for (const reply of bad) {
      const s = await setup({ reg: agentReg, agent: () => ({ reply, handoff: false, spans: { agentMs: 1 } }) });
      const { cookie } = await mint(s.stub, s.reg);
      const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
      expect(r.res.status).toBe(202);
      expect(r.json.inline).toBe(false);
      expect(r.json.requestId).toBeUndefined();
      expect(methods(s.calls)).not.toContain("echo");
      expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
    }
    const s = await setup({ reg: agentReg, agent: () => null });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(false);
  });

  test("verify rejection matches the rejection shape and clears pinning", async () => {
    for (const [code, status] of [["binding_absent", 403], ["invalid_turn", 400], ["session_pending", 503]] as const) {
      let verdict: string = "verified";
      const s = await setup({
        reg: agentReg, agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
        broker: { browserTurn: async () => verdict },
      });
      const { cookie } = await mint(s.stub, s.reg);
      const conv = crypto.randomUUID();
      const ok = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "one" });
      expect(ok.json.inline).toBe(true);
      expect(s.sql.exec("SELECT agent_session AS x FROM visitors").one().x).toBe(conv);
      verdict = code;
      const echoesBefore = methods(s.calls).filter((m) => m === "echo").length;
      const rej = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "two" });
      expect(rej.res.status).toBe(status);
      expect(rej.json).toEqual({ error: code });
      expect(s.turns.length).toBe(1);
      expect(methods(s.calls).filter((m) => m === "echo").length).toBe(echoesBefore);
      expect(s.sql.exec("SELECT COUNT(*) AS n FROM events").one().n).toBe(1);
      const visitor = s.sql.exec("SELECT conversation_id AS c, agent_session AS x FROM visitors").one();
      expect(visitor.c).toBeNull();
      expect(visitor.x).toBeNull();
    }
  });

  test("object verdict threads recipient into echo; malformed verdict fails closed", async () => {
    const s = await setup({
      reg: agentReg, agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
      broker: { browserTurn: async () => ({ code: "verified", recipient: "0oW000000000001EAA" }) },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const ok = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "one" });
    expect(ok.json.inline).toBe(true);
    const echoCall = s.calls.find((c) => c.method === "echo")!;
    expect((echoCall.args[2] as Record<string, unknown>).recipient).toBe("0oW000000000001EAA");
    const s2 = await setup({
      reg: agentReg, agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
      broker: { browserTurn: async () => ({ nope: 1 }) },
    });
    const { cookie: cookie2 } = await mint(s2.stub, s2.reg);
    const bad = await postEcho(s2.stub, s2.reg, cookie2, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "two" });
    expect(bad.res.status).toBe(400);
    expect(bad.json).toEqual({ error: "invalid_turn" });
  });

  test("verify transport failure degrades to 202 + alarm retry", async () => {
    const s = await setup({
      reg: agentReg, agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
      broker: { browserTurn: async () => { throw new Error("browser_binding_unavailable"); } },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.inline).toBe(false);
    expect(s.turns.length).toBe(0);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
    expect(s.alarm()).not.toBeNull();
  });

  test("missing AGENTCODE binding degrades to alarm retry, never 500", async () => {
    const s = await setup({ reg: agentReg, agent: null });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.inline).toBe(false);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
  });

  test("agent spans are scrubbed to finite numbers under allow-listed keys", async () => {
    const s = await setup({
      reg: agentReg,
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 7, evil: "x", nested: { a: 1 }, inf: Infinity, "has-dash": 1, "": 2, arr: [1] } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(true);
    const timings = r.json.timings as Record<string, unknown>;
    expect(timings.agentMs).toBe(7);
    for (const [k, v] of Object.entries(timings)) {
      expect(k).toMatch(/^[A-Za-z][A-Za-z0-9_]{0,31}$/);
      expect(typeof v).toBe("number");
    }
    expect(JSON.stringify(r.json)).not.toContain("evil");
  });

  test("retry after agent inline failure runs a REAL agent turn, never visitor text", async () => {
    let calls = 0;
    const s = await setup({
      reg: agentReg,
      agent: () => { calls++; if (calls === 1) throw new Error("agent down"); return { reply: "RETRY AGENT REPLY", handoff: false, spans: { agentMs: 9 } }; },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID(); const msg = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: msg, text: "visitor words" });
    expect(r.json.inline).toBe(false);
    // No alarm fire anywhere in this test: the captured immediate drive is
    // the retry, and the alarm stays armed as the durable backstop.
    expect(s.waitings()).toBe(1);
    expect(s.alarm()).not.toBeNull();
    await s.flush();
    // The drive re-ran agentcode (second turn) and submitted the AGENT REPLY.
    expect(s.turns.length).toBe(2);
    expect(s.turns[1].turn.requestKey).toBe(r.json.requestKey);
    const submitted = s.calls.find((c) => c.method === "echo")!;
    expect((submitted.args[2] as Record<string, unknown>).text).toBe("RETRY AGENT REPLY");
    const row = s.sql.exec("SELECT state, request_id AS r FROM events").one();
    expect(row.state).toBe("submitted");
    expect(row.r).toBe(ECHO_REQUEST_ID);
    // Drive-resolved turns pin the conversation like inline turns.
    expect(s.sql.exec("SELECT agent_session AS x FROM visitors").one().x).toBe(conv);
  });

  test("retry with agent still down parks honestly and never submits visitor text", async () => {
    const s = await setup({ reg: agentReg, agent: () => { throw new Error("agent down"); } });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "visitor words" });
    expect(r.json.inline).toBe(false);
    await s.flush();
    expect(methods(s.calls)).not.toContain("echo");
    const row = s.sql.exec("SELECT state, error AS e, attempts AS n FROM events").one();
    expect(row.state).toBe("agent_pending");
    expect(row.e).toBe("broker_retry_pending");
    expect(row.n).toBe(1);
  });

  test("legacy pre-retirement echo_pending rows drain through the agent path", async () => {
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "DRAINED AGENT REPLY", handoff: false, spans: { agentMs: 1 } }) });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID(); const msg = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: msg, text: "visitor words" });
    expect(r.json.inline).toBe(true);
    // Rewrite the row as a pre-retirement leftover: submitted state rolled
    // back to echo_pending is impossible inline, so simulate via storage.
    s.sql.exec("UPDATE events SET state='echo_pending', request_id=NULL, next_at=? WHERE state='submitted'", Date.now());
    await s.stub.alarm();
    const submitted = s.calls.filter((c) => c.method === "echo").at(-1)!;
    expect((submitted.args[2] as Record<string, unknown>).text).toBe("DRAINED AGENT REPLY");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("register persists agent binding fields; legacy input stays clean", async () => {
    const { broker } = makeBroker();
    const stored = new Map<string, unknown>();
    const env = {
      REGISTRATIONS: { getByName: (id: string) => ({ configure: async (r: unknown) => { stored.set(id, r); } }) },
      SF_BROKER: broker, SF_AUTH_CALLER_KEY: CALLER_KEY,
      PROXY_ENCRYPTION_KEY: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64"),
      PROXY_PUBLIC_ORIGIN: "https://proxy.example",
    };
    const admin = new ProxyAdmin({}, env as never);
    const scope = { teamId: "team_1", orgId: ORG, channelId: CHANNEL };
    const agent = await admin.register({ ...scope, deploymentName: "ApiDeployment", action: flowAction() as never, agentName: "Support Agent", agentMode: "agent", expectedQueueName: "Tubot_Queue", secureKeys: ["s".repeat(40)] });
    expect(agent.baseUrl).toBe(`https://proxy.example/p/${agent.id}`);
    const withAgent = stored.get(agent.id) as Record<string, unknown>;
    expect(withAgent.agentName).toBe("Support Agent");
    expect(withAgent.agentMode).toBe("agent");
    expect(withAgent.expectedQueueName).toBe("Tubot_Queue");
    const legacy = await admin.register({ ...scope, deploymentName: "ApiDeployment", action: flowAction() as never, secureKeys: ["s".repeat(40)] });
    const withoutAgent = stored.get(legacy.id) as Record<string, unknown>;
    expect("agentName" in withoutAgent).toBe(false);
    expect("agentMode" in withoutAgent).toBe(false);
    expect("expectedQueueName" in withoutAgent).toBe(false);
  });

  test("verify and handoff guard overlap: both start before either finishes", async () => {
    let release!: () => void;
    const gate = new Promise<void>((done) => { release = done; });
    const started: string[] = [];
    let bothAtRelease = false;
    const s = await setup({
      reg: agentReg,
      broker: {
        browserTurn: async () => { started.push("verify"); await gate; return "verified"; },
        sessionState: async () => { started.push("handoff"); await gate; return { escalated: false, queueName: null, queueId: null }; },
      },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const pending = postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    await Bun.sleep(50);
    bothAtRelease = started.includes("verify") && started.includes("handoff");
    release();
    const r = await pending;
    expect(bothAtRelease).toBe(true);
    expect(r.res.status).toBe(202);
    expect(r.json.inline).toBe(true);
    expect(r.json.requestId).toBe(ECHO_REQUEST_ID);
  });

  test("verify rejection keeps precedence over handoff suppression", async () => {
    const s = await setup({
      reg: agentReg,
      broker: {
        browserTurn: async () => "binding_absent",
        sessionState: async () => ({ escalated: true, queueName: "Tubot_Queue", queueId: null }),
      },
      agent: () => ({ reply: "MUST NOT SEND", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(403);
    expect(r.json).toEqual({ error: "binding_absent" });
    expect(s.turns.length).toBe(0);
  });

  test("F5: Flow-route pre-resolve starts with the agent turn, off the critical path", async () => {
    let release!: () => void;
    const gate = new Promise<void>((done) => { release = done; });
    const started: string[] = [];
    const preArgs: unknown[][] = [];
    let bothAtRelease = false;
    const s = await setup({
      reg: agentReg,
      broker: {
        resolveFlowRoute: async (...a: never[]) => { started.push("preresolve"); preArgs.push(a); await gate; return { ok: true }; },
      },
      agent: async () => { started.push("agent"); await gate; return { reply: "R", handoff: false, spans: { agentMs: 1 } }; },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const pending = postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    await Bun.sleep(50);
    bothAtRelease = started.includes("preresolve") && started.includes("agent");
    release();
    const r = await pending;
    expect(bothAtRelease).toBe(true);
    expect(r.res.status).toBe(202);
    expect(r.json.inline).toBe(true);
    expect(r.json.requestId).toBe(ECHO_REQUEST_ID);
    // Pre-resolve is scope-first with the registered Flow action.
    expect(preArgs).toHaveLength(1);
    expect(preArgs[0][0]).toEqual(expect.objectContaining({ teamId: "team_1", orgId: ORG, channelId: CHANNEL }));
    expect(preArgs[0][1]).toEqual(s.reg.action);
    // One pre-resolve, one submit: discovery is never paid twice.
    expect(methods(s.calls).filter((m) => m === "echo")).toHaveLength(1);
  });

  test("F5: submit drains a slow pre-resolve before echo, never submits first", async () => {
    let release!: () => void;
    const gate = new Promise<void>((done) => { release = done; });
    const s = await setup({
      reg: agentReg,
      broker: { resolveFlowRoute: async () => { await gate; return { ok: true }; } },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const pending = postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    await Bun.sleep(50);
    // Agent reply is in and validated, but echo must still be waiting.
    expect(methods(s.calls)).not.toContain("echo");
    release();
    const r = await pending;
    expect(r.json.inline).toBe(true);
    expect(r.json.requestId).toBe(ECHO_REQUEST_ID);
    expect(methods(s.calls).filter((m) => m === "echo")).toHaveLength(1);
  });

  test("F5: verify rejection skips pre-resolve and agent", async () => {
    let preResolved = false;
    const s = await setup({
      reg: agentReg,
      broker: {
        browserTurn: async () => "binding_absent",
        resolveFlowRoute: async () => { preResolved = true; return { ok: true }; },
      },
      agent: () => ({ reply: "MUST NOT SEND", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(403);
    expect(r.json).toEqual({ error: "binding_absent" });
    expect(s.turns.length).toBe(0);
    expect(preResolved).toBe(false);
    expect(methods(s.calls)).not.toContain("echo");
  });

  test("F5: handoff suppression skips pre-resolve and agent", async () => {
    let preResolved = false;
    const s = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      broker: {
        sessionState: async () => ({ escalated: true, queueName: "Tubot_Queue", queueId: null }),
        resolveFlowRoute: async () => { preResolved = true; return { ok: true }; },
      },
      agent: () => ({ reply: "MUST NOT SEND", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.suppressed).toBe(true);
    expect(s.turns.length).toBe(0);
    expect(preResolved).toBe(false);
    expect(methods(s.calls)).not.toContain("echo");
  });

  test("F5: pre-resolve failure fails open to a serial submit", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { resolveFlowRoute: async () => { throw new Error("discovery down"); } },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.inline).toBe(true);
    expect(r.json.requestId).toBe(ECHO_REQUEST_ID);
    expect(methods(s.calls).filter((m) => m === "echo")).toHaveLength(1);
  });

  test("F5: invalid agent reply still never submits, pre-resolve or not", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { resolveFlowRoute: async () => ({ ok: true }) },
      agent: () => ({ reply: "", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.inline).toBe(false);
    expect(r.json.requestId).toBeUndefined();
    expect(methods(s.calls)).not.toContain("echo");
  });
});

describe("202-async accept (flag-gated immediate executor)", () => {
  test("flag on: releases 202 and the immediate drive serves without an alarm fire", async () => {
    const s = await setup({
      reg: agentReg,
      env: { ASYNC_ACCEPT: "on" },
      agent: () => ({ reply: "ASYNC REPLY", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "hi async" });
    expect(r.res.status).toBe(202);
    expect(r.json.accepted).toBe(true);
    expect(r.json.inline).toBe(false);
    expect(r.json.requestId).toBeUndefined();
    expect(r.json.requestKey).toMatch(/^[a-f0-9]{64}$/);
    const timings = r.json.timings as Record<string, unknown>;
    for (const k of ["verifyMs", "handoffMs", "roundMs"]) expect(typeof timings[k]).toBe("number");
    expect(timings.agentMs).toBeUndefined();
    // Verify ran at accept (routing proof kept); the sealed turn parked with
    // exactly one captured immediate drive, and the alarm stays armed as the
    // backstop. (Pre-drive quiescence is unobservable: the drive starts
    // during accept, so agent/echo/pin state is asserted after the flush.)
    expect(methods(s.calls)).toContain("browserTurn");
    expect(s.waitings()).toBe(1);
    expect(s.alarm()).not.toBeNull();
    // No alarm fire anywhere in this test: the flush settles the immediate
    // drive, which serves the turn end to end and anchors the visitor pin.
    await s.flush();
    expect(s.turns.length).toBe(1);
    const echo = s.calls.find((c) => c.method === "echo")!;
    expect((echo.args[2] as Record<string, unknown>).text).toBe("ASYNC REPLY");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
    expect(s.sql.exec("SELECT agent_session AS x FROM visitors").one().x).toBe(conv);
  });

  test("flag on: rejected verify never parks, fails closed as before", async () => {
    const s = await setup({
      reg: agentReg,
      env: { ASYNC_ACCEPT: "on" },
      broker: { browserTurn: async () => "binding_absent" },
      agent: () => ({ reply: "MUST NOT RUN", handoff: false, spans: {} }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(403);
    expect(s.turns.length).toBe(0);
    expect(s.sql.exec("SELECT COUNT(*) AS n FROM events").one().n).toBe(0);
    expect(s.alarm()).toBeNull();
  });

  test("flag on: handoff suppression still wins over async park", async () => {
    const s = await setup({
      reg: agentReg,
      env: { ASYNC_ACCEPT: "true" },
      broker: { sessionState: async () => ({ escalated: true, queueName: "Tubot_Queue", queueId: null }) },
      agent: () => ({ reply: "MUST NOT RUN", handoff: false, spans: {} }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.suppressed).toBe(true);
    expect(s.turns.length).toBe(0);
    expect(s.sql.exec("SELECT state FROM events").one().state).not.toBe("agent_pending");
  });

  test("flag off or garbage: held inline path unchanged", async () => {
    for (const flag of [undefined, "off", "sometimes"]) {
      const s = await setup({
        reg: agentReg,
        ...(flag === undefined ? {} : { env: { ASYNC_ACCEPT: flag } }),
        agent: () => ({ reply: "HELD", handoff: false, spans: { agentMs: 1 } }),
      });
      const { cookie } = await mint(s.stub, s.reg);
      const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
      expect(r.json.inline).toBe(true);
      expect(r.json.requestId).toBe(ECHO_REQUEST_ID);
      expect(s.turns.length).toBe(1);
      expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
    }
  });
});

describe("handoff guard (proxy must not answer handed-off sessions)", () => {
  const SCOPE = { teamId: "team_1", orgId: ORG, channelId: CHANNEL };
  const live = (state: unknown) => ({ sessionState: async () => state });
  const suppressedCount = async (s: { stub: { inspect(s: unknown): Promise<unknown> } }) =>
    ((await s.stub.inspect(SCOPE)) as { suppressedHandoffTurns: number }).suppressedHandoffTurns;

  test("escalated live state suppresses the agent turn: no agent call, no echo, log + counter", async () => {
    const logs: string[] = [];
    const orig = console.log;
    console.log = (...a: unknown[]) => { logs.push(a.map(String).join(" ")); };
    try {
      let sessionStateCalls = 0;
      const s = await setup({
        reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
        broker: { sessionState: async () => { sessionStateCalls++; return { escalated: true, queueName: "Tubot_Queue", queueId: null }; } },
        agent: () => ({ reply: "MUST NOT SEND", handoff: false, spans: { agentMs: 1 } }),
      });
      const { cookie } = await mint(s.stub, s.reg);
      const conv = crypto.randomUUID();
      const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "hello after escalation" });
      expect(r.res.status).toBe(202);
      expect(r.json.accepted).toBe(true);
      expect(r.json.inline).toBe(true);
      expect(r.json.handoff).toBe(true);
      expect(r.json.suppressed).toBe(true);
      expect(r.json.requestId).toBeUndefined();
      expect(s.turns.length).toBe(0);
      expect(methods(s.calls)).not.toContain("echo");
      expect(sessionStateCalls).toBe(1);
      const row = s.sql.exec("SELECT state, payload, request_id AS r, error AS e FROM events").one();
      expect(row.state).toBe("handed_off");
      expect(row.payload).toBeNull();
      expect(row.r).toBeNull();
      expect(row.e).toBe("suppressed_after_handoff");
      expect(s.sql.exec("SELECT reason AS x FROM handoffs").one().x).toBe("escalated");
      expect(await suppressedCount(s)).toBe(1);
      const line = logs.map((l) => { try { return JSON.parse(l); } catch { return null; } })
        .find((o) => o && o.event === "handoff_turn_suppressed");
      expect(line).toBeDefined();
      expect(line.reason).toBe("escalated");
      expect(line.conversationId).toBe(conv);
      expect(line.total).toBe(1);
      expect(JSON.stringify(line)).not.toContain("hello after escalation");
      // Visitor binding stays live for humans.
      expect(s.sql.exec("SELECT conversation_id AS c FROM visitors").one().c).toBe(conv);
    } finally { console.log = orig; }
  });

  test("queue mismatch suppresses; matching queue runs the agent normally", async () => {
    const stateFor = (queueName: string | null) => ({ sessionState: async () => ({ escalated: false, queueName, queueId: null }) });
    const s = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      broker: stateFor("Chat_Queue"),
      agent: () => ({ reply: "MUST NOT SEND", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.suppressed).toBe(true);
    expect(s.turns.length).toBe(0);
    expect(s.sql.exec("SELECT reason AS x FROM handoffs").one().x).toBe("queue_mismatch");
    expect(await suppressedCount(s)).toBe(1);
    // Same route, session back in the expected queue: normal agent turn.
    const s2 = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      broker: stateFor("Tubot_Queue"),
      agent: () => ({ reply: "AGENT REPLY", handoff: false, spans: { agentMs: 1 } }),
    });
    const m2 = await mint(s2.stub, s2.reg);
    const r2 = await postEcho(s2.stub, s2.reg, m2.cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r2.json.inline).toBe(true);
    expect(r2.json.suppressed).toBeUndefined();
    expect(r2.json.requestId).toBe(ECHO_REQUEST_ID);
    expect(s2.turns.length).toBe(1);
    expect(await suppressedCount(s2)).toBe(0);
  });

  test("absent expected queue skips the comparison but still honors the escalated flag", async () => {
    const s = await setup({
      reg: agentReg,
      broker: live({ escalated: false, queueName: "Chat_Queue", queueId: null }),
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const ok = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(ok.json.inline).toBe(true);
    expect(ok.json.suppressed).toBeUndefined();
    expect(s.turns.length).toBe(1);
    const s2 = await setup({
      reg: agentReg,
      broker: live({ escalated: true, queueName: null, queueId: null }),
      agent: () => { throw new Error("agent must not run"); },
    });
    const m2 = await mint(s2.stub, s2.reg);
    const r2 = await postEcho(s2.stub, s2.reg, m2.cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r2.json.suppressed).toBe(true);
    expect(s2.turns.length).toBe(0);
  });

  test("unknown live state fails open: null, malformed, throw, and missing RPC all run normally", async () => {
    const states: unknown[] = [null, { escalated: "yes" }, 42, { escalated: false, queueName: "bad name", queueId: null }];
    for (const state of states) {
      const s = await setup({
        reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
        broker: live(state),
        agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
      });
      const { cookie } = await mint(s.stub, s.reg);
      const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
      expect(r.json.inline).toBe(true);
      expect(r.json.suppressed).toBeUndefined();
      expect(s.turns.length).toBe(1);
    }
    const throwing = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      broker: { sessionState: async () => { throw new Error("broker down"); } },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const mt = await mint(throwing.stub, throwing.reg);
    const rt = await postEcho(throwing.stub, throwing.reg, mt.cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(rt.json.inline).toBe(true);
    expect(throwing.turns.length).toBe(1);
    // Missing RPC (older brokers): no sessionState method at all.
    const legacy = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const ml = await mint(legacy.stub, legacy.reg);
    const rl = await postEcho(legacy.stub, legacy.reg, ml.cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(rl.json.inline).toBe(true);
    expect(rl.json.suppressed).toBeUndefined();
    expect(legacy.turns.length).toBe(1);
    expect(methods(legacy.calls)).not.toContain("sessionState");
  });

  test("suppression latches: later turns suppress locally even when live state clears", async () => {
    let escalated = true;
    const s = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      broker: { sessionState: async () => ({ escalated, queueName: "Tubot_Queue", queueId: null }) },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const first = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "one" });
    expect(first.json.suppressed).toBe(true);
    escalated = false;
    const second = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "two" });
    expect(second.res.status).toBe(202);
    expect(second.json.suppressed).toBe(true);
    expect(s.turns.length).toBe(0);
    expect(await suppressedCount(s)).toBe(2);
  });

  test("legacy-reg handed-off sessions suppress before any agent run", async () => {
    const s = await setup({
      reg: { expectedQueueName: "Tubot_Queue" },
      broker: live({ escalated: true, queueName: "Tubot_Queue", queueId: null }),
      agent: () => { throw new Error("agent must not run"); },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.suppressed).toBe(true);
    expect(r.json.requestId).toBeUndefined();
    expect(s.turns.length).toBe(0);
    expect(methods(s.calls)).not.toContain("echo");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("handed_off");
    expect(await suppressedCount(s)).toBe(1);
  });

  test("executor suppresses durable rows for handed-off conversations instead of echoing", async () => {
    // Inline agent failure parks agent_pending; the first drive fails too;
    // the handoff lands before the next pass, which must park handed_off
    // without any submit.
    let calls = 0;
    const s = await setup({
      reg: agentReg,
      agent: () => { calls++; if (calls <= 2) throw new Error("agent down"); return { reply: "R", handoff: false, spans: { agentMs: 1 } }; },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "visitor words" });
    expect(r.json.inline).toBe(false);
    await s.flush();
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
    s.sql.exec("INSERT INTO handoffs(conversation_id,reason,created_at) VALUES(?, 'agent_verdict', ?)", conv, Date.now());
    s.sql.exec("UPDATE events SET next_at=? WHERE state='agent_pending'", Date.now());
    await s.stub.alarm();
    expect(methods(s.calls)).not.toContain("echo");
    const row = s.sql.exec("SELECT state, payload, request_id AS r, error AS e FROM events").one();
    expect(row.state).toBe("handed_off");
    expect(row.payload).toBeNull();
    expect(row.r).toBeNull();
    expect(row.e).toBe("suppressed_after_handoff");
    expect(await suppressedCount(s)).toBe(1);
  });

  test("broker-unreachable fails open with a degraded log plus the unreachable counter", async () => {
    const logs: string[] = [];
    const orig = console.log;
    console.log = (...a: unknown[]) => { logs.push(a.map(String).join(" ")); };
    try {
      const s = await setup({
        reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
        broker: { sessionState: async () => { throw new Error("broker down"); } },
        agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
      });
      const { cookie } = await mint(s.stub, s.reg);
      const conv = crypto.randomUUID();
      const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "unreachable probe words" });
      expect(r.json.inline).toBe(true);
      expect(r.json.suppressed).toBeUndefined();
      expect(s.turns.length).toBe(1);
      const insp = (await s.stub.inspect(SCOPE)) as Record<string, unknown>;
      expect(insp.suppressedHandoffTurns).toBe(0);
      expect(insp.handoffLookupUnreachableTotal).toBe(1);
      expect(insp.handoffLookupInvalidTotal).toBe(0);
      const line = logs.map((l) => { try { return JSON.parse(l); } catch { return null; } })
        .find((o) => o && o.event === "handoff_lookup_degraded");
      expect(line).toBeDefined();
      expect(line.cause).toBe("error");
      expect(line.conversationId).toBe(conv);
      expect(line.total).toBe(1);
      expect(JSON.stringify(line)).not.toContain("unreachable probe words");
    } finally { console.log = orig; }
  });

  test("broker auth failures fail open under their own cause, never as not-handed-off", async () => {
    const s = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      broker: { sessionState: async () => { throw new Error("rpc_unauthorized"); } },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.suppressed).toBeUndefined();
    expect(s.turns.length).toBe(1);
    const insp = (await s.stub.inspect(SCOPE)) as Record<string, unknown>;
    expect(insp.handoffLookupUnreachableTotal).toBe(1);
    expect(insp.suppressedHandoffTurns).toBe(0);
  });

  test("malformed broker shapes fail open under the invalid counter, null stays quiet", async () => {
    const s = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      broker: live({ escalated: "yes" }),
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.suppressed).toBeUndefined();
    expect(s.turns.length).toBe(1);
    const insp = (await s.stub.inspect(SCOPE)) as Record<string, unknown>;
    expect(insp.handoffLookupInvalidTotal).toBe(1);
    expect(insp.handoffLookupUnreachableTotal).toBe(0);
    const quiet = await setup({
      reg: { ...agentReg, expectedQueueName: "Tubot_Queue" },
      broker: live(null),
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const m = await mint(quiet.stub, quiet.reg);
    const r2 = await postEcho(quiet.stub, quiet.reg, m.cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r2.json.suppressed).toBeUndefined();
    const insp2 = (await quiet.stub.inspect(SCOPE)) as Record<string, unknown>;
    expect(insp2.handoffLookupInvalidTotal).toBe(0);
    expect(insp2.handoffLookupUnreachableTotal).toBe(0);
  });
});

describe("linked turn context (headerCustom auto-fill)", () => {
  test("linked map accepted inline and forwarded on the agentTurn RPC", async () => {
    const s = await setup({
      reg: agentReg,
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const linked = { EndUserId: "0Pa000000000001EAA", SessionId: "0Mw000000000001EAA" };
    const r = await postEcho(s.stub, s.reg, cookie, {
      conversationId: conv, messageId: crypto.randomUUID(), text: "hi", linked,
    });
    expect(r.res.status).toBe(202);
    expect(r.json.accepted).toBe(true);
    expect(s.turns.length).toBe(1);
    expect(s.turns[0].turn.linked).toEqual(linked);
  });

  test("absent linked leaves the turn arg untouched (legacy shape)", async () => {
    const s = await setup({
      reg: agentReg,
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, {
      conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi",
    });
    expect(r.res.status).toBe(202);
    expect(s.turns.length).toBe(1);
    expect("linked" in (s.turns[0].turn as Record<string, unknown>)).toBe(false);
  });

  test("malformed linked maps reject 400 without touching agentcode", async () => {
    const bad = [
      "EndUserId", 42, ["x"],
      { "bad-key!": "v" }, { "": "v" }, { ["k".repeat(65)]: "v" },
      { EndUserId: 42 }, { EndUserId: "" }, { EndUserId: "v".repeat(257) },
      Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`k${i}`, "v"])),
      { a: "x".repeat(2000), b: "y".repeat(2000) },
    ];
    for (const linked of bad) {
      const s = await setup({
        reg: agentReg,
        agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
      });
      const { cookie } = await mint(s.stub, s.reg);
      const r = await postEcho(s.stub, s.reg, cookie, {
        conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi", linked,
      });
      expect(r.res.status).toBe(400);
      expect(r.json.error).toBe("invalid_message");
      expect(s.turns.length).toBe(0);
    }
  });
});

describe("proxy outbox budget guard (B4)", () => {
  test("deterministic LINKED_ cause parks on the first retry pass with cause preserved", async () => {
    const s = await setup({
      reg: agentReg,
      agent: () => { throw new Error("LINKED_BINDING_OR_DEFAULT_INVALID:ContactId"); },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(false);
    await s.flush();
    const row = s.sql.exec("SELECT state, payload, error AS e, attempts AS n FROM events").one();
    expect(row.state).toBe("needs_attention");
    expect(row.payload).toBeNull();
    expect(row.e).toBe("LINKED_BINDING_OR_DEFAULT_INVALID:ContactId");
    expect(row.n).toBe(1);
    expect(methods(s.calls)).not.toContain("echo");
    // Parked rows never run again: one inline turn + one drive turn, then quiet.
    expect(s.turns.length).toBe(2);
    await s.stub.alarm();
    expect(s.turns.length).toBe(2);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("needs_attention");
  });

  test("deterministic corrupt payload parks immediately under its own cause", async () => {
    // A corrupt row arrives as storage state (no accept attempt runs first:
    // the immediate drive starts during accept, so corrupting after postEcho
    // would race the drive's payload read). The executor must park it
    // terminal without ever invoking the agent.
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "MUST NOT RUN", handoff: false, spans: {} }) });
    const id = "c".repeat(64);
    s.sql.exec(
      "INSERT INTO events(id,fingerprint,state,payload,next_at,created_at) VALUES(?,?,'agent_pending',NULL,?,?)",
      id, "corrupt-test-fingerprint", Date.now(), Date.now()
    );
    await s.stub.alarm();
    const row = s.sql.exec("SELECT state, error AS e FROM events").one();
    expect(row.state).toBe("needs_attention");
    expect(row.e).toBe("missing_encrypted_turn");
    expect(s.turns.length).toBe(0);
    expect(methods(s.calls)).not.toContain("echo");
  });

  test("transient cause retries then parks at the cap with last cause preserved", async () => {
    const s = await setup({ reg: agentReg, agent: () => { throw new Error("agent down"); } });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(false);
    const due = () => s.sql.exec("UPDATE events SET next_at=? WHERE state='agent_pending'", Date.now());
    // Pass 1 is the immediate drive; later passes ride the alarm backstop.
    // The attempt budget counts drive passes regardless of vehicle.
    await s.flush();
    // Early transient failures keep retrying (a 30min outage must not wedge).
    for (let i = 0; i < 4; i++) { due(); await s.stub.alarm(); }
    let row = s.sql.exec("SELECT state, error AS e, attempts AS n FROM events").one();
    expect(row.state).toBe("agent_pending");
    expect(row.e).toBe("broker_retry_pending");
    expect(row.n).toBe(5);
    // Drive to the 30-attempt budget: passes 6..29 retry, pass 30 parks.
    for (let i = 0; i < 24; i++) { due(); await s.stub.alarm(); }
    row = s.sql.exec("SELECT state, error AS e, attempts AS n FROM events").one();
    expect(row.state).toBe("agent_pending");
    expect(row.n).toBe(29);
    due(); await s.stub.alarm();
    row = s.sql.exec("SELECT state, payload, error AS e, attempts AS n FROM events").one();
    expect(row.state).toBe("needs_attention");
    expect(row.payload).toBeNull();
    expect(row.e).toBe("retry_attempts_exhausted:agent down");
    expect(row.n).toBe(30);
    // Budget bound: 1 inline turn + exactly 30 drive turns (1 immediate +
    // 29 backstop), nothing submitted.
    expect(s.turns.length).toBe(31);
    expect(methods(s.calls)).not.toContain("echo");
  });

  test("transient failures then recovery still submit", async () => {
    let down = true;
    const s = await setup({
      reg: agentReg,
      agent: () => { if (down) throw new Error("sf outage"); return { reply: "RECOVERED", handoff: false, spans: { agentMs: 1 } }; },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(false);
    for (let i = 0; i < 3; i++) { s.sql.exec("UPDATE events SET next_at=? WHERE state='agent_pending'", Date.now()); await s.stub.alarm(); }
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
    down = false;
    s.sql.exec("UPDATE events SET next_at=? WHERE state='agent_pending'", Date.now());
    await s.stub.alarm();
    const row = s.sql.exec("SELECT state, request_id AS r FROM events").one();
    expect(row.state).toBe("submitted");
    expect(row.r).toBe(ECHO_REQUEST_ID);
    const submitted = s.calls.find((c) => c.method === "echo")!;
    expect((submitted.args[2] as Record<string, unknown>).text).toBe("RECOVERED");
  });

  test("submitted status polls are exempt from the attempt budget", async () => {
    let failStatus = true;
    const s = await setup({
      reg: agentReg,
      broker: { status: async () => { if (failStatus) throw new Error("sf status down"); return { state: "pending" }; } },
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(true);
    // Simulate a long-pending confirmation, then one transient status throw.
    s.sql.exec("UPDATE events SET attempts=45, next_at=? WHERE state='submitted'", Date.now());
    await s.stub.alarm();
    let row = s.sql.exec("SELECT state, error AS e FROM events").one();
    expect(row.state).toBe("submitted");
    expect(row.e).toBe("broker_retry_pending");
    // Recovery keeps polling instead of wedging.
    failStatus = false;
    s.sql.exec("UPDATE events SET next_at=? WHERE state='submitted'", Date.now());
    await s.stub.alarm();
    row = s.sql.exec("SELECT state FROM events").one();
    expect(row.state).toBe("submitted");
  });
});

describe("autonomous /browser/sync turn discovery", () => {
  test("discovers unprocessed EndUser entries via X-Tubot-Visitor token, runs agentTurn, and deduplicates repeat syncs", async () => {
    const conv = crypto.randomUUID();
    const msg = crypto.randomUUID();
    const s = await setup({
      reg: agentReg,
      broker: {
        browserSync: async () => ({
          conversationId: conv,
          entries: [{ messageId: msg, text: "Hello from widget", timestamp: Date.now() }],
        }),
      },
      agent: () => ({ reply: "AUTONOMOUS REPLY", handoff: false, spans: { agentMs: 5 } }),
    });
    const minted = await mint(s.stub, s.reg);
    const visitorToken = minted.json.visitorToken as string;
    expect(visitorToken).toMatch(/^[a-f0-9]{64}$/);
    const first = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/sync`, {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json", "X-Tubot-Visitor": visitorToken },
      body: "{}",
    }));
    expect(first.status).toBe(202);
    const firstJson = (await first.json()) as Record<string, unknown>;
    expect(firstJson.conversationId).toBe(conv);
    expect(firstJson.synced).toBe(1);
    expect(s.turns.length).toBe(1);
    expect(s.turns[0].turn.text).toBe("Hello from widget");
    const submitted = s.calls.find((c) => c.method === "echo")!;
    expect((submitted.args[2] as Record<string, unknown>).text).toBe("AUTONOMOUS REPLY");

    // Repeat sync with same entry does not re-run agentTurn
    const second = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/sync`, {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json", "X-Tubot-Visitor": visitorToken },
      body: JSON.stringify({ conversationId: conv }),
    }));
    expect(second.status).toBe(200);
    const secondJson = (await second.json()) as Record<string, unknown>;
    expect(secondJson.synced).toBe(0);
    expect(s.turns.length).toBe(1);
  });

  test("accepts Referer origin when Origin header is omitted by LWS iframe, but rejects mismatched explicit Origin", async () => {
    const s = await setup({ reg: agentReg });
    const refererOnly = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/session`, {
      method: "POST",
      headers: { Referer: `${ORIGIN}/ESWNuMessageWeb/`, "Content-Type": "application/json" },
      body: "{}",
    }));
    expect(refererOnly.status).toBe(200);
    const mismatchedOrigin = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/session`, {
      method: "POST",
      headers: { Origin: "https://evil.example", Referer: `${ORIGIN}/ESWNuMessageWeb/`, "Content-Type": "application/json" },
      body: "{}",
    }));
    expect(mismatchedOrigin.status).toBe(403);
  });
});

describe("browser client version reporting", () => {
  test("session accepts an optional clientVersion and rejects mistyped ones", async () => {
    const s = await setup({ reg: agentReg });
    const ok = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/session`, {
      method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" },
      body: JSON.stringify({ clientVersion: "1.1.0" }),
    }));
    expect(ok.status).toBe(200);
    expect(typeof ((await ok.json()) as Record<string, unknown>).visitorToken).toBe("string");
    const bad = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/session`, {
      method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" },
      body: JSON.stringify({ clientVersion: 42 }),
    }));
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as Record<string, unknown>).error).toBe("invalid_session_request");
  });

  test("sync accepts an optional clientVersion and rejects mistyped ones", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { browserSync: async () => ({ conversationId: null, entries: [] }) },
    });
    const minted = await mint(s.stub, s.reg);
    const token = minted.json.visitorToken as string;
    const ok = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/sync`, {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json", "X-Tubot-Visitor": token },
      body: JSON.stringify({ clientVersion: "1.1.0" }),
    }));
    expect(ok.status).toBe(200);
    const bad = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/sync`, {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json", "X-Tubot-Visitor": token },
      body: JSON.stringify({ clientVersion: { v: 1 } }),
    }));
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as Record<string, unknown>).error).toBe("invalid_sync");
  });

  test("echo accepts an optional clientVersion and rejects mistyped ones", async () => {
    const s = await setup({
      reg: agentReg,
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const good = { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi", clientVersion: "1.1.0" };
    const ok = await postEcho(s.stub, s.reg, cookie, good);
    expect(ok.res.status).toBe(202);
    const bad = await postEcho(s.stub, s.reg, cookie, { ...good, clientVersion: 42 });
    expect(bad.res.status).toBe(400);
    expect(bad.json.error).toBe("invalid_message");
  });
});

describe("visitor sliding TTL on /sync and /echo", () => {
  // Regression: only /session used to refresh expires_at, so a header that
  // only ever polled /sync lost its visitor row 30 min after mint and
  // orphaned its bound conversation (fresh mints can never re-adopt another
  // reference's session). Time is accelerated by aging the row directly.
  const visitorRow = (s: { sql: { exec: (q: string, ...p: unknown[]) => { toArray: () => Record<string, unknown>[] } } }) =>
    s.sql.exec("SELECT expires_at AS e, created_at AS c FROM visitors").toArray()[0] as { e: number; c: number };

  async function postSync(stub: { fetch(r: Request): Promise<Response> }, reg: { id: string }, token: string, body: unknown = {}) {
    const res = await stub.fetch(new Request(`https://proxy/p/${reg.id}/browser/sync`, {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json", "X-Tubot-Visitor": token },
      body: JSON.stringify(body),
    }));
    return { res, json: (await res.json()) as Record<string, unknown> };
  }

  test("sync extends a near-expiry visitor instead of letting it lapse", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { browserSync: async () => ({ conversationId: null, entries: [] }) },
    });
    const minted = await mint(s.stub, s.reg);
    const token = minted.json.visitorToken as string;
    s.sql.exec("UPDATE visitors SET expires_at=?", Date.now() + 60_000);
    const before = visitorRow(s).e;
    const t0 = Date.now();
    const { res } = await postSync(s.stub, s.reg, token);
    expect(res.status).toBe(200);
    const after = visitorRow(s).e;
    expect(after).toBeGreaterThan(before);
    expect(after - t0).toBeGreaterThanOrEqual(1_700_000);
    expect(after).toBeLessThanOrEqual(Date.now() + 1_800_000);
  });

  test("sync leaves a fresh visitor untouched (amortized writes)", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { browserSync: async () => ({ conversationId: null, entries: [] }) },
    });
    const minted = await mint(s.stub, s.reg);
    const token = minted.json.visitorToken as string;
    const before = visitorRow(s).e;
    const { res } = await postSync(s.stub, s.reg, token);
    expect(res.status).toBe(200);
    expect(visitorRow(s).e).toBe(before);
  });

  test("echo extends a near-expiry visitor", async () => {
    const s = await setup({
      reg: agentReg,
      agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie, json } = await mint(s.stub, s.reg);
    expect(typeof json.visitorToken).toBe("string");
    s.sql.exec("UPDATE visitors SET expires_at=?", Date.now() + 60_000);
    const before = visitorRow(s).e;
    const echo = await postEcho(s.stub, s.reg, cookie, {
      conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi",
    });
    expect(echo.res.status).toBe(202);
    expect(visitorRow(s).e).toBeGreaterThan(before);
  });

  test("sliding refresh respects the 8h absolute cap", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { browserSync: async () => ({ conversationId: null, entries: [] }) },
    });
    const minted = await mint(s.stub, s.reg);
    const token = minted.json.visitorToken as string;
    const aged = Date.now() - 28_000_000;
    s.sql.exec("UPDATE visitors SET created_at=?, expires_at=?", aged, Date.now() + 60_000);
    const { res } = await postSync(s.stub, s.reg, token);
    expect(res.status).toBe(200);
    const row = visitorRow(s);
    expect(row.e).toBe(row.c + 28_800_000);
  });

  test("an already-expired visitor still 401s on sync", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { browserSync: async () => ({ conversationId: null, entries: [] }) },
    });
    const minted = await mint(s.stub, s.reg);
    const token = minted.json.visitorToken as string;
    s.sql.exec("UPDATE visitors SET expires_at=?", Date.now() - 1_000);
    const { res, json } = await postSync(s.stub, s.reg, token);
    expect(res.status).toBe(401);
    expect(json.error).toBe("visitor_unauthorized");
  });
});

describe("browser origins allow-list + relay source", () => {
  const VF_ORIGIN = "https://mydomain--c.vf.force.com";
  const withOrigins = {
    browser: { origin: ORIGIN, origins: [ORIGIN, VF_ORIGIN], apiVersion: "v59.0", visitorField: "Proxy_Echo_Visitor_Ref__c" },
  };

  async function postSession(stub: { fetch(r: Request): Promise<Response> }, reg: { id: string }, headers: Record<string, string>) {
    const res = await stub.fetch(new Request(`https://proxy/p/${reg.id}/browser/session`, {
      method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: "{}",
    }));
    return { res, json: (await res.json()) as Record<string, unknown> };
  }

  async function postEchoHeaders(stub: { fetch(r: Request): Promise<Response> }, reg: { id: string }, cookie: string, body: unknown, headers: Record<string, string>) {
    const res = await stub.fetch(new Request(`https://proxy/p/${reg.id}/browser/echo`, {
      method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json", Cookie: cookie, ...headers }, body: JSON.stringify(body),
    }));
    return { res, json: (await res.json()) as Record<string, unknown> };
  }

  test("old-shape registration without origins keeps accepting the primary origin", async () => {
    const s = await setup({ reg: agentReg });
    expect("origins" in ((s.reg as Record<string, unknown>).browser as object)).toBe(false);
    const { res } = await postSession(s.stub, s.reg, { Origin: ORIGIN });
    expect(res.status).toBe(200);
  });

  test("accepts the VF test-page origin when listed in origins", async () => {
    const s = await setup({ reg: { ...agentReg, ...withOrigins } });
    const { res } = await postSession(s.stub, s.reg, { Origin: VF_ORIGIN });
    expect(res.status).toBe(200);
    const refererOnly = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/session`, {
      method: "POST", headers: { Referer: `${VF_ORIGIN}/apex/ESWPage123`, "Content-Type": "application/json" }, body: "{}",
    }));
    expect(refererOnly.status).toBe(200);
  });

  test("rejects non-listed origins with exact matching only (no wildcards, no substrings)", async () => {
    const s = await setup({ reg: { ...agentReg, ...withOrigins } });
    for (const bad of [
      "https://evil.example",
      `${ORIGIN}.evil.com`,
      "https://evil-site.example",
      `${VF_ORIGIN}.evil.com`,
      ORIGIN.slice("https://".length),
    ]) {
      const { res, json } = await postSession(s.stub, s.reg, { Origin: bad });
      expect(res.status).toBe(403);
      expect(json.error).toBe("origin_forbidden");
    }
    // A literal '*' entry grants nothing: matching is exact, never globbed.
    const star = await setup({
      reg: { ...agentReg, browser: { origin: ORIGIN, origins: ["*"], apiVersion: "v59.0", visitorField: "Proxy_Echo_Visitor_Ref__c" } },
    });
    const { res, json } = await postSession(star.stub, star.reg, { Origin: "https://anything.example" });
    expect(res.status).toBe(403);
    expect(json.error).toBe("origin_forbidden");
  });

  test("preflight advertises X-Tubot-Relay", async () => {
    const s = await setup({ reg: { ...agentReg, ...withOrigins } });
    const res = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/echo`, {
      method: "OPTIONS", headers: { Origin: VF_ORIGIN },
    }));
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Headers")).toContain("X-Tubot-Relay");
  });

  test("direct snippet POSTs mark the outbox row as snippet", async () => {
    const s = await setup({ reg: agentReg, agent: null });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEchoHeaders(s.stub, s.reg, cookie,
      { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" },
      { "X-Tubot-Relay": "snippet" });
    expect(r.res.status).toBe(202);
    expect(s.sql.exec("SELECT source AS x FROM relay_sources").one().x).toBe("snippet");
  });

  test("harness headers keep precedence over X-Tubot-Relay", async () => {
    for (const harness of ["X-Tubot-Harness", "X-Test-Browser"]) {
      const s = await setup({ reg: agentReg, agent: null });
      const { cookie } = await mint(s.stub, s.reg);
      const r = await postEchoHeaders(s.stub, s.reg, cookie,
        { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" },
        { [harness]: "1", "X-Tubot-Relay": "snippet" });
      expect(r.res.status).toBe(202);
      expect(s.sql.exec("SELECT source AS x FROM relay_sources").one().x).toBe("harness");
    }
  });

  test("unmarked and non-snippet relay values stay lwc", async () => {
    for (const headers of [{}, { "X-Tubot-Relay": "lwc" }, { "X-Tubot-Relay": "bridge" }]) {
      const s = await setup({ reg: agentReg, agent: null });
      const { cookie } = await mint(s.stub, s.reg);
      const r = await postEchoHeaders(s.stub, s.reg, cookie,
        { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" }, headers);
      expect(r.res.status).toBe(202);
      expect(s.sql.exec("SELECT source AS x FROM relay_sources").one().x).toBe("lwc");
    }
  });
});

describe("browser websocket transport (PartyServer)", () => {
  // Structural stand-in for a PartyServer Connection: the DO touches only
  // id/send/close/state/setState, so the fake needs nothing else. The real
  // 101 upgrade handshake runs only on workerd and is proven live on staging.
  function fakeSocket() {
    const sent: Record<string, unknown>[] = [];
    let state: unknown = null;
    let closed: { code: number; reason: string } | null = null;
    return {
      id: "sock-1",
      sent,
      closed: () => closed,
      send: (data: string) => { sent.push(JSON.parse(data)); },
      close: (code = 1000, reason = "") => { closed = { code, reason }; },
      get state() { return state; },
      setState: (v: unknown) => { state = v; return v; },
    };
  }
  type Stub = { fetch(r: Request): Promise<Response>; onConnect(c: never): Promise<void>; onMessage(c: never, m: unknown): Promise<void> };

  async function authedSocket(s: { stub: Stub; reg: { id: string } }) {
    const m = await mint(s.stub, s.reg);
    const sock = fakeSocket();
    await s.stub.onConnect(sock as never);
    expect(sock.sent).toEqual([{ type: "hello", protocol: 1 }]);
    await s.stub.onMessage(sock as never, JSON.stringify({ type: "auth", protocol: 1, visitorToken: (m.json as Record<string, unknown>).visitorToken }));
    expect(sock.sent.at(-1)).toEqual({ type: "authed" });
    expect(sock.closed()).toBeNull();
    return { sock, cookie: m.cookie };
  }

  test("upgrade gating mirrors POST preconditions", async () => {
    const noBrowser = await setup({ reg: { ...agentReg, browser: undefined } });
    const r404 = await noBrowser.stub.fetch(new Request(`https://proxy/p/${noBrowser.reg.id}/browser/ws`, {
      method: "GET", headers: { Origin: ORIGIN, Upgrade: "websocket", Connection: "Upgrade" },
    }));
    expect(r404.status).toBe(404);
    const s = await setup({ reg: agentReg });
    const url = `https://proxy/p/${s.reg.id}/browser/ws`;
    const get = (headers: Record<string, string>, method = "GET") =>
      s.stub.fetch(new Request(url, { method, headers }));
    expect((await get({ Origin: ORIGIN, Upgrade: "websocket" }, "POST")).status).toBe(405);
    const noUpgrade = await get({ Origin: ORIGIN });
    expect(noUpgrade.status).toBe(426);
    const badOrigin = await get({ Origin: "https://evil.example", Upgrade: "websocket" });
    expect(badOrigin.status).toBe(403);
    expect((await badOrigin.json() as Record<string, unknown>).error).toBe("origin_forbidden");
    const revoked = await setup({ reg: { ...agentReg, disabled: true } });
    const r403 = await revoked.stub.fetch(new Request(`https://proxy/p/${revoked.reg.id}/browser/ws`, {
      method: "GET", headers: { Origin: ORIGIN, Upgrade: "websocket" },
    }));
    expect(r403.status).toBe(403);
  });

  test("first frame must be auth", async () => {
    const s = await setup({ reg: agentReg, agent: null }) as unknown as { stub: Stub; reg: { id: string } };
    const sock = fakeSocket();
    await s.stub.onConnect(sock as never);
    await s.stub.onMessage(sock as never, JSON.stringify({ type: "turn", conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" }));
    expect(sock.sent.at(-1)).toEqual({ type: "error", code: "auth_required" });
    expect(sock.closed()).toEqual({ code: 4401, reason: "auth_required" });
  });

  test("auth rejects bad protocol, bad tokens, and garbage frames", async () => {
    const s = await setup({ reg: agentReg, agent: null }) as unknown as { stub: Stub; reg: { id: string } };
    await mint(s.stub, s.reg); // live, the upgrade handshake ensures tables before any socket exists
    const badProtocol = fakeSocket();
    await s.stub.onConnect(badProtocol as never);
    await s.stub.onMessage(badProtocol as never, JSON.stringify({ type: "auth", protocol: 999, visitorToken: "f".repeat(64) }));
    expect(badProtocol.sent.at(-1)).toEqual({ type: "error", code: "protocol_mismatch" });
    expect(badProtocol.closed()).toEqual({ code: 4401, reason: "protocol_mismatch" });
    const badToken = fakeSocket();
    await s.stub.onConnect(badToken as never);
    await s.stub.onMessage(badToken as never, JSON.stringify({ type: "auth", protocol: 1, visitorToken: "f".repeat(64) }));
    expect(badToken.sent.at(-1)).toEqual({ type: "error", code: "visitor_unauthorized" });
    expect(badToken.closed()).not.toBeNull();
    // Malformed and oversize frames error without closing: the client falls back to POST.
    const garbage = fakeSocket();
    await s.stub.onConnect(garbage as never);
    await s.stub.onMessage(garbage as never, "{not json");
    expect(garbage.sent.at(-1)).toEqual({ type: "error", code: "invalid_frame" });
    expect(garbage.closed()).toBeNull();
    await s.stub.onMessage(garbage as never, "x".repeat(9000));
    expect(garbage.sent.at(-1)).toEqual({ type: "error", code: "frame_too_large" });
    expect(garbage.closed()).toBeNull();
  });

  test("authed turn serves inline through the shared core and marks lwc", async () => {
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "R", handoff: false, spans: { agentMs: 1 } }) });
    const { sock } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const conv = crypto.randomUUID();
    const msg = crypto.randomUUID();
    await (s.stub as unknown as Stub).onMessage(sock as never, JSON.stringify({ conversationId: conv, messageId: msg, text: "hi", type: "turn" }));
    const accept = sock.sent.at(-1)!;
    expect(accept.type).toBe("accepted");
    expect(accept.transport).toBe("ws");
    expect(accept.messageId).toBe(msg);
    expect(accept.requestId).toBe(ECHO_REQUEST_ID);
    expect(accept.inline).toBe(true);
    expect(s.sql.exec("SELECT source AS x FROM relay_sources").one().x).toBe("lwc");
    expect(s.sql.exec("SELECT state AS x FROM events").one().x).toBe("submitted");
    // POST twin of the same turn dedupes to the same request key without
    // re-running the agent turn — even for a different visitor, exactly as a
    // POST/POST double submit behaves.
    const twin = await postEcho(s.stub, s.reg, "", { conversationId: conv, messageId: msg, text: "hi" });
    expect(twin.res.status).toBe(401); // no cookie: proves nothing leaks without auth
    const m = await mint(s.stub, s.reg);
    const twin2 = await postEcho(s.stub, s.reg, m.cookie, { conversationId: conv, messageId: msg, text: "hi" });
    expect(twin2.res.status).toBe(202);
    expect(twin2.json.accepted).toBe(true);
    expect(twin2.json.requestKey).toBe(accept.requestKey);
    expect(s.turns.length).toBe(1);
  });

  test("same-visitor POST twin dedupes to the WS request key", async () => {
    const s = await setup({ reg: agentReg, agent: null });
    const { sock, cookie } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const body = { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" };
    await (s.stub as unknown as Stub).onMessage(sock as never, JSON.stringify({ ...body, type: "turn" }));
    const accept = sock.sent.at(-1)!;
    expect(accept.type).toBe("accepted");
    const twin = await postEcho(s.stub, s.reg, cookie, body);
    expect(twin.res.status).toBe(202);
    expect(twin.json.accepted).toBe(true);
    expect(twin.json.requestKey).toBe(accept.requestKey);
    expect(s.sql.exec("SELECT COUNT(*) AS n FROM events").one().n).toBe(1);
  });

  test("malformed turns fail closed over the socket", async () => {
    const s = await setup({ reg: agentReg, agent: null });
    const { sock } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const sub = s.stub as unknown as Stub;
    const badId = crypto.randomUUID();
    await sub.onMessage(sock as never, JSON.stringify({ type: "turn", conversationId: "nope", messageId: badId, text: "hi" }));
    expect(sock.sent.at(-1)).toEqual({ type: "error", messageId: badId, code: "invalid_message", status: 400 });
    await sub.onMessage(sock as never, JSON.stringify({ type: "ping" }));
    expect(sock.sent.at(-1)).toEqual({ type: "error", code: "unknown_frame" });
    expect(sock.closed()).toBeNull();
    expect(s.sql.exec("SELECT COUNT(*) AS n FROM events").one().n).toBe(0);
  });

  test("hints ack and mark the following turn hinted", async () => {
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "R", handoff: false, spans: {} }) });
    const { sock } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const sub = s.stub as unknown as Stub;
    const conv = crypto.randomUUID();
    await sub.onMessage(sock as never, JSON.stringify({ type: "hint", clientTurnId: "c1", conversationId: conv }));
    expect(sock.sent.at(-1)).toEqual({ type: "hint-ack", clientTurnId: "c1" });
    const msg = crypto.randomUUID();
    await sub.onMessage(sock as never, JSON.stringify({ type: "turn", conversationId: conv, messageId: msg, text: "hi" }));
    const accept = sock.sent.at(-1)!;
    expect(accept.type).toBe("accepted");
    expect(accept.hinted).toBe(true);
    expect(typeof accept.hintAgeMs).toBe("number");
    // A turn on an unhinted conversation carries no mark.
    const msg2 = crypto.randomUUID();
    await sub.onMessage(sock as never, JSON.stringify({ type: "turn", conversationId: crypto.randomUUID(), messageId: msg2, text: "hi" }));
    const accept2 = sock.sent.at(-1)!;
    expect(accept2.type).toBe("accepted");
    expect("hinted" in accept2).toBe(false);
  });

  test("malformed hints fail closed without touching turns", async () => {
    const s = await setup({ reg: agentReg, agent: null });
    const { sock } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const sub = s.stub as unknown as Stub;
    await sub.onMessage(sock as never, JSON.stringify({ type: "hint", conversationId: crypto.randomUUID() }));
    expect(sock.sent.at(-1)).toEqual({ type: "error", code: "invalid_hint" });
    expect(sock.closed()).toBeNull();
  });

  test("authed sync frame serves through the shared core and echoes requestId", async () => {
    const conv = crypto.randomUUID();
    const msg = crypto.randomUUID();
    const s = await setup({
      reg: agentReg,
      broker: {
        browserSync: async () => ({
          conversationId: conv,
          entries: [{ messageId: msg, text: "Hello over socket", timestamp: Date.now() }],
        }),
      },
      agent: () => ({ reply: "SOCKET REPLY", handoff: false, spans: { agentMs: 3 } }),
    });
    const { sock } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    await (s.stub as unknown as Stub).onMessage(sock as never, JSON.stringify({ type: "sync", requestId: "s1" }));
    const synced = sock.sent.at(-1)!;
    expect(synced.type).toBe("synced");
    expect(synced.requestId).toBe("s1");
    expect(synced.conversationId).toBe(conv);
    expect(synced.synced).toBe(1);
    expect((synced.results as Array<Record<string, unknown>>)[0].messageId).toBe(msg);
    expect(s.turns.length).toBe(1);
    expect(s.turns[0].turn.text).toBe("Hello over socket");
    expect(s.sql.exec("SELECT source AS x FROM relay_sources").one().x).toBe("lwc");
    // Sync discovery entries ride into verify so it skips its duplicate fetch.
    const verify = s.calls.find((c) => c.method === "browserTurn")!;
    expect(verify.args[2]).toEqual(expect.objectContaining({
      conversationId: conv, messageId: msg, text: "Hello over socket",
      knownEntries: [{ messageId: msg, text: "Hello over socket", timestamp: expect.any(Number) }],
    }));
  });

  test("sync frame mirrors the idle contract and validates like POST", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { browserSync: async () => ({ conversationId: null, entries: [] }) },
      agent: null,
    });
    const { sock } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const sub = s.stub as unknown as Stub;
    await sub.onMessage(sock as never, JSON.stringify({ type: "sync", requestId: "idle-1" }));
    expect(sock.sent.at(-1)).toEqual({ type: "synced", requestId: "idle-1", conversationId: null, synced: 0 });
    await sub.onMessage(sock as never, JSON.stringify({ type: "sync", requestId: "bad-1", conversationId: "nope" }));
    expect(sock.sent.at(-1)).toEqual({ type: "error", requestId: "bad-1", code: "invalid_sync", status: 400 });
    expect(sock.closed()).toBeNull();
  });

  test("sync frame maps broker outages to error frames without closing", async () => {
    const s = await setup({
      reg: agentReg,
      broker: { browserSync: async () => { throw Error("broker down"); } },
      agent: null,
    });
    const { sock } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    await (s.stub as unknown as Stub).onMessage(sock as never, JSON.stringify({ type: "sync", requestId: "o1" }));
    expect(sock.sent.at(-1)).toEqual({ type: "error", requestId: "o1", code: "sync_unavailable", status: 503 });
    expect(sock.closed()).toBeNull();
  });

  test("WS sync then POST sync dedupes through the one shared core", async () => {
    const conv = crypto.randomUUID();
    const msg = crypto.randomUUID();
    const s = await setup({
      reg: agentReg,
      broker: {
        browserSync: async () => ({
          conversationId: conv,
          entries: [{ messageId: msg, text: "Once only", timestamp: Date.now() }],
        }),
      },
      agent: () => ({ reply: "R", handoff: false, spans: {} }),
    });
    const { sock, cookie } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    await (s.stub as unknown as Stub).onMessage(sock as never, JSON.stringify({ type: "sync", requestId: "d1" }));
    expect((sock.sent.at(-1) as Record<string, unknown>).synced).toBe(1);
    const twin = await s.stub.fetch(new Request(`https://proxy/p/${s.reg.id}/browser/sync`, {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({ conversationId: conv }),
    }));
    expect(twin.status).toBe(200);
    expect(((await twin.json()) as Record<string, unknown>).synced).toBe(0);
    expect(s.turns.length).toBe(1);
  });

  test("revoked route closes live sockets", async () => {
    const s = await setup({ reg: agentReg, agent: null });
    const { sock } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    await s.stub.revoke({ teamId: "team_1", orgId: ORG, channelId: CHANNEL } as never);
    await (s.stub as unknown as Stub).onMessage(sock as never, JSON.stringify({ type: "turn", conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" }));
    expect(sock.closed()).toEqual({ code: 4403, reason: "proxy_unavailable" });
  });

  test("retry agent-win pushes progress only to the bound visitor (no reply text)", async () => {
    let calls = 0;
    const s = await setup({
      reg: agentReg,
      agent: () => { calls++; if (calls === 1) throw new Error("agent down"); return { reply: "PUSHED REPLY", handoff: false, spans: { agentMs: 1 } }; },
    });
    const a = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const b = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const conv = crypto.randomUUID(); const msg = crypto.randomUUID();
    // Sockets stubbed before the turn: the immediate drive pushes during it.
    (s.stub as unknown as Record<string, unknown>).getConnections = () => [a.sock, b.sock];
    const bSent = b.sock.sent.length;
    const r = await postEcho(s.stub, s.reg, a.cookie, { conversationId: conv, messageId: msg, text: "hi" });
    expect(r.json.inline).toBe(false);
    await s.flush();
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
    expect(a.sock.sent.at(-1)).toEqual({ type: "progress", requestKey: r.json.requestKey, tAccept: expect.any(Number), tAgentStart: expect.any(Number), tAgentDone: expect.any(Number), tSubmit: expect.any(Number) });
    // No rendered push kinds ever: the native bubble is the only path.
    expect(a.sock.sent.filter((f: unknown) => ["reply", "delivered", "failed"].includes((f as { type?: string }).type as string))).toHaveLength(0);
    // Visitor B is authed but bound to no conversation: no leak.
    expect(b.sock.sent.length).toBe(bSent);
  });

  test("retry executor ships ordered progress markers without any rendered push", async () => {
    let calls = 0;
    const s = await setup({
      reg: agentReg,
      agent: () => { calls++; if (calls === 1) throw new Error("agent down"); return { reply: "MARKED", handoff: false, spans: { agentMs: 1 } }; },
    });
    const a = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const conv = crypto.randomUUID(); const msg = crypto.randomUUID();
    (s.stub as unknown as Record<string, unknown>).getConnections = () => [a.sock];
    const r = await postEcho(s.stub, s.reg, a.cookie, { conversationId: conv, messageId: msg, text: "hi" });
    expect(r.json.inline).toBe(false);
    await s.flush();
    const frames = a.sock.sent as Array<{ type?: unknown; requestKey?: unknown }>;
    const progress = frames.find((f) => f.type === "progress" && f.requestKey === r.json.requestKey) as unknown as {
      tAccept: number; tAgentStart: number; tAgentDone: number; tSubmit: number;
    };
    expect(progress).toBeTruthy();
    expect(progress.tAccept).toEqual(expect.any(Number));
    expect(progress.tAgentStart).toBeGreaterThanOrEqual(progress.tAccept);
    expect(progress.tAgentDone).toBeGreaterThanOrEqual(progress.tAgentStart);
    expect(progress.tSubmit).toBeGreaterThanOrEqual(progress.tAgentDone);
    // Markers are the only post-submit push kind: no reply text on the wire.
    expect(frames.filter((f) => ["reply", "delivered", "failed"].includes(f.type as string))).toHaveLength(0);
  });

  test("alarm executor sends no push frames before the submit confirms (no ghost on unconfirmed submit)", async () => {
    let calls = 0;
    const s = await setup({
      reg: agentReg,
      broker: { echo: async () => ({ requestId: "bogus" }) },
      agent: () => { calls++; if (calls === 1) throw new Error("agent down"); return { reply: "GHOST?", handoff: false, spans: { agentMs: 1 } }; },
    });
    const a = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const conv = crypto.randomUUID(); const msg = crypto.randomUUID();
    const r = await postEcho(s.stub, s.reg, a.cookie, { conversationId: conv, messageId: msg, text: "hi" });
    expect(r.json.inline).toBe(false);
    (s.stub as unknown as Record<string, unknown>).getConnections = () => [a.sock];
    const sentBefore = a.sock.sent.length;
    await s.stub.alarm();
    expect(s.sql.exec("SELECT state FROM events").one().state).not.toBe("submitted");
    expect(a.sock.sent.slice(sentBefore).filter((f: unknown) => ["reply", "progress", "delivered", "failed"].includes((f as { type?: string }).type as string))).toHaveLength(0);
  });

  test("inline agent-win submits without any socket push (native bubble only)", async () => {
    const s = await setup({ reg: agentReg, agent: () => ({ reply: "INLINE SUBMIT", handoff: false, spans: { agentMs: 1 } }) });
    const { sock, cookie } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    (s.stub as unknown as Record<string, unknown>).getConnections = () => [sock];
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(true);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
    expect(sock.sent.filter((f: unknown) => ["reply", "progress", "delivered", "failed"].includes((f as { type?: string }).type as string))).toHaveLength(0);
  });

  test("delivery observation records the state without terminal pushes", async () => {
    for (const state of ["delivered", "failed"]) {
      const s = await setup({
        reg: agentReg,
        broker: { status: async () => ({ state }) },
        agent: () => ({ reply: "R", handoff: false, spans: {} }),
      });
      const { sock, cookie } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
      const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
      expect(r.json.inline).toBe(true);
      (s.stub as unknown as Record<string, unknown>).getConnections = () => [sock];
      s.sql.exec("UPDATE events SET next_at=? WHERE state='submitted'", Date.now());
      await s.stub.alarm();
      expect(s.sql.exec("SELECT state FROM events").one().state).toBe(state);
      expect(sock.sent.filter((f: unknown) => ["delivered", "failed"].includes((f as { type?: string }).type as string))).toHaveLength(0);
    }
  });

  test("attempts-exhausted park records needs_attention without a failed push", async () => {
    const s = await setup({ reg: agentReg, agent: () => { throw new Error("agent down"); } });
    const { sock, cookie } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(false);
    // Settle the immediate drive first: its in-flight attempts write would
    // otherwise race the forced count below. (Production overlap needs a
    // >60s hung pass — bounded legs total ~25s serial — and stays send-safe
    // via agent replay + submit claim dedup.)
    await s.flush();
    s.sql.exec("UPDATE events SET attempts=29, next_at=? WHERE id=?", Date.now(), r.json.requestKey);
    (s.stub as unknown as Record<string, unknown>).getConnections = () => [sock];
    await s.stub.alarm();
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("needs_attention");
    expect(sock.sent.filter((f: unknown) => ["delivered", "failed"].includes((f as { type?: string }).type as string))).toHaveLength(0);
  });

  test("a stale EARLY_RENDER var is ignored (removed flag has no effect)", async () => {
    const s = await setup({ reg: agentReg, env: { EARLY_RENDER: "off" }, agent: () => ({ reply: "STILL SUBMITS", handoff: false, spans: {} }) });
    const { cookie } = await authedSocket(s as unknown as { stub: Stub; reg: { id: string } });
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(true);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });
});

describe("verify-late accept (flag-gated, async-only)", () => {
  const GUEST = "0PAxx0000000001AAA";
  const lateEnv = { ASYNC_ACCEPT: "on", VERIFY_LATE: "on" };
  const due = (s: { sql: { exec(q: string, ...p: unknown[]): unknown } }) =>
    (s.sql.exec("UPDATE events SET next_at=? WHERE state='agent_pending'", Date.now()) as unknown);

  test("accept releases verify-late; the drive verifies + serves with recipient relay", async () => {
    // Broker overrides bypass the calls recorder: count invocations directly.
    let verifies = 0;
    const s = await setup({
      reg: agentReg, env: lateEnv,
      broker: { browserTurn: async () => { verifies++; return { code: "verified", recipient: GUEST }; } },
      agent: () => ({ reply: "LATE", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi late" });
    expect(r.res.status).toBe(202);
    expect(r.json.accepted).toBe(true);
    expect(r.json.inline).toBe(false);
    expect(r.json.verifyLate).toBe(true);
    // Pre-drive quiescence (verifies 0, no agent, parked) is unobservable:
    // the drive starts during accept. The release shape above plus
    // exactly-once verification below pin the contract instead.
    expect(s.waitings()).toBe(1);
    await s.flush();
    expect(verifies).toBe(1);
    expect(s.turns.length).toBe(1);
    const echo = s.calls.find((c) => c.method === "echo")!;
    expect((echo.args[2] as Record<string, unknown>).text).toBe("LATE");
    expect((echo.args[2] as Record<string, unknown>).recipient).toBe(GUEST);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("transient verify heals inside the poll budget and submits", async () => {
    let n = 0;
    const s = await setup({
      reg: agentReg, env: lateEnv,
      broker: { browserTurn: async () => (++n === 1 ? "session_pending" : { code: "verified", recipient: GUEST }) },
      agent: () => ({ reply: "HEALED", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    await s.flush();
    expect(n).toBe(2);
    expect(s.turns.length).toBe(1);
    expect(methods(s.calls)).toContain("echo");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("permanent verify failure parks terminal: one speculative turn burned, nothing submits", async () => {
    // Speculation cost, pre-accepted: a forged FIRST turn starts the agent
    // before the probe rejects it. The burn is exactly one turn (the join
    // never starts a second), and the submit stays proof-gated.
    const s = await setup({
      reg: agentReg, env: lateEnv,
      broker: { browserTurn: async () => "invalid_turn" },
      agent: () => ({ reply: "DISCARDED", handoff: false, spans: {} }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "forged" });
    await s.flush();
    expect(s.turns.length).toBe(1);
    expect(methods(s.calls)).not.toContain("echo");
    const row = s.sql.exec("SELECT state, payload, error AS e FROM events").one();
    expect(row.state).toBe("needs_attention");
    expect(row.payload).toBeNull();
    expect(String(row.e)).toContain("verify_rejected");
  });

  test("first pass starts the agent before the first probe returns (speculative)", async () => {
    let releaseProbe: ((v: unknown) => void) | null = null;
    let agentStarted = false;
    const s = await setup({
      reg: agentReg, env: lateEnv,
      broker: { browserTurn: () => new Promise((r) => { releaseProbe = r as (v: unknown) => void; }) },
      agent: () => { agentStarted = true; return { reply: "SPEC", handoff: false, spans: { agentMs: 1 } }; },
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    const p = s.flush();
    await new Promise((r) => setTimeout(r, 100));
    // Serial code would still be stuck awaiting the first probe here.
    expect(agentStarted).toBe(true);
    releaseProbe!({ code: "verified", recipient: GUEST });
    await p;
    // Joined exactly once: no second agent start at the join.
    expect(s.turns.length).toBe(1);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("binding_absent heals inside the budget and submits (agent overlapped)", async () => {
    let n = 0;
    const s = await setup({
      reg: agentReg, env: lateEnv,
      broker: { browserTurn: async () => (++n <= 2 ? "binding_absent" : { code: "verified", recipient: GUEST }) },
      agent: () => ({ reply: "BOUND", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    await s.flush();
    expect(n).toBe(3);
    expect(s.turns.length).toBe(1);
    expect(methods(s.calls)).toContain("echo");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("binding_absent forever: one speculative agent turn, then proof-only retries", async () => {
    let probes = 0;
    const s = await setup({
      reg: agentReg, env: { ...lateEnv, VERIFY_LATE_BUDGET_MS: "1500" },
      broker: { browserTurn: async () => { probes++; return "binding_absent"; } },
      agent: () => ({ reply: "SPECULATIVE", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    // Pass 1 rides the immediate drive; pass 2 rides the alarm backstop.
    await s.flush();
    // First pass overlaps the agent with the bind wait, then requeues when
    // the budget exhausts unproven: the submit stays gated.
    expect(s.turns.length).toBe(1);
    expect(methods(s.calls)).not.toContain("echo");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
    const firstPassProbes = probes;
    expect(firstPassProbes).toBeGreaterThan(1);
    due(s);
    await s.stub.alarm();
    // Retry pass: exactly one probe, no second agent turn, still parked.
    expect(probes).toBe(firstPassProbes + 1);
    expect(s.turns.length).toBe(1);
    expect(methods(s.calls)).not.toContain("echo");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
  });

  test("retry passes probe once (no poll-budget burn on short-transient)", async () => {
    let probes = 0;
    const s = await setup({
      reg: agentReg, env: { ...lateEnv, VERIFY_LATE_BUDGET_MS: "1500" },
      broker: { browserTurn: async () => { probes++; return "session_pending"; } },
      agent: () => ({ reply: "SPECULATIVE", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    // Pass 1 rides the immediate drive; pass 2 rides the alarm backstop.
    await s.flush();
    const firstPassProbes = probes;
    expect(firstPassProbes).toBeGreaterThan(1);
    expect(s.turns.length).toBe(1);
    due(s);
    await s.stub.alarm();
    expect(probes).toBe(firstPassProbes + 1);
    expect(s.turns.length).toBe(1);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
  });

  test("poll exhaustion requeues; recovery on the next pass submits", async () => {
    let mode = "mismatch";
    const s = await setup({
      reg: agentReg, env: { ...lateEnv, VERIFY_LATE_BUDGET_MS: "1500" },
      broker: { browserTurn: async () => (mode === "mismatch" ? "transcript_mismatch" : { code: "verified", recipient: GUEST }) },
      agent: () => ({ reply: "RECOVERED", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    // Pass 1 rides the immediate drive; pass 2 rides the alarm backstop.
    await s.flush();
    // Agent ran against the still-unproven turn (accepted tradeoff), but the
    // submit stayed gated: nothing submitted, row requeued, not parked.
    expect(s.turns.length).toBe(1);
    expect(methods(s.calls)).not.toContain("echo");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("agent_pending");
    mode = "verified";
    due(s);
    await s.stub.alarm();
    expect(methods(s.calls)).toContain("echo");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("late accept skips the live handoff read for unknown conversations", async () => {
    let sessionStateCalls = 0;
    const s = await setup({
      reg: agentReg, env: lateEnv,
      broker: { sessionState: async () => { sessionStateCalls++; return null; } },
      agent: () => ({ reply: "C", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.accepted).toBe(true);
    await s.flush();
    // Total 1 = accept 0 (skipped for the unknown conversation) + executor
    // 1 (the mandatory live re-check, the backstop for the accept skip).
    expect(sessionStateCalls).toBe(1);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("late accept checks handoff for known conversations (then caches)", async () => {
    let sessionStateCalls = 0;
    const s = await setup({
      reg: agentReg, env: lateEnv,
      broker: { sessionState: async () => { sessionStateCalls++; return null; } },
      agent: () => ({ reply: "C", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    // Each drive re-checks live exactly once, so accept-side reads are
    // proven by totals: turn 1 accept skips (0) + drive (1) = 1; turn 2
    // accept reads live (1) + drive (1) = 3; turn 3 accept cache-hits (0)
    // + drive (1) = 4. A flush settles each drive before its total.
    await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "one" });
    await s.flush();
    expect(sessionStateCalls).toBe(1);
    await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "two" });
    await s.flush();
    expect(sessionStateCalls).toBe(3);
    await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "three" });
    await s.flush();
    expect(sessionStateCalls).toBe(4);
  });

  test("pre-handed-off first turn accepts, then suppresses in the executor", async () => {
    // Contract change (deliberate, surfaced): async verify-late accept no
    // longer live-reads handoff for conversations this route never served —
    // enforcement moves to the immediate drive's mandatory live re-check
    // (which runs before every submit). Safe because (a) the snippet and LWC
    // relay ignore the accept-time suppressed flag entirely (verified: zero
    // reads), discovering handoff via sync either way; (b) E2E stage 11 pins
    // the real widget handoff path (handed_off rows + no agent reply).
    // Cost: one discarded agent turn per pre-handed-off conversation (the
    // first suppress latches; later turns latch-first without agent spend).
    const s = await setup({
      reg: agentReg, env: lateEnv,
      broker: { sessionState: async () => ({ escalated: true, queueName: "Tubot_Queue", queueId: null }) },
      agent: () => ({ reply: "DISCARDED", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.res.status).toBe(202);
    expect(r.json.accepted).toBe(true);
    expect(r.json.suppressed).toBeUndefined();
    await s.flush();
    expect(methods(s.calls)).not.toContain("echo");
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("handed_off");
  });

  test("verify-late without async keeps the serial inline verify", async () => {
    const s = await setup({
      reg: agentReg, env: { VERIFY_LATE: "on" },
      agent: () => ({ reply: "HELD", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const r = await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    expect(r.json.inline).toBe(true);
    expect(r.json.verifyLate).toBeUndefined();
    expect(methods(s.calls)).toContain("browserTurn");
    expect(r.json.requestId).toBe(ECHO_REQUEST_ID);
  });
});

describe("async overhead trims (executor immediacy + concurrent handoff)", () => {
  const due = (s: { sql: { exec(q: string, ...p: unknown[]): unknown } }) =>
    (s.sql.exec("UPDATE events SET next_at=? WHERE state='agent_pending'", Date.now()) as unknown);

  test("async accept parks with a 60s alarm backstop and captures an immediate drive", async () => {
    const s = await setup({
      reg: agentReg, env: { ASYNC_ACCEPT: "on" },
      agent: () => ({ reply: "X", handoff: false, spans: {} }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    // Immediacy moved from alarm(0) to waitUntil: the alarm is now purely
    // the durable backstop (a dead isolate replays at the horizon), and the
    // first attempt runs on the hot isolate with no scheduling delay. The
    // original no-grace intent holds stronger: zero wait instead of <500ms.
    expect(s.alarm()).not.toBeNull();
    const horizon = s.alarm()! - Date.now();
    expect(horizon).toBeGreaterThan(59000);
    expect(horizon).toBeLessThanOrEqual(60000);
    expect(s.waitings()).toBe(1);
    await s.flush();
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
    // Executor success arms the status-poll horizon like inline submits
    // (the +60s backstop must not leak into the poll cadence).
    const pollIn = (s.sql.exec("SELECT next_at AS x FROM events").one().x as number) - Date.now();
    expect(pollIn).toBeGreaterThan(1000);
    expect(pollIn).toBeLessThanOrEqual(2000);
  });

  test("legacy executor overlaps the live handoff re-check with the agent turn", async () => {
    let release: ((v: unknown) => void) | null = null;
    let agentStarted = false;
    let handoffReads = 0;
    const s = await setup({
      reg: agentReg, env: { ASYNC_ACCEPT: "on" },
      // Call 1 is the accept-time cached read (resolves); call 2 is the
      // drive's live re-check (hangs until released). Counting pins the
      // hang to the drive deterministically — no flip-timing hole.
      broker: { sessionState: () => (++handoffReads === 1 ? Promise.resolve(null) : new Promise((r) => { release = r as (v: unknown) => void; })) },
      agent: () => { agentStarted = true; return { reply: "C", handoff: false, spans: { agentMs: 1 } }; },
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    const p = s.flush();
    await new Promise((r) => setTimeout(r, 100));
    // Serial code is still stuck awaiting the handoff read here.
    expect(agentStarted).toBe(true);
    expect(handoffReads).toBe(2);
    release!(null);
    await p;
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("late executor overlaps the handoff re-check with the agent turn", async () => {
    let release: ((v: unknown) => void) | null = null;
    let agentStarted = false;
    let handoffReads = 0;
    const s = await setup({
      reg: agentReg, env: { ASYNC_ACCEPT: "on", VERIFY_LATE: "on" },
      // Verify-late accept skips the live read for this fresh conversation,
      // so call 1 is the drive's re-check: hang it until released.
      broker: { sessionState: () => { handoffReads++; return new Promise((r) => { release = r as (v: unknown) => void; }); } },
      agent: () => { agentStarted = true; return { reply: "C", handoff: false, spans: { agentMs: 1 } }; },
    });
    const { cookie } = await mint(s.stub, s.reg);
    await postEcho(s.stub, s.reg, cookie, { conversationId: crypto.randomUUID(), messageId: crypto.randomUUID(), text: "hi" });
    const p = s.flush();
    await new Promise((r) => setTimeout(r, 100));
    expect(agentStarted).toBe(true);
    expect(handoffReads).toBe(1);
    release!(null);
    await p;
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("submitted");
  });

  test("async accept caches the handoff verdict; executor stays live", async () => {
    let sessionStateCalls = 0;
    const s = await setup({
      reg: agentReg, env: { ASYNC_ACCEPT: "on" },
      broker: { sessionState: async () => { sessionStateCalls++; return null; } },
      agent: () => ({ reply: "C", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    // Two turns, same conversation; each drive re-checks live exactly once.
    // Turn 1: accept live-read (miss, 1) + drive (1) = 2. Turn 2: accept
    // cache-hit (0) + drive (1) = 3. The accept cache and the live executor
    // re-check are proven by totals (mid-turn handoff must suppress).
    await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "one" });
    await s.flush();
    expect(sessionStateCalls).toBe(2);
    await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "two" });
    await s.flush();
    expect(sessionStateCalls).toBe(3);
  });

  test("inline accept never caches handoff (no executor backstop there)", async () => {
    let sessionStateCalls = 0;
    const s = await setup({
      reg: agentReg,
      broker: { sessionState: async () => { sessionStateCalls++; return null; } },
      agent: () => ({ reply: "C", handoff: false, spans: { agentMs: 1 } }),
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "one" });
    await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "two" });
    expect(sessionStateCalls).toBe(2);
  });

  test("latched conversation suppresses in the executor without agent spend", async () => {
    // The first drive fails transiently; the latch lands before the next
    // pass, which suppresses pre-agent. turns 1 = the failed first drive;
    // the LATCHED pass spends zero agent (a regressed latch check would
    // invoke the agent again and transient-park instead of handing off).
    const s = await setup({
      reg: agentReg, env: { ASYNC_ACCEPT: "on" },
      agent: () => { throw new Error("agent down"); },
    });
    const { cookie } = await mint(s.stub, s.reg);
    const conv = crypto.randomUUID();
    await postEcho(s.stub, s.reg, cookie, { conversationId: conv, messageId: crypto.randomUUID(), text: "hi" });
    await s.flush();
    s.sql.exec("INSERT OR IGNORE INTO handoffs(conversation_id,reason,created_at) VALUES(?,?,?)", conv, "escalated", Date.now());
    due(s);
    await s.stub.alarm();
    expect(s.turns.length).toBe(1);
    expect(s.sql.exec("SELECT state FROM events").one().state).toBe("handed_off");
  });
});
