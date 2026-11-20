import { describe, expect, it } from "bun:test";
import { turnScopeMatches, validAgentName, validAgentTurn, validChannelId, validConfig, validOrgId, validQueueName, validScope, validSessionHandoffState, type ProxyConfig } from "./contracts";

const flowAction = (): ProxyConfig["action"] => ({
  name: "Tubot_Proxy_Send_Notification",
  definitionName: "Tubot_Proxy_Echo",
  inputMapping: { definition: "definitionName", recipients: "recipients", parameters: "parameters" },
  outputMapping: { requestId: "requestId" },
});

describe("proxy flow contract", () => {
  it("accepts the notification flow mapping", () => {
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction() })).toBe(true);
  });
  it("accepts namespaced flow and definition names", () => {
    const action = { ...flowAction(), name: "tubot__Tubot_Proxy_Send_Notification", definitionName: "tubot__Tubot_Proxy_Echo" };
    expect(validConfig({ deploymentName: "ApiDeployment", action })).toBe(true);
  });
  it("rejects the legacy apex mapping shape", () => {
    const legacy = {
      name: "TubotProxyEcho",
      definitionName: "Tubot_Proxy_Echo",
      inputMapping: { recipient: "messagingEndUserId", text: "text", definition: "messageDefinitionName", requestKey: "requestKey" },
      outputMapping: { success: "success", requestId: "requestId" },
    } as unknown as ProxyConfig["action"];
    expect(validConfig({ deploymentName: "ApiDeployment", action: legacy })).toBe(false);
  });
  it("rejects duplicate mapped inputs", () => {
    const action = flowAction();
    action.inputMapping.recipients = "definitionName";
    expect(validConfig({ deploymentName: "ApiDeployment", action })).toBe(false);
  });
  it("keeps strict tenant channel scopes", () => {
    expect(validScope({ teamId: "team_1", orgId: "00Dxx0000000001AAA", channelId: "0Mjxx0000000001AAA" })).toBe(true);
    expect(validScope({ teamId: "", orgId: "00Dxx0000000001AAA", channelId: "0Mjxx0000000001AAA" })).toBe(false);
  });
  it("validates org and channel ids individually", () => {
    expect(validOrgId("00Dxx0000000001AAA")).toBe(true);
    expect(validOrgId("00Dxx0000000001")).toBe(true);
    expect(validOrgId("0Mjxx0000000001AAA")).toBe(false);
    expect(validOrgId("00Dxx!00000001AAA")).toBe(false);
    expect(validOrgId(undefined)).toBe(false);
    expect(validChannelId("0Mjxx0000000001AAA")).toBe(true);
    expect(validChannelId("0Mjxx0000000001")).toBe(true);
    expect(validChannelId("00Dxx0000000001AAA")).toBe(false);
    expect(validChannelId("")).toBe(false);
  });
  it("accepts absent echo scope and requires exact matches when present", () => {
    const scope = { teamId: "team_1", orgId: "00Dxx0000000001AAA", channelId: "0Mjxx0000000001AAA" };
    expect(turnScopeMatches(scope, {})).toBe(true);
    expect(turnScopeMatches(scope, { channelId: scope.channelId, orgId: scope.orgId })).toBe(true);
    expect(turnScopeMatches(scope, { channelId: "0Mjxx0000000002AAA", orgId: scope.orgId })).toBe(false);
    expect(turnScopeMatches(scope, { channelId: scope.channelId, orgId: "00Dxx0000000002AAA" })).toBe(false);
    expect(turnScopeMatches(scope, { channelId: "not-an-id", orgId: scope.orgId })).toBe(false);
    expect(turnScopeMatches(scope, { channelId: scope.channelId, orgId: null })).toBe(false);
  });
});

describe("proxy channel-agent contract", () => {
  it("accepts absent agent fields (serving is agent-only regardless)", () => {
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction() })).toBe(true);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentMode: "echo" })).toBe(true);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentMode: "agent" })).toBe(true);
  });
  it("accepts a bound agent name with either mode", () => {
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentName: "Support Agent", agentMode: "echo" })).toBe(true);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentName: "Support Agent", agentMode: "agent" })).toBe(true);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentName: "Support Agent" })).toBe(true);
  });
  it("rejects blank, overlong, or non-string agent names", () => {
    expect(validAgentName("Support Agent")).toBe(true);
    expect(validAgentName("")).toBe(false);
    expect(validAgentName("   ")).toBe(false);
    expect(validAgentName("x".repeat(161))).toBe(false);
    expect(validAgentName("x".repeat(160))).toBe(true);
    expect(validAgentName(undefined)).toBe(false);
    expect(validAgentName(42)).toBe(false);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentName: "" })).toBe(false);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentName: "x".repeat(161) })).toBe(false);
  });
  it("rejects unknown agent modes", () => {
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentMode: "agent" })).toBe(true);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentMode: "auto" as never })).toBe(false);
  });
  it("validates agent turns: shape, text bounds, optional message id", () => {
    const good = { conversationId: "c1", text: "hello", requestKey: "k1" };
    expect(validAgentTurn(good)).toBe(true);
    expect(validAgentTurn({ ...good, messageId: "m1", channelId: "0Mjxx0000000001AAA", orgId: "00Dxx0000000001AAA" })).toBe(true);
    expect(validAgentTurn({ ...good, conversationId: "" })).toBe(false);
    expect(validAgentTurn({ ...good, text: "" })).toBe(false);
    expect(validAgentTurn({ ...good, text: "x".repeat(4097) })).toBe(false);
    expect(validAgentTurn({ ...good, text: "x".repeat(4096) })).toBe(true);
    expect(validAgentTurn({ ...good, requestKey: "" })).toBe(false);
    expect(validAgentTurn({ ...good, messageId: "" })).toBe(false);
  });
  it("keeps turn scope matching for agent turns", () => {
    const scope = { teamId: "team_1", orgId: "00Dxx0000000001AAA", channelId: "0Mjxx0000000001AAA" };
    expect(turnScopeMatches(scope, { channelId: scope.channelId, orgId: scope.orgId })).toBe(true);
    expect(turnScopeMatches(scope, { channelId: "0Mjxx0000000002AAA" })).toBe(false);
  });
});

describe("proxy handoff guard contract", () => {
  it("accepts an absent expected queue and valid queue names", () => {
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction() })).toBe(true);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), expectedQueueName: "AI_Holding_Queue_100" })).toBe(true);
    expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), agentMode: "agent", expectedQueueName: "Tubot_Queue" })).toBe(true);
  });
  it("rejects malformed expected queue names", () => {
    for (const q of ["", "0startsWithDigit", "has space", "has-dash", "x".repeat(81), 42, null]) {
      expect(validQueueName(q)).toBe(false);
      expect(validConfig({ deploymentName: "ApiDeployment", action: flowAction(), expectedQueueName: q as never })).toBe(false);
    }
    expect(validQueueName("A")).toBe(true);
    expect(validQueueName("x".repeat(80))).toBe(true);
  });
  it("validates live handoff state shapes", () => {
    expect(validSessionHandoffState({ escalated: false, queueName: "AI_Holding_Queue_100", queueId: "00Gxx0000000001AAA" })).toBe(true);
    expect(validSessionHandoffState({ escalated: true, queueName: null, queueId: null })).toBe(true);
    expect(validSessionHandoffState({ escalated: false, queueName: null, queueId: null })).toBe(true);
    expect(validSessionHandoffState(null)).toBe(false);
    expect(validSessionHandoffState({ escalated: "yes", queueName: null, queueId: null })).toBe(false);
    expect(validSessionHandoffState({ escalated: false, queueName: "bad name", queueId: null })).toBe(false);
    expect(validSessionHandoffState({ escalated: false, queueName: null, queueId: "short" })).toBe(false);
    expect(validSessionHandoffState({ queueName: null, queueId: null })).toBe(false);
  });
});
