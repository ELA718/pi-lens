import { describe, expect, it } from "vitest";
import { parseGitleaksReport } from "../../clients/gitleaks-client.js";

function report(match: string, secret: string, rule = "generic-api-key") {
	return parseGitleaksReport(JSON.stringify([{ RuleID: rule, File: "sample.test.ts", StartLine: 1, Match: match, Secret: secret }]));
}

describe("generic secret findings with non-credential values", () => {
	it.each(["idempotencyKey", "idempotency_key", "p_idempotency_key", "route_key", "optimizationKey"])("recognizes a protocol identifier in %s", field => {
		expect(report(`${field}: 'receiving-attempt-2048'`, "receiving-attempt-2048")).toEqual([]);
	});
	it("recognizes SQL named idempotency arguments", () => {
		expect(report("p_idempotency_key => '2739-route-exact'", "2739-route-exact")).toEqual([]);
	});
	it("recognizes readable compound routes but retains opaque UUID-shaped keys", () => {
		const route = "receiving--pallet--2026-08-01";
		expect(report(`route_key: '${route}'`, route)).toEqual([]);
		const opaque = "acacaaaa-caca-caca-caca-acacaaaaaaaa";
		expect(report(`route_key: '${opaque}'`, opaque)).toHaveLength(1);
	});
	it("retains opaque credential-shaped values even in a protocol field", () => {
		const secret = "R7q6FjJ6Gr8VXBdDdGcTgFmTYgVkP39P";
		expect(report(`idempotencyKey: '${secret}'`, secret)).toHaveLength(1);
	});
	it.each(["apiKey", "secret", "accessToken", "idempotencyApiKey", "authorization"])("retains credential values under %s even in test files", field => {
		expect(report(`${field}: 'receiving-attempt-2048'`, "receiving-attempt-2048")).toHaveLength(1);
	});
	it("does not change provider-specific secret findings", () => {
		expect(report("idempotencyKey: 'receiving-attempt-2048'", "receiving-attempt-2048", "provider-api-key")).toHaveLength(1);
	});
	it("retains incomplete metadata and unexpected syntax", () => {
		expect(report("", "receiving-attempt-2048")).toHaveLength(1);
		expect(report("idempotencyKey + 'receiving-attempt-2048'", "receiving-attempt-2048")).toHaveLength(1);
	});
	it("rejects an incomplete JWT header as evidence of a credential", () => {
		const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
		expect(report(`token: ${header}'`, header)).toEqual([]);
	});
	it("recognizes a deliberately invalid JWT signature fixture", () => {
		const token = "e30.eyJzZXNzaW9uX2lkIjoic2Vzc2lvbi0xMTEifQ.signature";
		expect(report(`accessToken: '${token}'`, token)).toEqual([]);
	});
	it("retains a complete signed-token-shaped value", () => {
		const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.R7q6FjJ6Gr8VXBdDdGcTgFmTYgVkP39P";
		expect(report(`accessToken: '${token}'`, token)).toHaveLength(1);
	});
});
