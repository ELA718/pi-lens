import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import {
	assertGrammarAvailable,
	makeRealRunnerEnv,
} from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();

beforeAll(async () => {
	await assertGrammarAvailable("typescript");
	await loader.loadQueries(process.cwd());
});
afterAll(() => env.cleanup());

async function findings(code: string) {
	const { filePath } = env.addFile("telemetry.ts", code);
	const query = loader.getQueryById("ts-ssrf");
	if (!query) throw new Error("SSRF rule missing");
	return getSharedTreeSitterClient()!.runQueryOnFile(
		query,
		filePath,
		"typescript",
	);
}

const telemetryDataflows = `
type Parsed = { dsn: string; envelopeUrl: string };
const sentryDsn = Deno.env.get("SENTRY_DSN")?.trim() || "";
function parseDsn(dsn: string): Parsed {
  let parsed: URL;
  try { parsed = new URL(dsn); } catch { throw new Error("invalid"); }
  const segments = parsed.pathname.split("/").filter(Boolean);
  const project = segments.at(-1);
  const base = segments.slice(0, -1).join("/");
  const apiBase = base ? \`/\${base}\` : "";
  return { dsn, envelopeUrl: \`\${parsed.origin}\${apiBase}/api/\${project}/envelope/\` };
}
function requireConfig() {
  const dsn = Deno.env.get("SENTRY_DSN")?.trim();
  if (!dsn) throw new Error("missing");
  return { dsn, environment: Deno.env.get("ENV") || "production" };
}
async function event(requestBody: unknown) {
  const parsed = parseDsn(sentryDsn);
  await fetch(parsed.envelopeUrl, { method: "POST", body: JSON.stringify(requestBody) });
}
export async function checkIn(input: { monitorSlug: string }) {
  const config = requireConfig();
  const parsed = parseDsn(config.dsn);
  await fetch(parsed.envelopeUrl, { method: "POST", body: JSON.stringify(input) });
}
`;

describe("SSRF deployment-configuration provenance", () => {
	it("removes both telemetry findings when only payload data is request-controlled", async () => {
		expect(await findings(telemetryDataflows)).toHaveLength(0);
	});

	it.each([
		["request input", `async function send(request: { url: string }) { await fetch(request.url); }`],
		["mixed input", `const base = Deno.env.get("BASE"); function join(a: string, b: string) { return a + b; } async function send(request: { url: string }) { await fetch(join(base!, request.url)); }`],
		["imported helper", `import { parseEndpoint } from "./config"; async function send() { await fetch(parseEndpoint(Deno.env.get("URL"))); }`],
		["shadowed environment", `function send(Deno: { env: { get(key: string): string } }) { return fetch(Deno.env.get("URL")); }`],
		["mutated environment", `Deno.env.get = request.envReader; async function send() { await fetch(Deno.env.get("URL")); }`],
		["dynamic environment key", `async function send(request: { key: string }) { await fetch(Deno.env.get(request.key)); }`],
		["exported wrapper", `export function targetUrl() { return Deno.env.get("URL")!; } async function send() { await fetch(targetUrl()); }`],
		["callback escape", `function targetUrl() { return Deno.env.get("URL")!; } register(targetUrl); async function send() { await fetch(targetUrl()); }`],
		["reassigned wrapper", `function targetUrl() { return Deno.env.get("URL")!; } async function send() { targetUrl = () => request.url; await fetch(targetUrl()); }`],
		["mutable object escape", `function config() { return { targetUrl: Deno.env.get("URL") }; } async function send() { const value = config(); mutate(value); await fetch(value.targetUrl); }`],
		["exported binding", `export const targetUrl = Deno.env.get("URL"); async function send() { await fetch(targetUrl); }`],
		["malformed syntax", `function targetUrl() { return Deno.env.get("URL")!; async function broken( { return 1; } async function send() { await fetch(targetUrl()); }`],
	])("retains $0 destinations", async (_label, code) => {
		expect((await findings(code)).length).toBeGreaterThan(0);
	});

	it("retains cyclic provenance", async () => {
		expect(
			(
				await findings(
					`const targetUrl = otherUrl; const otherUrl = targetUrl; async function send() { await fetch(targetUrl); }`,
				)
			).length,
		).toBeGreaterThan(0);
	});

	it("retains over-depth provenance", async () => {
		const bindings = Array.from(
			{ length: 40 },
			(_, index) =>
				`const targetUrl${index} = ${index === 39 ? 'Deno.env.get("URL")' : `targetUrl${index + 1}`};`,
		).join("\n");
		expect(
			(await findings(`${bindings}\nfetch(targetUrl0);`)).length,
		).toBeGreaterThan(0);
	});

	it("retains over-budget source bytes", async () => {
		expect(
			(
				await findings(
					`/* ${"x".repeat(512_001)} */\nfetch(Deno.env.get("URL"));`,
				)
			).length,
		).toBeGreaterThan(0);
	});

	it("retains over-budget syntax trees", async () => {
		const noise = Array.from({ length: 10_100 }, (_, index) => `const n${index} = ${index};`).join("\n");
		expect(
			(await findings(`${noise}\nfetch(Deno.env.get("URL"));`)).length,
		).toBeGreaterThan(0);
	});
});
