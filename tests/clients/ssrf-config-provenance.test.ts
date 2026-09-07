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
		["direct deployment config", `fetch(Deno.env.get("URL"));`],
		["direct process deployment config", `fetch(process.env.URL);`],
		["direct Bun deployment config", `fetch(Bun.env.URL);`],
		["direct import.meta deployment config", `fetch(import.meta.env.URL);`],
		["native URL from deployment config", `fetch(new URL(Deno.env.get("URL")));`],
		["native URL from trimmed deployment config", `fetch(new URL(Deno.env.get("URL").trim()));`],
		["unrelated URL class shadow", `{ class URL {} void URL; } fetch(new URL(Deno.env.get("URL")));`],
		["unrelated lexical shadow", `{ const Deno = request.runtime; void Deno; } fetch(Deno.env.get("URL"));`],
		["unrelated loop binding", `for (const Deno of request.runtimes) { void Deno; } fetch(Deno.env.get("URL"));`],
		["unrelated catch binding", `try {} catch (Deno) { void Deno; } fetch(Deno.env.get("URL"));`],
		["unrelated mutable-binding shadow", `const cfg = { url: Deno.env.get("URL") }; function unrelated() { const cfg = { url: request.url }; cfg.url = request.other; } fetch(cfg.url);`],
		["later safe property read", `const cfg = { url: Deno.env.get("URL") }; function send() { fetch(cfg.url); } function inspect() { return cfg.url; } send();`],
		["unrelated native prototype shadow", `function unrelated(String: typeof request.runtime) { String.prototype.trim = request.fn; } fetch(Deno.env.get("URL").trim());`],
		["unrelated class binding", `{ class Deno {} void Deno; } fetch(Deno.env.get("URL"));`],
	])("removes $0 destinations", async (_label, code) => {
		expect(await findings(code)).toHaveLength(0);
	});

	it.each([
		["request input", `async function send(request: { url: string }) { await fetch(request.url); }`],
		["shadowed private producer", `function configured() { return Deno.env.get("URL"); } function send(configured: () => string) { fetch(configured()); } send(() => request.url);`],
		["implicit URL coercion mutation", `URL.prototype.toString = function () { return request.url; }; fetch(new URL(Deno.env.get("URL")));`],
		["implicit URL coercion after trim", `URL.prototype.toString = function () { return request.url; }; fetch(new URL(Deno.env.get("URL").trim()));`],
		["unknown destructured member alias escape", `function acquire() { return ""; } const { __proto__: proto } = acquire(); const transform = proto.trim; use(transform); fetch(Deno.env.get("URL").trim());`],
		["destructured constructor prototype alias mutation", `const { constructor: Constructor } = ""; const proto = Constructor.prototype; proto.trim = () => request.url; fetch(Deno.env.get("URL").trim());`],
		["runtime object alias", `const runtime = Deno; runtime.env.set("URL", request.url); fetch(Deno.env.get("URL"));`],
		["global runtime member alias", `const runtime = globalThis.Deno; runtime.env.set("URL", request.url); fetch(Deno.env.get("URL"));`],
		["global runtime computed alias", `const runtime = globalThis["Deno"]; runtime.env.set("URL", request.url); fetch(Deno.env.get("URL"));`],
		["runtime Object.assign mutation", `Object.assign(Deno, { env: request.env }); fetch(Deno.env.get("URL"));`],
		["runtime unknown mutator", `mutate(Deno); fetch(Deno.env.get("URL"));`],
		["aliased String prototype mutation", `const NativeString = String; NativeString.prototype.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["globalThis String prototype mutation", `globalThis.String.prototype.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["Array prototype transform mutation", `Array.prototype.join = function () { return request.url; }; fetch(Deno.env.get("URL").split("/").join("/"));`],
		["String prototype transform mutation", `String.prototype.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["string instance prototype alias mutation", `const proto = Object.getPrototypeOf(""); proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["aliased prototype acquisition mutation", `const getProto = Object.getPrototypeOf; const proto = getProto(""); proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["computed instance prototype mutation", `const proto = ""["__proto__"]; proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["assigned computed prototype acquisition", `const key = "__proto__"; let proto; proto = ""[key]; proto.trim = () => request.url; fetch(Deno.env.get("URL").trim());`],
		["conditional computed prototype acquisition", `const key = "__proto__"; const proto = true ? ""[key] : ""[key]; proto.trim = () => request.url; fetch(Deno.env.get("URL").trim());`],
		["returned computed prototype acquisition", `const key = "__proto__"; function acquire() { return ""[key]; } const proto = acquire(); proto.trim = () => request.url; fetch(Deno.env.get("URL").trim());`],
		["binding-resolved computed prototype mutation", `const value = ""; const key = "__proto__"; const proto = value[key]; proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["destructured native prototype mutation", `const { __proto__: proto } = ""; proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["conditional-source destructuring mutation", `const value = true ? "" : ""; const { __proto__: proto } = value; proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["function-return destructuring mutation", `function value() { return ""; } const { __proto__: proto } = value(); proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["parameter destructuring mutation", `function alter({ __proto__: proto }) { proto.trim = function () { return request.url; }; } alter(""); fetch(Deno.env.get("URL").trim());`],
		["for-of destructuring mutation", `for (const { __proto__: proto } of [""]) { proto.trim = function () { return request.url; }; } fetch(Deno.env.get("URL").trim());`],
		["destructured native constructor mutation", `const { constructor: Constructor } = ""; Constructor.prototype.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["assigned destructured native acquisition", `const value = ""; let proto; ({ __proto__: proto } = (value)); proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["escaped computed prototype mutation", String.raw`const value = ""; const key = "\x5f_proto__"; const proto = value[key]; proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["parenthesized computed prototype mutation", `const value = ""; const key = "__proto__"; const proto = (value[key]); proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["asserted computed prototype mutation", `const value = ""; const key = "__proto__"; const proto = value[key] as any; proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["dynamic native instance property mutation", `const proto = ""[request.key]; proto.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["computed instance prototype alias mutation", `const proto = ""["__proto__"]; const alias = proto; alias.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["computed global String alias mutation", `const S = globalThis["String"]; S.prototype.trim = function () { return request.url; }; fetch(Deno.env.get("URL").trim());`],
		["URL prototype transform mutation", `URL.prototype.toString = function () { return request.url; }; fetch(new URL(Deno.env.get("URL")).toString());`],
		["for-var environment shadow", `function send() { for (var Deno of request.runtimes) {} fetch(Deno.env.get("URL")); }`],
		["for-const environment shadow", `for (const Deno of request.runtimes) { fetch(Deno.env.get("URL")); }`],
		["destructured config shadow", `const cfg = { url: Deno.env.get("URL") }; function send() { const { cfg } = request; fetch(cfg.url); }`],
		["later closure alias", `const cfg = { url: Deno.env.get("URL") }; function send() { fetch(cfg.url); } const alias = cfg; alias.url = request.url; send();`],
		["named class-expression URL", `const C = class URL { constructor() { this.value = request.url; } toString() { return this.value; } send() { fetch(new URL(Deno.env.get("URL")).toString()); } };`],
		["named function-expression URL", `const send = function URL() { fetch(new URL(Deno.env.get("URL")).toString()); };`],
		["renamed destructured environment", `const { runtime: Deno } = request; fetch(Deno.env.get("URL"));`],
		["array destructured environment", `const [Deno] = request.runtimes; fetch(Deno.env.get("URL"));`],
		["global environment assignment", `Deno = request.runtime; fetch(Deno.env.get("URL"));`],
		["global destructured environment assignment", `({ Deno } = request); fetch(Deno.env.get("URL"));`],
		["bare for environment assignment", `for (Deno of request.runtimes) {} fetch(Deno.env.get("URL"));`],
		["object embedding alias", `const cfg = { url: Deno.env.get("URL") }; function send() { fetch(cfg.url); } const holder = { cfg }; holder.cfg.url = request.url; send();`],
		["array embedding alias", `const cfg = { url: Deno.env.get("URL") }; function send() { fetch(cfg.url); } const holder = [cfg]; holder[0].url = request.url; send();`],
		["object spread override", `const config = { url: Deno.env.get("URL"), ...request.body }; fetch(config.url);`],
		["computed object override", `const config = { url: Deno.env.get("URL"), [request.key]: request.url }; fetch(config.url);`],
		["unknown object member", `const config = { url: Deno.env.get("URL"), target() { return request.url; } }; fetch(config.url);`],
		["binding alias mutation", `const config = { url: Deno.env.get("URL") }; const alias = config; alias.url = request.url; fetch(config.url);`],
		["environment alias mutation", `const env = Deno.env; env.set("URL", request.url); fetch(Deno.env.get("URL"));`],
		["direct environment mutation", `Deno.env.set("URL", request.url); fetch(Deno.env.get("URL"));`],
		["aliased environment method mutation", `const set = Deno.env.set; set("URL", request.url); fetch(Deno.env.get("URL"));`],
		["imported environment binding", `import Deno from "./runtime"; fetch(Deno.env.get("URL"));`],
		["destructured environment parameter", `function send({ Deno }: typeof request) { fetch(Deno.env.get("URL")); }`],
		["arrow environment parameter", `(Deno: typeof request.runtime) => fetch(Deno.env.get("URL"));`],
		["destructured environment binding", `const { Deno } = request; fetch(Deno.env.get("URL"));`],
		["environment replacement", `Deno.env = request.env; fetch(Deno.env.get("URL"));`],
		["Object.assign environment mutation", `Object.assign(process.env, { URL: request.url }); fetch(process.env.URL);`],
		["closure binding mutation", `const cfg = { url: Deno.env.get("URL") }; function mutate() { cfg.url = request.url; } mutate(); fetch(cfg.url);`],
		["function parameter write", `function dest(url: string) { url = request.url; return url; } fetch(dest(Deno.env.get("URL")));`],
		["function object-parameter escape", `function dest(config: { url: string }) { mutate(config); return config.url; } fetch(dest({ url: Deno.env.get("URL")! }));`],
		["function object-parameter alias", `function dest(config: { url: string }) { const alias = config; alias.url = request.url; return config.url; } fetch(dest({ url: Deno.env.get("URL")! }));`],
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
