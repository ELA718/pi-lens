import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { assertGrammarAvailable, makeRealRunnerEnv } from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();
beforeAll(async () => {
	await assertGrammarAvailable("typescript");
	await loader.loadQueries(process.cwd());
});
afterAll(() => env.cleanup());

async function provesExactOriginGuard(code: string): Promise<boolean> {
	const client = getSharedTreeSitterClient()!;
	const { filePath } = env.addFile("request.ts", code);
	const tree = await client.parseFile(filePath, "typescript", code);
	if (!tree) throw new Error("TypeScript parse failed");
	const stack = [tree.rootNode];
	let destination;
	while (stack.length > 0) {
		const node = stack.pop()!;
		if (
			node.type === "call_expression" &&
			node.childForFieldName?.("function")?.text === "fetch"
		) {
			destination = node.childForFieldName?.("arguments")?.children.find((child) => child.isNamed);
			break;
		}
		stack.push(...node.children);
	}
	if (!destination) throw new Error("fetch destination missing");
	const proven = Reflect.get(client, "isProvenExactOriginGuardedFetch").call(
		client,
		destination,
		tree.rootNode,
	);
	const query = loader.getQueryById("ts-ssrf");
	if (!query) throw new Error("SSRF rule missing");
	const findings = await client.runQueryOnFile(query, filePath, "typescript", {}, code);
	if (proven && findings.length !== 0) throw new Error("proven guard retained by ts-ssrf");
	if (!proven && findings.length === 0) throw new Error("unsafe guard suppressed by ts-ssrf");
	return proven;
}

const guardedFetch = (changes = "") => `
const BASE = "https://api.example.com";
const EXPECTED_ORIGIN = new URL(BASE).origin;
async function send(path: string, params: URLSearchParams) {
  const url = new URL(path, BASE);
  params.forEach((value, key) => url.searchParams.set(key, value));
  ${changes || `
  if (url.origin !== EXPECTED_ORIGIN) {
    throw new Error("origin mismatch");
  }
  return fetch(url.toString(), { method: "GET", redirect: "error" });`}
}`;

describe("exact parsed-origin fetch guard proof", () => {
	it("accepts a native URL, terminating mismatch guard, and rejected redirects", async () => {
		expect(await provesExactOriginGuard(guardedFetch())).toBe(true);
	});

	it.each([
		["missing redirect policy", `
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { method: "GET" });`],
		["redirect follow policy", `
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "follow" });`],
		["redirect override spread", `
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error", ...options });`],
		["computed redirect override", `
  const key = "redirect";
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error", [key]: "follow" });`],
		["escaped static redirect override", `
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error", "redir\\u0065ct": "follow" });`],
		["computed redirect getter", `
  const key = "redirect";
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error", get [key]() { return "follow"; } });`],
		["computed redirect method", `
  const key = "redirect";
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error", [key]() { return "follow"; } });`],
		["non-terminating rejected branch", `
  if (url.origin !== EXPECTED_ORIGIN) console.warn("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });`],
		["inverted guard", `
  if (url.origin === EXPECTED_ORIGIN) throw new Error("wrong branch");
  return fetch(url.toString(), { redirect: "error" });`],
		["mutation before validation", `
  url.toString = attackerSerializer;
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });`],
		["escape before validation", `
  observe(url);
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });`],
		["intervening mutation", `
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  url.host = inputHost;
  return fetch(url.toString(), { redirect: "error" });`],
		["intervening escape", `
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  observe(url);
  return fetch(url.toString(), { redirect: "error" });`],
		["destination alias", `
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  const alias = url;
  return fetch(alias.toString(), { redirect: "error" });`],
	])("rejects %s", async (_label, change) => {
		expect(await provesExactOriginGuard(guardedFetch(change))).toBe(false);
	});

	it("rejects a shadowed URL constructor", async () => {
		expect(await provesExactOriginGuard(guardedFetch().replace(
		"async function send(path: string, params: URLSearchParams)",
		"async function send(path: string, params: URLSearchParams, URL: any)",
	))).toBe(false);
	});

	it("rejects a guard origin shadowed by a function parameter", async () => {
		expect(await provesExactOriginGuard(guardedFetch().replace(
		"async function send(path: string, params: URLSearchParams)",
		"async function send(path: string, params: URLSearchParams, EXPECTED_ORIGIN: string)",
	))).toBe(false);
	});

	it.each([
		["destructuring", guardedFetch(`
  const { origin: EXPECTED_ORIGIN } = attacker;
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });`)],
		["catch binding", guardedFetch(`
  try { throw attacker; } catch (EXPECTED_ORIGIN) {
    if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
    return fetch(url.toString(), { redirect: "error" });
  }`)],
		["loop binding", guardedFetch(`
  for (const EXPECTED_ORIGIN of attackerOrigins) {
    if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
    return fetch(url.toString(), { redirect: "error" });
  }`)],
	])("rejects expected origin shadowed by %s", async (_label, code) => {
		expect(await provesExactOriginGuard(code)).toBe(false);
	});

	it("rejects a fixed base shadowed by a function parameter", async () => {
		expect(await provesExactOriginGuard(guardedFetch().replace(
		"async function send(path: string, params: URLSearchParams)",
		"async function send(path: string, params: URLSearchParams, BASE: string)",
	))).toBe(false);
	});

	it("rejects a fixed base shadowed by destructuring", async () => {
		expect(await provesExactOriginGuard(guardedFetch(`
  const { base: BASE } = attacker;
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });`))).toBe(false);
	});

	it("rejects mutation of native URL behavior", async () => {
		expect(await provesExactOriginGuard(`
URL.prototype.toString = attackerSerializer;
${guardedFetch()}`)).toBe(false);
	});

	it("rejects mutation through globalThis URL access", async () => {
		expect(await provesExactOriginGuard(`
Reflect.set(globalThis, "URL", attackerConstructor);
${guardedFetch()}`)).toBe(false);
	});

	it.each([
		["escaped prototype key", `URL["proto" + "type"].toString = attackerSerializer;`],
		["parenthesized prototype acquisition", `(URL).prototype.toString = attackerSerializer;`],
		["as-expression prototype acquisition", `(URL as typeof URL).prototype.toString = attackerSerializer;`],
		["transparent prototype lookup", `Object.getPrototypeOf(URL.prototype).toString = attackerSerializer;`],
		["escaped global constructor key", `const key = "URL"; globalThis[key] = attackerConstructor;`],
		["escaped self constructor key", `const key = "URL"; self[key] = attackerConstructor;`],
		["escaped window constructor key", `window["U" + "RL"] = attackerConstructor;`],
		["escaped Node global constructor key", `global["U" + "RL"] = attackerConstructor;`],
	])("rejects %s", async (_label, mutation) => {
		expect(await provesExactOriginGuard(`${mutation}\n${guardedFetch()}`)).toBe(false);
	});

	it.each([
		["parenthesized constructor", guardedFetch().replaceAll("new URL(", "new (URL)(")],
		["as-expression constructor", guardedFetch().replaceAll("new URL(", "new (URL as typeof URL)(")],
		["as-expression guarded instance", guardedFetch().replace("url.origin", "(url as URL).origin")],
		["escaped instance mutation", guardedFetch(`
  url["to" + "String"] = attackerSerializer;
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });`)],
	])("rejects %s", async (_label, code) => {
		expect(await provesExactOriginGuard(code)).toBe(false);
	});

	it.each([
		["URL instance", `
const BASE = "https://api.example.com";
const EXPECTED_ORIGIN = new URL(BASE).origin;
function unrelated(path: string) { const url = new URL(path, BASE); }
async function send() {
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });
}`],
		["expected origin", `
const BASE = "https://api.example.com";
{ const EXPECTED_ORIGIN = new URL(BASE).origin; }
async function send(path: string) {
  const url = new URL(path, BASE);
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });
}`],
		["fixed base", `
{ const BASE = "https://api.example.com"; }
const EXPECTED_ORIGIN = new URL(BASE).origin;
async function send(path: string) {
  const url = new URL(path, BASE);
  if (url.origin !== EXPECTED_ORIGIN) throw new Error("origin mismatch");
  return fetch(url.toString(), { redirect: "error" });
}`],
	])("rejects an out-of-scope %s declaration", async (_label, code) => {
		expect(await provesExactOriginGuard(code)).toBe(false);
	});

	it("rejects a guard derived from a different base", async () => {
		expect(await provesExactOriginGuard(guardedFetch().replace(
		"new URL(BASE).origin",
		"new URL(OTHER_BASE).origin",
	))).toBe(false);
	});
});
