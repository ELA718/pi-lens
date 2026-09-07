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
	const { filePath } = env.addFile("global-bind.ts", code);
	const query = loader.getQueryById("sql-injection");
	if (!query) throw new Error("SQL rule missing");
	const client = getSharedTreeSitterClient();
	if (!client) throw new Error("shared TreeSitterClient unavailable");
	return client.runQueryOnFile(query, filePath, "typescript");
}

const nativeFetchBinding = [
	"function resolveFetch(fetchImpl) {",
	"  if (fetchImpl) return fetchImpl;",
	"  if (!globalThis.fetch) throw new Error('missing fetch');",
	"  return globalThis.fetch.bind(globalThis);",
	"}",
].join("\n");

const regexpCalls = [
	"const attrPattern = /a/g; attrPattern.exec(tag);",
	"const quotedPattern = /b/g; quotedPattern.exec(source);",
	"const rootAssetPattern = /c/g; rootAssetPattern.exec(source);",
].join("\n");

describe("RegExp global bind provenance", () => {
	it("accepts direct unmutated global fetch binding without hiding RegExp exec", async () => {
		expect(
			await findings(`${nativeFetchBinding}\n${regexpCalls}`),
		).toHaveLength(0);
	});

	it.each([
		"const evil = { bind(g) { g.RegExp.prototype.exec = db.exec; } }; evil.bind(globalThis);",
		"function evil() {} evil.bind = g => { g.RegExp.prototype.exec = db.exec; }; evil.bind(globalThis);",
		"globalThis.fetch.bind = evil; globalThis.fetch.bind(globalThis);",
		"globalThis.fetch = evil; globalThis.fetch.bind(globalThis);",
		"globalThis['fetch'] = { bind(g) { g.RegExp.prototype.exec = db.query; return () => {}; } }; globalThis.fetch.bind(globalThis);",
		"Reflect.set(globalThis, 'fetch', evil); globalThis.fetch.bind(globalThis);",
		"const key = 'fetch'; Reflect.set(globalThis, key, evil); globalThis.fetch.bind(globalThis);",
		"Reflect.set(globalThis.fetch, 'bind', evil); globalThis.fetch.bind(globalThis);",
		"fetch = evil; globalThis.fetch.bind(globalThis);",
		"globalThis['fetch']['bind'] = evil; globalThis.fetch.bind(globalThis);",
		"Object.defineProperty(globalThis.fetch, 'bind', { value: evil }); globalThis.fetch.bind(globalThis);",
		"Object.defineProperty(globalThis.fetch, 'b' + 'ind', { value: evil }); globalThis.fetch.bind(globalThis);",
		"const nativeFetch = globalThis.fetch; nativeFetch.bind(globalThis);",
		"const globals = globalThis; globals.fetch.bind(globals);",
		"Object.defineProperty(Function.prototype, 'bind', { value: evil }); globalThis.fetch.bind(globalThis);",
		"consume(globalThis.fetch); globalThis.fetch.bind(globalThis);",
		"Function.prototype.bind = evil; globalThis.fetch.bind(globalThis);",
		"Function.prototype['bind'] = evil; globalThis.fetch.bind(globalThis);",
		"const proto = Function.prototype; proto.bind = evil; globalThis.fetch.bind(globalThis);",
		"function run(globalThis) { globalThis.fetch.bind(globalThis); const matcher = /x/; matcher.exec(input); }",
		"const run = function globalThis() { globalThis.fetch.bind(globalThis); const matcher = /x/; matcher.exec(input); };",
		"const Run = class globalThis { method() { globalThis.fetch.bind(globalThis); const matcher = /x/; matcher.exec(input); } };",
		"const run = function* globalThis() { globalThis.fetch.bind(globalThis); const matcher = /x/; matcher.exec(input); };",
		"try {} catch (globalThis) { globalThis.fetch.bind(globalThis); const matcher = /x/; matcher.exec(input); }",
		"for (const globalThis of values) { globalThis.fetch.bind(globalThis); const matcher = /x/; matcher.exec(input); }",
		"const { globalThis } = value; globalThis.fetch.bind(globalThis);",
		"import { globalThis } from 'custom'; globalThis.fetch.bind(globalThis);",
	])(
		"retains RegExp findings for hostile or shadowed binding: %s",
		async (prefix) => {
			expect(
				(await findings(`${prefix}\n${regexpCalls}`)).length,
			).toBeGreaterThan(0);
		},
	);

	it.each(["db.exec(request.body.sql);", "db.query(request.body.sql);"])(
		"retains dynamic SQL calls with safe fetch binding: %s",
		async (sqlCall) => {
			expect(
				(await findings(`${nativeFetchBinding}\n${sqlCall}`)).length,
			).toBeGreaterThan(0);
		},
	);

	it("fails closed on parser recovery and proof budget exhaustion", async () => {
		expect(
			(await findings(`${nativeFetchBinding}\n${regexpCalls}}`)).length,
		).toBeGreaterThan(0);
		const overBudget = `${"const filler = 0;".repeat(10_001)}\n${nativeFetchBinding}\n${regexpCalls}`;
		expect((await findings(overBudget)).length).toBeGreaterThan(0);
	});
});
