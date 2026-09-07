import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ruleFilesForLanguage, TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import { assertGrammarAvailable, makeRealRunnerEnv } from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();
beforeAll(async () => { await assertGrammarAvailable("typescript"); await loader.loadQueries(process.cwd()); });
afterAll(() => env.cleanup());

async function findings(code: string, language = "typescript") {
	const { filePath } = env.addFile(language === "tsx" ? "cleanup.tsx" : "cleanup.ts", code);
	const query = loader.getQueryById("sql-injection");
	if (!query) throw new Error("SQL rule missing");
	return getSharedTreeSitterClient()!.runQueryOnFile(query, filePath, language);
}

describe("SQL composition provenance", () => {
	it.each([
		"db.query('SELECT id FROM records WHERE tag = $1', [tag]);",
		"const TAG = 'fixture'; function cleanup() { const rows = `SELECT id FROM records WHERE tag = '${TAG}'`; db.query(`DELETE FROM records WHERE id IN (${rows})`); }",
		"const TABLE = 'records'; db.query('SELECT * FROM ' + TABLE);",
		"db.query(('SELECT 1'));",
		"scenario.run((message) => console.log(message));",
	])("accepts static SQL and bound values: %s", async code => {
		expect(await findings(code)).toHaveLength(0);
	});

	it.each([
		"/^fixed$/.exec(input);",
		"new RegExp(pattern).exec(input);",
		"RegExp(pattern).exec(input);",
		"const matcher = /^fixed$/; matcher.exec(input);",
		"const matcher = /^fixed$/g; const match = matcher.exec(input);",
		"const matcher = /^fixed$/g; let match; while ((match = matcher.exec(input)) !== null) {}",
		"const matcher = /^fixed$/g; matcher.lastIndex = 0; matcher.exec(input);",
		"const patterns = [/a/g, /b/g]; for (const pattern of patterns) pattern.exec(input);",
		"function scan(input, patterns) { for (const pattern of patterns) pattern.exec(input); } scan(input, [/a/g]); scan(input, [/b/g]);",
		"const make = (source) => new RegExp(source, 'g'); const matcher = make('x'); matcher.exec(input);",
		"function one() { const matcher = /a/g; matcher.exec(input); } function two() { const matcher = /b/g; matcher.exec(input); }",
	])("accepts only source-proven RegExp execution: %s", async code => {
		expect(await findings(code)).toHaveLength(0);
	});

	it.each([
		"const rows = request.body.sql; db.query(`DELETE FROM records WHERE id IN (${rows})`);",
		"db.query((request.body.sql));",
		"db.query(flag ? request.body.sql : 'SELECT 1');",
		"db.query(await getSql());",
		"db.query(request.body.sql as string);",
		"db.query(<string>request.body.sql);",
		"const sql = 'SELECT * FROM records WHERE id = ' + request.params.id; db.query(sql);",
		"function run(sql) { db.query(sql); }",
		"const part = 'fixed'; consume(part => db.query('SELECT ' + part));",
		"const TAG = 'fixture'; function cleanup(TAG) { db.query(`SELECT '${TAG}'`); }",
		"const TAG = 'fixture'; const cleanup = TAG => db.query(`SELECT '${TAG}'`);",
		"const TAG = 'fixture'; function other() { const TAG = request.query.tag; db.query(`SELECT '${TAG}'`); }",
		"let TAG = 'fixture'; db.query(`SELECT '${TAG}'`);",
		"const TAG = 'fixture'; TAG = request.query.tag; db.query(`SELECT '${TAG}'`);",
		"function other() { const TAG = 'fixture'; } db.query(`SELECT '${TAG}'`);",
		"const a = b; const b = a; db.query(`SELECT '${a}'`);",
		"const rows = `SELECT '${request.query.tag}'`; db.query(`DELETE FROM records WHERE id IN (${rows})`);",
	])("retains dynamic, shadowed, cyclic or inaccessible values: %s", async code => {
		expect((await findings(code)).length).toBeGreaterThan(0);
	});

	it.each([
		"unknown.exec(input);",
		"let matcher = /^fixed$/; matcher.exec(input);",
		"const matcher = /^fixed$/; matcher = unknown; matcher.exec(input);",
		"const matcher = /^fixed$/; matcher.exec = sql.exec; matcher.exec(input);",
		"const matcher = /^fixed$/; const alias = matcher; alias.exec = sql.exec; matcher.exec(input);",
		"const matcher = /^fixed$/; function check(matcher) { matcher.exec(input); }",
		"const matcher = /^fixed$/; try {} catch (matcher) { matcher.exec(input); }",
		"const matcher = /^fixed$/; for (const matcher of unknown) matcher.exec(input);",
		"const matcher = /^fixed$/; { matcher.exec(input); let matcher; }",
		"matcher.exec(input); const matcher = /^fixed$/;",
		"const BASE = /^fixed$/; const matcher = BASE; matcher.exec(input);",
		"function scan(input: string, matchers: RegExp[]) { for (const matcher of matchers) matcher.exec(input); }",
		"const makeMatcher = (): RegExp => sql; const matcher = makeMatcher(); matcher.exec(input);",
		"const RegExp = SQL; new RegExp(pattern).exec(input);",
		"globalThis.RegExp = SQL; new RegExp(pattern).exec(input);",
		"Object.defineProperty(RegExp.prototype, 'exec', { value: SQL }); new RegExp(pattern).exec(input);",
		"Object.defineProperty(globalThis, 'RegExp', { value: SQL }); new RegExp(pattern).exec(input);",
		"RegExp.prototype.exec = SQL; new RegExp(pattern).exec(input);",
		"const matcher = /^fixed$/; matcher.lastIndex = dynamic; matcher.exec(input);",
		"import RegExp from 'custom'; new RegExp(pattern).exec(input);",
		"type RegExp = SqlExecutor; (value as RegExp).exec(input);",
		"const matcher = /^fixed$/; let alias; alias = matcher; alias.exec = sql.exec; matcher.exec(input);",
		"const matcher = /^fixed$/; Object.defineProperty(matcher, 'exec', { value: sql.exec }); matcher.exec(input);",
		"RegExp.prototype.exec = db.exec; /x/.exec(userInput);",
		"const matcher = /x/; RegExp.prototype.exec = db.exec; matcher.exec(userInput);",
		"const matcher = /x/; const box = { matcher }; box.matcher.exec = db.exec; matcher.exec(userInput);",
		"const matcher = /x/; const list = [matcher]; list[0].exec = db.exec; matcher.exec(userInput);",
		"const matcher = /x/; const alias = (matcher); alias.exec = db.exec; matcher.exec(userInput);",
		"const proto = RegExp.prototype; proto.exec = db.exec; /x/.exec(input);",
		"Object.assign(RegExp.prototype, { exec: db.exec }); /x/.exec(input);",
		"const globals = globalThis; globals.RegExp.prototype.exec = db.exec; /x/.exec(input);",
		"globalThis['RegExp'].prototype.exec = db.exec; /x/.exec(input);",
		"const matcher = /x/; function getMatcher() { return matcher; } getMatcher().exec = db.exec; matcher.exec(input);",
		"const matcher = /x/; new Mutator(matcher); matcher.exec(input);",
		"const matcher = /x/; (matcher).exec = db.exec; matcher.exec(input);",
		"globalThis['\\x52egExp'].prototype.exec = db.exec; /x/.exec(input);",
		"const patterns = [/x/g]; mutate(patterns); for (const pattern of patterns) pattern.exec(input);",
		"function scan(input, patterns) { for (const pattern of patterns) pattern.exec(input); } consume(scan); scan(input, [/x/g]);",
		"const make = (source) => new RegExp(source, 'g'); consume(make); const matcher = make('x'); matcher.exec(input);",
		"const patterns = other; const other = patterns; for (const pattern of patterns) pattern.exec(input);",
		"const make = () => make(); const matcher = make(); matcher.exec(input);",
		"function bind(fetchImpl) { const resolved = fetchImpl ?? globalThis.fetch; return resolved.bind(globalThis); } const matcher = /x/g; matcher.exec(input);",
		"const evil = { bind(g) { g.RegExp.prototype.exec = db.exec; } }; evil.bind(globalThis); const matcher = /x/; matcher.exec(input);",
		"const matcher = /x/; function f() { if (flag) { var matcher = db; } matcher.exec(input); }",
		"const matcher = /x/; function f({ matcher }) { matcher.exec(input); }",
		"const patterns = [/x/]; for (const matcher in patterns) matcher.exec(input);",
		"const matcher = /x/; function f() { for (var matcher of values) {} matcher.exec(input); }",
		"const matcher = /x/; function f() { for (var matcher in values) {} matcher.exec(input); }",
		"db.exec(request.body.sql);",
		"db.exec(request.body.sql);",
	])("retains unproven, mutable, shadowed, hoisted, or SQL exec calls: %s", async code => {
		expect((await findings(code)).length).toBeGreaterThan(0);
	});

	it("fails closed on missing syntax nodes", async () => {
		expect((await findings("const matcher = /x/; matcher.exec(input); function broken() {")).length).toBeGreaterThan(0);
	});

	it("fails closed when RegExp proof exceeds its node budget", async () => {
		const code = `${"const filler = 0;".repeat(10_001)} const matcher = /x/; matcher.exec(input);`;
		expect((await findings(code)).length).toBeGreaterThan(0);
	});

	it("fails closed before queueing a root wider than its node budget", async () => {
		const code = `const wide = [${Array.from({ length: 10_001 }, () => "0").join(",")}]; /x/.exec(input);`;
		expect((await findings(code)).length).toBeGreaterThan(0);
	});

	it("applies the SQL rule to TypeScript and TSX, not JavaScript", async () => {
		expect((await findings("db.query(request.body.sql)", "typescript")).length).toBeGreaterThan(0);
		expect((await findings("const view = <div />; db.query(request.body.sql)", "tsx")).length).toBeGreaterThan(0);
		expect(ruleFilesForLanguage("javascript").some(path => path.endsWith("/typescript/sql-injection.yml"))).toBe(false);
	});

	it("retains a static candidate when the parser recovered an error", async () => {
		expect((await findings("const SQL = 'SELECT 1'; db.query(SQL); }")).length).toBeGreaterThan(0);
	});
});
