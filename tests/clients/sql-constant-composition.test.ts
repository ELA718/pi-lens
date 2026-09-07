import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import { assertGrammarAvailable, makeRealRunnerEnv } from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();
beforeAll(async () => { await assertGrammarAvailable("typescript"); await loader.loadQueries(process.cwd()); });
afterAll(() => env.cleanup());

async function findings(code: string) {
	const { filePath } = env.addFile("cleanup.ts", code);
	const query = loader.getQueryById("sql-injection");
	if (!query) throw new Error("SQL rule missing");
	return getSharedTreeSitterClient()!.runQueryOnFile(query, filePath, "typescript");
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

	it("retains a static candidate when the parser recovered an error", async () => {
		expect((await findings("const SQL = 'SELECT 1'; db.query(SQL); }")).length).toBeGreaterThan(0);
	});
});
