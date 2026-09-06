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
	it("accepts a fixed template composed from uniquely bound string constants", async () => {
		expect(await findings("const TAG = 'fixture'; function cleanup() { const rows = `SELECT id FROM records WHERE tag = '${TAG}'`; db.query(`DELETE FROM records WHERE id IN (${rows})`); }")).toHaveLength(0);
	});

	it.each([
		"const rows = request.body.sql; db.query(`DELETE FROM records WHERE id IN (${rows})`);",
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
});
