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

async function sqlFunctionCaptures(code: string) {
	const { filePath } = env.addFile("security-control.ts", code);
	const query = loader.getQueryById("sql-injection");
	if (!query) throw new Error("SQL rule missing");
	return (
		await getSharedTreeSitterClient()!.runQueryOnFile(
			query,
			filePath,
			"typescript",
		)
	).map((match) => match.captures.SQL_FUNC);
}

describe("non-SQL callable provenance security controls", () => {
	it.each([
		[
			"callback calling runSql",
			"run",
			`function invoke(run: (id: string) => unknown, id: string) { return run(id); }
invoke(id => runSql(id), request.params.id);`,
		],
		[
			"callback using a computed query member",
			"execute",
			`function invoke(execute: (sql: string) => unknown, sql: string) { return execute(sql); }
invoke(sql => db["query"](sql), request.body.sql);`,
		],
		[
			"callback using Reflect.apply",
			"run",
			`function invoke(run: (sql: string) => unknown, sql: string) { return run(sql); }
invoke(sql => Reflect.apply(db.query, db, [sql]), request.body.sql);`,
		],
		[
			"callback using an aliased query function",
			"execute",
			`function invoke(execute: (sql: string) => unknown, sql: string) { return execute(sql); }
invoke(sql => { const q = db.query; return q(sql); }, request.body.sql);`,
		],
		[
			"callback after a destructured parameter",
			"run",
			`function invoke({ audit }: { audit: boolean }, run: (sql: string) => unknown, sql: string) { return run(sql); }
invoke({ audit: true }, sql => runSql(sql), request.body.sql);`,
		],
	])("retains %s", async (_name, sqlFunction, code) => {
		expect(await sqlFunctionCaptures(code)).toContain(sqlFunction);
	});

	it("retains a callable returned by an unknown imported wrapper", async () => {
		const code = `import { makeRunner } from "./unknown-wrapper.js";
const { execute } = makeRunner({ callback: runSql });
execute(request.body.sql);`;
		expect(await sqlFunctionCaptures(code)).toContain("execute");
	});
});
