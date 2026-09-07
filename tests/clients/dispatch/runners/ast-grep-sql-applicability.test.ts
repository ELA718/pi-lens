import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { loadAstGrepNapi } from "../../../../clients/deps/ast-grep-napi.js";
import { evaluateAstGrepRules } from "../../../../clients/dispatch/runners/ast-grep-napi.js";
import { scanProjectDiagnostics } from "../../../../clients/project-diagnostics/scanner.js";
import { __filterClientSqlDiagnosticsForTest } from "../../../../clients/lsp/index.js";
import { filterBoundAstGrepSqlDiagnostics } from "../../../../clients/sql-provenance.js";
import type { LSPDiagnostic } from "../../../../clients/lsp/client.js";
import { setupTestEnvironment } from "../../test-utils.js";

const env = setupTestEnvironment("pi-lens-sql-applicability-");
afterAll(() => env.cleanup());

async function diagnosticFor(content: string, language: "ts" | "tsx" = "ts"): Promise<LSPDiagnostic> {
	const sg = await loadAstGrepNapi();
	const root = sg[language].parse(content).root();
	const call = root.find({ rule: { kind: "call_expression" } } as never);
	if (!call) throw new Error("SQL call missing from fixture");
	const range = call.range();
	return {
		range: {
			start: { line: range.start.line, character: range.start.column },
			end: { line: range.end.line, character: range.end.column },
		},
		severity: 1,
		message: "SQL candidate",
		source: "ast-grep",
		code: "no-sql-in-code",
	};
}

describe("SQL scanner applicability through production project dispatch", () => {
	it("scans .mts without treating static or parameterized SQL as injection", async () => {
		const staticFile = path.join(env.tmpDir, "static.mts");
		const dynamicFile = path.join(env.tmpDir, "dynamic.mts");
		fs.writeFileSync(
			staticFile,
			[
				'client.query("SELECT * FROM users");',
				'client.query("SELECT * FROM users WHERE id = $1", [id]);',
				'client.query("status", ["SELECT * FROM audit_log"]);',
				'const TABLE = "users"; client.query(`SELECT * FROM ${TABLE}`);',
				'client.query(("SELECT 1"));',
			].join("\n"),
		);
		fs.writeFileSync(
			dynamicFile,
			[
				"client.query(`SELECT * FROM users WHERE id = ${request.params.id}`);",
				'client.query("SELECT * FROM users WHERE id = " + request.params.id);',
				"const part = 'fixed'; consume(part => client.query('SELECT ' + part));",
				"client.query((request.body.sql));",
				"client.query(flag ? request.body.sql : 'SELECT 1');",
				"client.query(await getSql());",
				"client.query(request.body.sql as string);",
				"client.query(<string>request.body.sql);",
			].join("\n"),
		);

		const result = await scanProjectDiagnostics({
			cwd: env.tmpDir,
			tier: "cheap",
			files: [staticFile, dynamicFile],
			maxFiles: 2,
		});
		const sql = result.diagnostics.filter(diagnostic =>
			["no-sql-in-code", "sql-injection"].includes(diagnostic.rule ?? ""),
		);

		expect(result.filesScanned).toBe(2);
		expect(sql.filter(diagnostic => diagnostic.filePath === staticFile)).toEqual([]);
		expect(sql.filter(diagnostic => diagnostic.filePath === dynamicFile).map(diagnostic => diagnostic.line)).toEqual(
			expect.arrayContaining([1, 2, 3, 4, 5, 6, 7, 8]),
		);
	});

	it("retains recovered-error candidates in both production SQL detectors", async () => {
		const file = path.join(env.tmpDir, "malformed.ts");
		fs.writeFileSync(file, "const SQL = 'SELECT 1'; client.query(SQL); }\n");
		const result = await scanProjectDiagnostics({ cwd: env.tmpDir, tier: "cheap", files: [file], maxFiles: 1 });
		const rules = result.diagnostics.map(diagnostic => diagnostic.rule);
		expect(rules).toContain("no-sql-in-code");
		expect(rules).toContain("sql-injection");
	});

	it("applies the TSX NAPI match cap after proven-static candidates without twin diagnostics", async () => {
		const file = path.join(env.tmpDir, "after-static-cap.tsx");
		const content = "const SQL = 'SELECT 1';\nclient.query(SQL);\nclient.query(request.body.sql);\nexport const View = () => <div />;";
		fs.writeFileSync(file, content);
		const sg = await loadAstGrepNapi();
		const diagnostics = evaluateAstGrepRules(file, sg.tsx.parse(content).root(), env.tmpDir, "jsts", { maxMatchesPerRule: 1 });
		expect(diagnostics.filter(diagnostic => diagnostic.rule?.startsWith("no-sql-in-code")).map(diagnostic => [diagnostic.rule, diagnostic.line])).toEqual([["no-sql-in-code", 3]]);
	});

	it.each(["mts", "cts", "mjs", "cjs", "jsx"])("admits .%s to the real NAPI scan", async extension => {
		const file = path.join(env.tmpDir, `dynamic-${extension}.${extension}`);
		fs.writeFileSync(file, "client.query(sql);\n");
		const result = await scanProjectDiagnostics({ cwd: env.tmpDir, tier: "cheap", files: [file], maxFiles: 1 });
		expect(result.diagnostics.some(diagnostic => diagnostic.rule?.startsWith("no-sql-in-code"))).toBe(true);
	});

	it("scans real TSX syntax while preserving static and parameterized SQL exclusions", async () => {
		const unsafeFile = path.join(env.tmpDir, "dynamic.tsx");
		const safeFile = path.join(env.tmpDir, "static.tsx");
		fs.writeFileSync(unsafeFile, [
			"let mutableSql = 'SELECT 1';",
			"export function View({ sql }: { sql: string }) {",
			"  const shadowedSql = 'SELECT 1';",
			"  return <button onClick={() => {",
			"    const shadowedSql = sql; client.query(shadowedSql);",
			"    mutableSql = sql; client.query(mutableSql);",
			"    client.query(sql);",
			"  }}>Run</button>;",
			"}",
		].join("\n"));
		fs.writeFileSync(safeFile, [
			"const SQL = 'SELECT 1';",
			"const TABLE = 'users';",
			"client.query(SQL);",
			"client.query('SELECT * FROM users WHERE id = $1', [id]);",
			"client.query(`SELECT * FROM ${TABLE}`);",
			"export const View = () => <div />;",
		].join("\n"));
		const result = await scanProjectDiagnostics({ cwd: env.tmpDir, tier: "cheap", files: [unsafeFile, safeFile], maxFiles: 2 });
		const sql = result.diagnostics.filter(diagnostic => diagnostic.rule?.startsWith("no-sql-in-code"));
		expect(sql.filter(diagnostic => diagnostic.filePath === unsafeFile).map(diagnostic => diagnostic.line)).toEqual([5, 6, 7]);
		expect(sql.filter(diagnostic => diagnostic.filePath === safeFile)).toEqual([]);
	});

	it("retains recovered and budget-exhausted TSX SQL candidates", async () => {
		const recoveredFile = path.join(env.tmpDir, "recovered.tsx");
		const recovered = "export const View = () => <div />;\nconst SQL = 'SELECT 1'; client.query(SQL); }\n";
		fs.writeFileSync(recoveredFile, recovered);
		const recoveredResult = await scanProjectDiagnostics({ cwd: env.tmpDir, tier: "cheap", files: [recoveredFile], maxFiles: 1 });
		expect(recoveredResult.diagnostics.filter(diagnostic => diagnostic.rule?.startsWith("no-sql-in-code")).map(diagnostic => diagnostic.line)).toEqual([2]);

		const budgetFile = path.join(env.tmpDir, "budget.tsx");
		const budgeted = `${Array.from({ length: 17_000 }, (_, i) => `const value${i} = ${i};`).join("\n")}\nconst SQL = 'SELECT 1';\nclient.query(SQL);\nexport const View = () => <div />;`;
		const sg = await loadAstGrepNapi();
		const budgetDiagnostics = evaluateAstGrepRules(budgetFile, sg.tsx.parse(budgeted).root(), env.tmpDir, "jsts");
		expect(budgetDiagnostics.filter(diagnostic => diagnostic.rule?.startsWith("no-sql-in-code")).map(diagnostic => diagnostic.rule)).toEqual(["no-sql-in-code"]);
	});
});

describe("bound ast-grep SQL candidate filtering", () => {
	it("does no I/O for empty, unrelated, or originally unbound candidates", async () => {
		const content = 'const SQL = "SELECT 1";\nclient.query(SQL);';
		const candidate = await diagnosticFor(content);
		let reads = 0;
		const readContent = async () => { reads++; return content; };
		expect(await __filterClientSqlDiagnosticsForTest("sample.ts", [], undefined, undefined, undefined, readContent)).toEqual([]);
		expect(await __filterClientSqlDiagnosticsForTest("sample.ts", [{ ...candidate, code: "other-rule" }], undefined, "utf-8", undefined, readContent)).toHaveLength(1);
		expect(await __filterClientSqlDiagnosticsForTest("sample.ts", [candidate], undefined, "utf-8", undefined, readContent)).toEqual([candidate]);
		expect(reads).toBe(0);
	});

	it("retains an old candidate when disk and a newer binding change during read", async () => {
		const oldContent = 'const SQL = "SELECT 1";\nclient.query(SQL);';
		const newContent = 'const SQL = "SELECT 2";\nclient.query(SQL);';
		const candidate = await diagnosticFor(oldContent);
		const capturedOldHash = createHash("sha256").update(oldContent).digest("hex");
		let currentBinding = capturedOldHash;
		const result = await __filterClientSqlDiagnosticsForTest(
			"sample.ts", [candidate], capturedOldHash, "utf-8", undefined,
			async () => {
				currentBinding = createHash("sha256").update(newContent).digest("hex");
				return newContent;
			},
		);
		expect(currentBinding).not.toBe(capturedOldHash);
		expect(result).toEqual([candidate]);
	});

	it("suppresses a proven constant only for the ast-grep contributor own exact snapshot", async () => {
		const content = 'const SQL = "SELECT 1";\nclient.query(SQL);';
		const diagnostic = await diagnosticFor(content);
		const hash = createHash("sha256").update(content).digest("hex");
		expect(await filterBoundAstGrepSqlDiagnostics([diagnostic], "sample.ts", content, hash, "utf-8")).toEqual([]);
		expect(await filterBoundAstGrepSqlDiagnostics([diagnostic], "sample.ts", content, undefined, "utf-8")).toEqual([diagnostic]);
		expect(await filterBoundAstGrepSqlDiagnostics([diagnostic], "sample.ts", content, "primary-bound-but-ast-unknown", "utf-8")).toEqual([diagnostic]);
	});

	it("matches the ast-grep contributor range in its negotiated encoding", async () => {
		const content = 'const SQL = "SELECT 1";\n/*😀*/ client.query(SQL);';
		const utf8Diagnostic = await diagnosticFor(content);
		const utf16Diagnostic = {
			...utf8Diagnostic,
			range: {
				start: { ...utf8Diagnostic.range.start, character: utf8Diagnostic.range.start.character - 2 },
				end: { ...utf8Diagnostic.range.end, character: utf8Diagnostic.range.end.character - 2 },
			},
		};
		const hash = createHash("sha256").update(content).digest("hex");
		expect(await filterBoundAstGrepSqlDiagnostics([utf16Diagnostic], "sample.ts", content, hash, "utf-16")).toEqual([]);
		expect(await filterBoundAstGrepSqlDiagnostics([utf8Diagnostic], "sample.ts", content, hash, "utf-16")).toEqual([utf8Diagnostic]);
	});

	it("retains candidates on parse errors and ambiguous or encoding-mismatched ranges", async () => {
		const malformed = 'const SQL = "SELECT 1";\nclient.query(SQL);\n}';
		const diagnostic = await diagnosticFor(malformed);
		const hash = createHash("sha256").update(malformed).digest("hex");
		expect(await filterBoundAstGrepSqlDiagnostics([diagnostic], "sample.ts", malformed, hash, "utf-8")).toEqual([diagnostic]);
		const exactContent = 'const SQL = "SELECT 1";\nclient.query(SQL);';
		const exactHash = createHash("sha256").update(exactContent).digest("hex");
		const wrongRange = { ...diagnostic, range: { ...diagnostic.range, end: { ...diagnostic.range.end, character: diagnostic.range.end.character + 1 } } };
		expect(await filterBoundAstGrepSqlDiagnostics([wrongRange], "sample.ts", exactContent, exactHash, "utf-16")).toEqual([wrongRange]);
	});
});
