/**
 * module_report / read_symbol MCP smoke (#245, #256).
 *
 * Drives the real stdio JSON-RPC transport against a tiny synthetic TS project so
 * the review-graph lookup is instant (targeting the whole repo would be heavier).
 * module_report is read-only — it never builds a graph and never calls an LSP
 * server (#256), so `semantic.source` is always "none" here. Live-LSP enrichment
 * is re-homed to #236 (LSP writes graph edges); its module lives on at
 * clients/module-report-lsp.ts.
 *
 * Requires `npm run build` first (resolves mcp/server.js next to its source).
 */

import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { McpHarness } from "./harness.js";

interface ModuleReportShape {
	available: boolean;
	semantic: { source: string; references: boolean; implementations: boolean };
	api: Array<{ name: string }>;
}

function textOf(res: Record<string, unknown>): string {
	return (res.result as { content: { text: string }[] }).content[0].text;
}

function parseReport(res: Record<string, unknown>): ModuleReportShape {
	const text = textOf(res);
	return JSON.parse(
		text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1),
	) as ModuleReportShape;
}

function makeTinyProject(prefix: string): string {
	const dir = mkdtempSync(path.join(tmpdir(), prefix));
	writeFileSync(
		path.join(dir, "tsconfig.json"),
		JSON.stringify({ compilerOptions: { strict: true } }, null, 2),
	);
	writeFileSync(
		path.join(dir, "a.ts"),
		[
			"export function foo(): number {",
			"  return 1;",
			"}",
			"",
			"export function useFoo(): number {",
			"  return foo() + foo();",
			"}",
			"",
		].join("\n"),
	);
	return dir;
}

describe("module_report + read_symbol over MCP (tiny project)", () => {
	let projectDir: string;
	let harness: McpHarness;

	beforeAll(async () => {
		projectDir = makeTinyProject("pi-lens-modreport-mcp-");
		harness = new McpHarness({ cwd: projectDir });
		const init = await harness.request(1, "initialize", {
			protocolVersion: "2025-06-18",
			capabilities: {},
			clientInfo: { name: "modreport-smoke", version: "0" },
		});
		expect((init.result as { protocolVersion: string }).protocolVersion).toBe(
			"2025-06-18",
		);
		harness.notify("notifications/initialized");
	});

	afterAll(() => {
		harness.dispose();
		try {
			rmSync(projectDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
		} catch {
			// OS reclaims the temp dir eventually.
		}
	});

	it("answers pilens_module_report with a navigable report (read-only, source none)", async () => {
		const res = await harness.request(10, "tools/call", {
			name: "pilens_module_report",
			arguments: { file: path.join(projectDir, "a.ts") },
		});
		const report = parseReport(res);
		expect(report.available).toBe(true);
		expect(report.api.some((e) => e.name === "foo")).toBe(true);
		// Read path never calls LSP → always "none".
		expect(report.semantic.source).toBe("none");
		expect((res.result as { structuredContent?: unknown }).structuredContent).toBeUndefined();
	}, 30_000);

	it("answers pilens_read_symbol with the verbatim body", async () => {
		const res = await harness.request(11, "tools/call", {
			name: "pilens_read_symbol",
			arguments: { file: path.join(projectDir, "a.ts"), symbol: "foo" },
		});
		expect((res.result as { isError?: boolean }).isError).toBeFalsy();
		const text = textOf(res);
		expect(text).toContain("export function foo");
		expect(text).toContain("return 1;");
		const source = text.slice(text.indexOf("\n\n") + 2);
		expect((res.result as { structuredContent?: unknown }).structuredContent).toEqual({
			readReceipt: { version: 1, path: path.join(projectDir, "a.ts"), startLine: 1, endLine: 3,
				sourceHash: createHash("sha256").update(source).digest("hex") },
		});
	}, 30_000);

	it("receipts cover only the delivered slice, never an enclosing outline", async () => {
		const args = { file: path.join(projectDir, "a.ts"), line: 2, maxLines: 1, aroundLine: 1 };
		const res = await harness.request(13, "tools/call", {
			name: "pilens_read_enclosing", arguments: { ...args, onOversize: "slice" },
		});
		const source = textOf(res).split("\n\n").slice(1).join("\n\n");
		expect((res.result as { structuredContent?: unknown }).structuredContent).toEqual({
			readReceipt: { version: 1, path: path.join(projectDir, "a.ts"), startLine: 2, endLine: 2,
				sourceHash: createHash("sha256").update(source).digest("hex") },
		});
		const outline = await harness.request(14, "tools/call", {
			name: "pilens_read_enclosing", arguments: { ...args, onOversize: "outline" },
		});
		expect((outline.result as { structuredContent?: unknown }).structuredContent).toBeUndefined();
	}, 30_000);

	it("embeds did-you-mean suggestions on a near-miss (#523)", async () => {
		const res = await harness.request(12, "tools/call", {
			name: "pilens_read_symbol",
			arguments: { file: path.join(projectDir, "a.ts"), symbol: "fooo" },
		});
		expect((res.result as { isError?: boolean }).isError).toBe(true);
		expect((res.result as { structuredContent?: unknown }).structuredContent).toBeUndefined();
		expect(textOf(res)).toContain("foo");
	}, 30_000);

	it("AST search and replacement resolve relative paths against the requested cwd", async () => {
		const other = makeTinyProject("pi-lens-ast-cwd-");
		const file = path.join(other, "a.ts");
		writeFileSync(file, "export function elsewhere() { return 99; }\n");
		const original = readFileSync(path.join(projectDir, "a.ts"), "utf8");
		try {
			const search = await harness.request(20, "tools/call", {
				name: "pilens_ast_grep_search", arguments: { cwd: other, paths: ["a.ts"], lang: "typescript", nodeKind: "function_declaration" },
			});
			expect(textOf(search)).toContain("elsewhere");
			const replaced = await harness.request(21, "tools/call", {
				name: "pilens_ast_grep_replace", arguments: { cwd: other, paths: ["a.ts"], lang: "typescript", pattern: "return 99;", rewrite: "return 100;", apply: true },
			});
			expect((replaced.result as { isError?: boolean }).isError).toBeFalsy();
			expect(readFileSync(file, "utf8")).toContain("return 100;");
			expect(readFileSync(path.join(projectDir, "a.ts"), "utf8")).toBe(original);
		} finally { rmSync(other, { recursive: true, force: true }); }
	}, 30_000);
});
