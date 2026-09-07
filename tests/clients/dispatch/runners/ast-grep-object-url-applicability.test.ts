import { createHash } from "node:crypto";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { loadAstGrepNapi } from "../../../../clients/deps/ast-grep-napi.js";
import { evaluateAstGrepRules } from "../../../../clients/dispatch/runners/ast-grep-napi.js";
import type { LSPDiagnostic } from "../../../../clients/lsp/client.js";
import { __filterClientSqlDiagnosticsForTest } from "../../../../clients/lsp/index.js";
import { filterBoundAstGrepObjectUrlDiagnostics } from "../../../../clients/object-url-provenance.js";
import { setupTestEnvironment } from "../../test-utils.js";

const env = setupTestEnvironment("pi-lens-object-url-applicability-");
afterAll(() => env.cleanup());

async function napiRedirectLines(
	content: string,
	language: "ts" | "js" = "ts",
	maxMatchesPerRule = 10,
) {
	const sg = await loadAstGrepNapi();
	const diagnostics = evaluateAstGrepRules(
		path.join(env.tmpDir, `sample.${language}`),
		sg[language].parse(content).root(),
		env.tmpDir,
		"jsts",
		{ maxMatchesPerRule },
	);
	return diagnostics
		.filter(
			(diagnostic) =>
				diagnostic.rule ===
				(language === "ts" ? "no-open-redirect" : "no-open-redirect-js"),
		)
		.map((diagnostic) => diagnostic.line);
}

async function diagnosticFor(
	content: string,
	language: "ts" | "js" = "ts",
): Promise<LSPDiagnostic> {
	const sg = await loadAstGrepNapi();
	const call = sg[language]
		.parse(content)
		.root()
		.findAll({ rule: { kind: "call_expression" } } as never)
		.find((node) => node.text().startsWith("window.open("));
	if (!call) throw new Error("window.open call missing from fixture");
	const range = call.range();
	return {
		range: {
			start: { line: range.start.line, character: range.start.column },
			end: { line: range.end.line, character: range.end.column },
		},
		severity: 1,
		message: "Potential open redirect vulnerability — validate redirect URLs",
		source: "ast-grep",
		code: language === "ts" ? "no-open-redirect" : "no-open-redirect-js",
	};
}

const proven = [
	[
		"function",
		"function open(blob: Blob) { const url = URL.createObjectURL(blob); window.open(url, '_blank'); }",
	],
	[
		"arrow",
		"const open = (blob: Blob) => { const url = URL.createObjectURL(blob); window.open(url, '_blank'); };",
	],
	[
		"method",
		"class Printer { open(blob: Blob) { const url = URL.createObjectURL(blob); window.open(url, '_blank'); } }",
	],
	[
		"Promise callback",
		"Promise.resolve(blob).then(blob => { const url = URL.createObjectURL(blob); window.open(url, '_blank'); });",
	],
	[
		"try block",
		"function open(blob: Blob) { try { const url = URL.createObjectURL(blob); window.open(url, '_blank'); } finally {} }",
	],
] as const;

const unproven = [
	["unknown identifier", "window.open(next, '_blank');"],
	["property target", "window.open(request.next, '_blank');"],
	[
		"let declaration",
		"let url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"var declaration",
		"var url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"reassignment",
		"const url = URL.createObjectURL(blob); url = next; window.open(url, '_blank');",
	],
	[
		"update",
		"const url = URL.createObjectURL(blob); url++; window.open(url, '_blank');",
	],
	[
		"declaration after use",
		"window.open(url, '_blank'); const url = URL.createObjectURL(blob);",
	],
	["parameter", "function open(url: string) { window.open(url, '_blank'); }"],
	["import", "import { url } from './url.js'; window.open(url, '_blank');"],
	[
		"catch binding",
		"const url = URL.createObjectURL(blob); try {} catch (url) { window.open(url, '_blank'); }",
	],
	["destructuring", "const { url } = source; window.open(url, '_blank');"],
	[
		"nested shadow",
		"const url = URL.createObjectURL(blob); { const url = next; window.open(url, '_blank'); }",
	],
	[
		"arrow parameter shadow",
		"const url = URL.createObjectURL(blob); consume(url => window.open(url, '_blank'));",
	],
	[
		"shadowed URL",
		"const URL = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"shadowed window",
		"const window = popup; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"function-hoisted var URL",
		"function open(blob: Blob) { { var URL = factory; } const url = URL.createObjectURL(blob); window.open(url, '_blank'); }",
	],
	[
		"function-hoisted var window",
		"function open(blob: Blob) { { var window = popup; } const url = URL.createObjectURL(blob); window.open(url, '_blank'); }",
	],
	[
		"named function expression URL",
		"const open = function URL(blob: Blob) { const url = URL.createObjectURL(blob); window.open(url, '_blank'); };",
	],
	[
		"named class expression window",
		"const Printer = class window { open(blob: Blob) { const url = URL.createObjectURL(blob); window.open(url, '_blank'); } };",
	],
	[
		"enum URL",
		"enum URL { Value } const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"namespace window",
		"namespace window { export const value = 1; } const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"global URL write",
		"URL = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"global window write",
		"window = popup; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"global URL.createObjectURL write",
		"URL.createObjectURL = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"computed global URL.createObjectURL write",
		"URL['createObjectURL'] = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"escaped computed global URL.createObjectURL write",
		"URL['create\\u004fbjectURL'] = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"nested window.URL.createObjectURL write",
		"window.URL.createObjectURL = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"nested globalThis.URL.createObjectURL write",
		"globalThis.URL.createObjectURL = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"window.URL write",
		"window.URL = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"globalThis.URL write",
		"globalThis.URL = factory; const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"destructuring global URL write",
		"({ URL } = source); const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"generator function declaration URL",
		"function* URL() {} const url = URL.createObjectURL(blob); window.open(url, '_blank');",
	],
	[
		"aliased creator",
		"const create = URL.createObjectURL; const url = create(blob); window.open(url, '_blank');",
	],
	[
		"interprocedural creator",
		"function create(blob: Blob) { return URL.createObjectURL(blob); } const url = create(blob); window.open(url, '_blank');",
	],
	[
		"recovered syntax",
		"const url = URL.createObjectURL(blob); window.open(url, '_blank'); }",
	],
] as const;

describe("object URL redirect applicability through the real NAPI rules", () => {
	it.each(proven)(
		"suppresses a proven %s local object URL",
		async (_name, content) => {
			expect(await napiRedirectLines(content)).toEqual([]);
		},
	);

	it.each(unproven)("retains an unproven %s target", async (_name, content) => {
		expect(await napiRedirectLines(content)).toEqual([1]);
	});

	it("does not let a proven local object URL consume the finding cap", async () => {
		const content =
			"const url = URL.createObjectURL(blob); window.open(url, '_blank');\nwindow.open(request.next, '_blank');";
		expect(await napiRedirectLines(content, "ts", 1)).toEqual([2]);
	});

	it("keeps other redirect sinks and exact language boundaries unchanged", async () => {
		const content =
			"const url = URL.createObjectURL(blob); window.open(url, '_blank');\nwindow.location.href = url;\nres.redirect(url);";
		expect(await napiRedirectLines(content)).toEqual([2, 3]);
		expect(await napiRedirectLines(content, "js")).toEqual([2, 3]);
		const sg = await loadAstGrepNapi();
		const tsxDiagnostics = evaluateAstGrepRules(
			path.join(env.tmpDir, "sample.tsx"),
			sg.tsx.parse(`${content}\nexport const View = () => <div />;`).root(),
			env.tmpDir,
			"jsts",
		);
		expect(
			tsxDiagnostics.some((diagnostic) =>
				diagnostic.rule?.startsWith("no-open-redirect"),
			),
		).toBe(false);
	});

	it("retains a JavaScript target inside a dynamic with scope", async () => {
		const content =
			"with (scope) { const url = URL.createObjectURL(blob); window.open(url, '_blank'); }";
		expect(await napiRedirectLines(content, "js")).toEqual([1]);
	});

	it("retains a proven-looking target when traversal exceeds the budget", async () => {
		const content = `${Array.from({ length: 17_000 }, (_, index) => `const value${index} = ${index};`).join("\n")}\nconst url = URL.createObjectURL(blob);\nwindow.open(url, '_blank');`;
		expect(await napiRedirectLines(content)).toEqual([17_002]);
	});
});

describe("content-bound ast-grep LSP object URL filtering", () => {
	it("routes the ast-grep contributor's exact bound snapshot through the LSP seam", async () => {
		const content =
			"const url = URL.createObjectURL(blob); window.open(url, '_blank');";
		const diagnostic = await diagnosticFor(content);
		const hash = createHash("sha256").update(content).digest("hex");
		expect(
			await __filterClientSqlDiagnosticsForTest(
				"sample.ts",
				[diagnostic],
				hash,
				"utf-8",
				content,
			),
		).toEqual([]);
		expect(
			await __filterClientSqlDiagnosticsForTest(
				"sample.ts",
				[diagnostic],
				undefined,
				"utf-8",
				content,
			),
		).toEqual([diagnostic]);
	});

	it.each(proven)(
		"suppresses a proven %s target only for the exact ast-grep snapshot",
		async (_name, content) => {
			const diagnostic = await diagnosticFor(content);
			const hash = createHash("sha256").update(content).digest("hex");
			expect(
				await filterBoundAstGrepObjectUrlDiagnostics(
					[diagnostic],
					"sample.ts",
					content,
					hash,
					"utf-8",
				),
			).toEqual([]);
		},
	);

	it.each(unproven)("retains an unproven %s target", async (_name, content) => {
		const diagnostic = await diagnosticFor(content);
		const hash = createHash("sha256").update(content).digest("hex");
		expect(
			await filterBoundAstGrepObjectUrlDiagnostics(
				[diagnostic],
				"sample.ts",
				content,
				hash,
				"utf-8",
			),
		).toEqual([diagnostic]);
	});

	it("requires the ast-grep capture hash and exact encoded range", async () => {
		const content =
			"/*😀*/ const url = URL.createObjectURL(blob); window.open(url, '_blank');";
		const utf8 = await diagnosticFor(content);
		const utf16 = {
			...utf8,
			range: {
				start: {
					...utf8.range.start,
					character: utf8.range.start.character - 2,
				},
				end: { ...utf8.range.end, character: utf8.range.end.character - 2 },
			},
		};
		const hash = createHash("sha256").update(content).digest("hex");
		expect(
			await filterBoundAstGrepObjectUrlDiagnostics(
				[utf16],
				"sample.ts",
				content,
				hash,
				"utf-16",
			),
		).toEqual([]);
		expect(
			await filterBoundAstGrepObjectUrlDiagnostics(
				[utf8],
				"sample.ts",
				content,
				hash,
				"utf-16",
			),
		).toEqual([utf8]);
		expect(
			await filterBoundAstGrepObjectUrlDiagnostics(
				[utf8],
				"sample.ts",
				content,
				undefined,
				"utf-8",
			),
		).toEqual([utf8]);
		expect(
			await filterBoundAstGrepObjectUrlDiagnostics(
				[utf8],
				"sample.ts",
				`${content}\n`,
				hash,
				"utf-8",
			),
		).toEqual([utf8]);
	});

	it("does not borrow another source or rule identity", async () => {
		const content =
			"const url = URL.createObjectURL(blob); window.open(url, '_blank');";
		const diagnostic = await diagnosticFor(content);
		const hash = createHash("sha256").update(content).digest("hex");
		for (const changed of [
			{ ...diagnostic, source: "typescript" },
			{ ...diagnostic, code: "other-rule" },
		]) {
			expect(
				await filterBoundAstGrepObjectUrlDiagnostics(
					[changed],
					"sample.ts",
					content,
					hash,
					"utf-8",
				),
			).toEqual([changed]);
		}
	});

	it("retains a JavaScript LSP target inside a dynamic with scope", async () => {
		const content =
			"with (scope) { const url = URL.createObjectURL(blob); window.open(url, '_blank'); }";
		const diagnostic = await diagnosticFor(content, "js");
		const hash = createHash("sha256").update(content).digest("hex");
		expect(
			await filterBoundAstGrepObjectUrlDiagnostics(
				[diagnostic],
				"sample.js",
				content,
				hash,
				"utf-8",
			),
		).toEqual([diagnostic]);
	});

	it("retains budget-exhausted content", async () => {
		const content = `${Array.from({ length: 17_000 }, (_, index) => `const value${index} = ${index};`).join("\n")}\nconst url = URL.createObjectURL(blob);\nwindow.open(url, '_blank');`;
		const diagnostic = await diagnosticFor(content);
		const hash = createHash("sha256").update(content).digest("hex");
		expect(
			await filterBoundAstGrepObjectUrlDiagnostics(
				[diagnostic],
				"sample.ts",
				content,
				hash,
				"utf-8",
			),
		).toEqual([diagnostic]);
	});
});
