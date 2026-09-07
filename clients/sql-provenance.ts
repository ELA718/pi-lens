import { createHash } from "node:crypto";
import * as path from "node:path";
import type { SgNode } from "./deps/ast-grep-napi.js";
import { loadAstGrepNapi } from "./deps/ast-grep-napi.js";
import type { LSPDiagnostic } from "./lsp/client.js";
import type { PositionEncoding } from "./lsp/position-encoding.js";

const MAX_RESOLUTION_DEPTH = 32;
const MAX_TRAVERSED_NODES = 50_000;
const SQL_RULE_IDS = new Set(["no-sql-in-code", "no-sql-in-code-js"]);

export interface SqlSyntaxAdapter<Node> {
	kind(node: Node): string;
	text(node: Node): string;
	children(node: Node): Node[];
	field(node: Node, name: string): Node | null;
	parent(node: Node): Node | null;
	isNamed(node: Node): boolean;
	key(node: Node): string;
}

interface ResolutionBudget {
	remaining: number;
}

function spend(budget: ResolutionBudget): boolean {
	budget.remaining--;
	return budget.remaining >= 0;
}

function containsBinding<Node>(
	node: Node,
	name: string,
	adapter: SqlSyntaxAdapter<Node>,
	budget: ResolutionBudget,
): boolean | undefined {
	const stack = [node];
	while (stack.length > 0) {
		if (!spend(budget)) return undefined;
		const current = stack.pop()!;
		if (adapter.kind(current) === "identifier" && adapter.text(current) === name) return true;
		stack.push(...adapter.children(current));
	}
	return false;
}

function resolveVisibleConst<Node>(
	name: string,
	use: Node,
	root: Node,
	adapter: SqlSyntaxAdapter<Node>,
	budget: ResolutionBudget,
): Node | null {
	const declarators: Node[] = [];
	let refused = false;
	const stack = [root];
	while (stack.length > 0) {
		if (!spend(budget)) return null;
		const node = stack.pop()!;
		const kind = adapter.kind(node);
		if (kind === "variable_declarator" && adapter.text(adapter.field(node, "name") ?? node) === name) {
			const declaration = adapter.parent(node);
			if (declaration && adapter.kind(declaration) === "lexical_declaration" &&
				adapter.children(declaration).some(child => adapter.text(child) === "const")) {
				declarators.push(node);
			} else {
				refused = true;
			}
		} else if (["assignment_expression", "augmented_assignment_expression"].includes(kind)) {
			const left = adapter.field(node, "left");
			if (left && adapter.kind(left) === "identifier" && adapter.text(left) === name) refused = true;
		} else if (["formal_parameters", "catch_clause", "import_clause", "object_pattern", "array_pattern"].includes(kind)) {
			const binding = containsBinding(node, name, adapter, budget);
			if (binding === undefined) return null;
			if (binding) refused = true;
		} else if (kind === "arrow_function") {
			const parameter = adapter.field(node, "parameter");
			if (parameter) {
				const binding = containsBinding(parameter, name, adapter, budget);
				if (binding === undefined) return null;
				if (binding) refused = true;
			}
		}
		stack.push(...adapter.children(node));
	}
	if (refused || declarators.length !== 1) return null;
	const value = adapter.field(declarators[0], "value");
	if (!value) return null;
	const declaration = adapter.parent(declarators[0]);
	const scope = declaration && adapter.parent(declaration);
	if (!scope) return null;
	const scopeKey = adapter.key(scope);
	for (let node: Node | null = use; node; node = adapter.parent(node)) {
		if (!spend(budget)) return null;
		if (adapter.key(node) === scopeKey) return value;
	}
	return null;
}

export function isStaticSqlExpression<Node>(
	node: Node | null,
	root: Node,
	adapter: SqlSyntaxAdapter<Node>,
	seen = new Set<string>(),
	budget: ResolutionBudget = { remaining: MAX_TRAVERSED_NODES },
	depth = 0,
): boolean {
	if (!node || depth > MAX_RESOLUTION_DEPTH || !spend(budget)) return false;
	const kind = adapter.kind(node);
	if (kind === "string" || kind === "number") return true;
	if (kind === "parenthesized_expression") {
		return isStaticSqlExpression(adapter.children(node).find(adapter.isNamed) ?? null, root, adapter, seen, budget, depth + 1);
	}
	if (kind === "binary_expression") {
		if (!adapter.children(node).some(child => !adapter.isNamed(child) && adapter.text(child) === "+")) return false;
		return isStaticSqlExpression(adapter.field(node, "left"), root, adapter, new Set(seen), budget, depth + 1) &&
			isStaticSqlExpression(adapter.field(node, "right"), root, adapter, new Set(seen), budget, depth + 1);
	}
	if (kind === "template_string") {
		for (const child of adapter.children(node).filter(part => adapter.kind(part) === "template_substitution")) {
			if (!isStaticSqlExpression(adapter.children(child).find(adapter.isNamed) ?? null, root, adapter, new Set(seen), budget, depth + 1)) return false;
		}
		return true;
	}
	if (kind !== "identifier") return false;
	const name = adapter.text(node);
	if (seen.has(name)) return false;
	const value = resolveVisibleConst(name, node, root, adapter, budget);
	if (!value) return false;
	seen.add(name);
	return isStaticSqlExpression(value, root, adapter, seen, budget, depth + 1);
}

const napiAdapter: SqlSyntaxAdapter<SgNode> = {
	kind: node => String(node.kind()),
	text: node => node.text(),
	children: node => node.children(),
	field: (node, name) => node.field(name as never),
	parent: node => node.parent(),
	isNamed: node => node.isNamed(),
	key: node => `${node.kind()}:${node.range().start.index}:${node.range().end.index}`,
};

export function isProvenStaticSqlNapiMatch(match: SgNode): boolean {
	const args = napiAdapter.field(match, "arguments");
	const sql = args ? napiAdapter.children(args).find(napiAdapter.isNamed) ?? null : null;
	return !!sql && isStaticSqlExpression(sql, match.getRoot().root(), napiAdapter);
}

function isSqlCandidate(diagnostic: LSPDiagnostic): boolean {
	return diagnostic.source === "ast-grep" && SQL_RULE_IDS.has(String(diagnostic.code ?? ""));
}

export function hasAstGrepSqlCandidate(diagnostics: readonly LSPDiagnostic[]): boolean {
	return diagnostics.some(isSqlCandidate);
}

function languageForFile(sg: Awaited<ReturnType<typeof loadAstGrepNapi>>, filePath: string) {
	const ext = path.extname(filePath).toLowerCase();
	if (ext === ".tsx") return sg.tsx;
	if ([".ts", ".mts", ".cts"].includes(ext)) return sg.ts;
	if (ext === ".jsx") return sg.jsx;
	if ([".js", ".mjs", ".cjs"].includes(ext)) return sg.js;
	return undefined;
}

function encodedColumn(line: string, utf8Column: number, encoding: PositionEncoding): number | undefined {
	const bytes = Buffer.from(line, "utf8");
	if (utf8Column < 0 || utf8Column > bytes.length) return undefined;
	const prefix = bytes.subarray(0, utf8Column).toString("utf8");
	if (Buffer.byteLength(prefix, "utf8") !== utf8Column) return undefined;
	if (encoding === "utf-8") return utf8Column;
	if (encoding === "utf-32") return [...prefix].length;
	return prefix.length;
}

function exactRangeMatches(
	diagnostic: LSPDiagnostic,
	call: SgNode,
	content: string,
	encoding: PositionEncoding,
): boolean {
	const range = call.range();
	const lines = content.split("\n");
	const start = encodedColumn(lines[range.start.line] ?? "", range.start.column, encoding);
	const end = encodedColumn(lines[range.end.line] ?? "", range.end.column, encoding);
	return start !== undefined && end !== undefined &&
		diagnostic.range.start.line === range.start.line && diagnostic.range.start.character === start &&
		diagnostic.range.end.line === range.end.line && diagnostic.range.end.character === end;
}

export async function filterBoundAstGrepSqlDiagnostics(
	diagnostics: LSPDiagnostic[],
	filePath: string,
	content: string,
	astGrepContentHash: string | undefined,
	encoding: PositionEncoding,
): Promise<LSPDiagnostic[]> {
	if (!hasAstGrepSqlCandidate(diagnostics)) return diagnostics;
	const contentHash = createHash("sha256").update(content).digest("hex");
	if (astGrepContentHash !== contentHash) return diagnostics;
	try {
		const sg = await loadAstGrepNapi();
		const language = languageForFile(sg, filePath);
		if (!language) return diagnostics;
		const root = language.parse(content).root();
		if (root.findAll({ rule: { kind: "ERROR" } } as never).length > 0) return diagnostics;
		const calls = root.findAll({ rule: { kind: "call_expression" } } as never);
		return diagnostics.filter(diagnostic => {
			if (!isSqlCandidate(diagnostic)) return true;
			const candidates = calls.filter(call => exactRangeMatches(diagnostic, call, content, encoding));
			if (candidates.length !== 1) return true;
			const args = napiAdapter.field(candidates[0], "arguments");
			const sql = args ? napiAdapter.children(args).find(napiAdapter.isNamed) ?? null : null;
			return !sql || !isStaticSqlExpression(sql, root, napiAdapter);
		});
	} catch {
		return diagnostics;
	}
}
