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
	start(node: Node): number;
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
		if (["identifier", "shorthand_property_identifier_pattern"].includes(adapter.kind(current)) &&
			adapter.text(current) === name) return true;
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
		} else if (kind === "for_in_statement") {
			const binding = adapter.field(node, "left");
			if (!binding) return null;
			const found = containsBinding(binding, name, adapter, budget);
			if (found === undefined) return null;
			if (found) refused = true;
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

function hasParseErrorOrExhaustedBudget<Node>(
	root: Node,
	adapter: SqlSyntaxAdapter<Node>,
	budget: ResolutionBudget,
): boolean {
	const stack = [root];
	while (stack.length > 0) {
		if (!spend(budget)) return true;
		const node = stack.pop()!;
		if (adapter.kind(node) === "ERROR") return true;
		stack.push(...adapter.children(node));
	}
	return false;
}

function sameNode<Node>(left: Node | null | undefined, right: Node | null | undefined, adapter: SqlSyntaxAdapter<Node>): boolean {
	return !!left && !!right && adapter.key(left) === adapter.key(right);
}

function simpleParameters<Node>(
	fn: Node,
	adapter: SqlSyntaxAdapter<Node>,
): Node[] | null {
	const parameters = adapter.field(fn, "parameters");
	const parameter = adapter.field(fn, "parameter");
	const nodes = parameters
		? adapter.children(parameters).filter(adapter.isNamed)
		: parameter ? [parameter] : [];
	const identifiers: Node[] = [];
	for (const node of nodes) {
		const pattern = adapter.kind(node) === "identifier" ? node : adapter.field(node, "pattern");
		if (!pattern || adapter.kind(pattern) !== "identifier") return null;
		identifiers.push(pattern);
	}
	return identifiers;
}

function callArguments<Node>(call: Node, adapter: SqlSyntaxAdapter<Node>): Node[] | null {
	const args = adapter.field(call, "arguments");
	if (!args) return null;
	const named = adapter.children(args).filter(adapter.isNamed);
	return named.some(node => adapter.kind(node) === "spread_element") ? null : named;
}

function directCallForIdentifier<Node>(node: Node, adapter: SqlSyntaxAdapter<Node>): Node | null {
	const parent = adapter.parent(node);
	return parent && adapter.kind(parent) === "call_expression" &&
		sameNode(adapter.field(parent, "function"), node, adapter) ? parent : null;
}

function collectNamedIdentifiers<Node>(
	root: Node,
	name: string,
	adapter: SqlSyntaxAdapter<Node>,
	budget: ResolutionBudget,
): Node[] | null {
	const matches: Node[] = [];
	const stack = [root];
	while (stack.length > 0) {
		if (!spend(budget)) return null;
		const node = stack.pop();
		if (!node) return null;
		const kind = adapter.kind(node);
		if (adapter.isNamed(node) && (kind.endsWith("identifier") || kind.endsWith("identifier_pattern")) &&
			adapter.text(node) === name) matches.push(node);
		stack.push(...adapter.children(node));
	}
	return matches;
}

function containsNode<Node>(scope: Node, candidate: Node, adapter: SqlSyntaxAdapter<Node>): boolean {
	for (let node: Node | null = candidate; node; node = adapter.parent(node)) {
		if (sameNode(node, scope, adapter)) return true;
	}
	return false;
}

function isInlineFunction<Node>(node: Node, adapter: SqlSyntaxAdapter<Node>): boolean {
	return ["arrow_function", "function_expression"].includes(adapter.kind(node));
}

function callbackUsesOnlyStaticSql<Node>(
	callback: Node,
	parameterIndex: number,
	root: Node,
	adapter: SqlSyntaxAdapter<Node>,
	budget: ResolutionBudget,
	depth: number,
): boolean {
	const parameters = simpleParameters(callback, adapter);
	const sqlParameter = parameters?.[parameterIndex];
	if (!parameters || !sqlParameter) return false;
	const references = collectNamedIdentifiers(callback, adapter.text(sqlParameter), adapter, budget);
	if (!references) return false;
	let calls = 0;
	for (const reference of references) {
		if (sameNode(reference, sqlParameter, adapter)) continue;
		const call = directCallForIdentifier(reference, adapter);
		const args = call && callArguments(call, adapter);
		if (!call || !args?.[0] ||
			!resolveStaticSqlExpression(args[0], root, adapter, new Set(), budget, depth + 1)) return false;
		calls++;
	}
	return calls > 0;
}

function isProvenPrivateCallbackSql<Node>(
	sql: Node,
	root: Node,
	adapter: SqlSyntaxAdapter<Node>,
	budget: ResolutionBudget,
	depth: number,
): boolean {
	if (depth > MAX_RESOLUTION_DEPTH || adapter.kind(sql) !== "identifier") return false;

	let sourceCallback: Node | null = adapter.parent(sql);
	while (sourceCallback && !isInlineFunction(sourceCallback, adapter)) sourceCallback = adapter.parent(sourceCallback);
	if (!sourceCallback) return false;
	const sourceParameters = simpleParameters(sourceCallback, adapter);
	const sourceParameterIndex = sourceParameters?.findIndex(parameter => adapter.text(parameter) === adapter.text(sql)) ?? -1;
	const sourceParameter = sourceParameters?.[sourceParameterIndex];
	if (!sourceParameter || sourceParameterIndex < 0) return false;

	const sinkCall = adapter.parent(adapter.parent(sql) ?? sql);
	const sinkArgs = sinkCall && adapter.kind(sinkCall) === "call_expression" ? callArguments(sinkCall, adapter) : null;
	if (!sinkCall || !sameNode(sinkArgs?.[0], sql, adapter) || !containsNode(sourceCallback, sinkCall, adapter)) return false;
	const sourceReferences = collectNamedIdentifiers(sourceCallback, adapter.text(sourceParameter), adapter, budget);
	if (!sourceReferences || sourceReferences.some(reference =>
		!sameNode(reference, sourceParameter, adapter) && !sameNode(reference, sql, adapter)
	)) return false;

	if (!adapter.children(root).some(child => ["import_statement", "export_statement"].includes(adapter.kind(child)))) return false;

	const sourceArgs = adapter.parent(sourceCallback);
	const forwardingCall = sourceArgs && adapter.kind(sourceArgs) === "arguments" ? adapter.parent(sourceArgs) : null;
	const forwardedArgs = forwardingCall && adapter.kind(forwardingCall) === "call_expression"
		? callArguments(forwardingCall, adapter) : null;
	const callbackArgumentIndex = forwardedArgs?.findIndex(argument => sameNode(argument, sourceCallback, adapter)) ?? -1;
	const forwardingCallee = forwardingCall && adapter.field(forwardingCall, "function");
	if (!forwardingCall || callbackArgumentIndex < 0 || !forwardingCallee || adapter.kind(forwardingCallee) !== "identifier") return false;

	let helper: Node | null = adapter.parent(forwardingCall);
	while (helper && !["function_declaration", "function_expression", "arrow_function"].includes(adapter.kind(helper))) {
		helper = adapter.parent(helper);
	}
	if (!helper || adapter.kind(helper) !== "function_declaration" || !sameNode(adapter.parent(helper), root, adapter)) return false;
	const helperParameters = simpleParameters(helper, adapter);
	const forwardedParameterIndex = helperParameters?.findIndex(parameter => adapter.text(parameter) === adapter.text(forwardingCallee)) ?? -1;
	if (forwardedParameterIndex < 0) return false;
	const forwardedParameter = helperParameters?.[forwardedParameterIndex];
	if (!forwardedParameter) return false;
	const forwardedReferences = collectNamedIdentifiers(helper, adapter.text(forwardedParameter), adapter, budget);
	if (!forwardedReferences || forwardedReferences.some(reference =>
		!sameNode(reference, forwardedParameter, adapter) && !sameNode(reference, forwardingCallee, adapter)
	)) return false;
	const helperName = adapter.field(helper, "name");
	if (!helperName || adapter.kind(helperName) !== "identifier") return false;

	const helperReferences = collectNamedIdentifiers(root, adapter.text(helperName), adapter, budget);
	if (!helperReferences) return false;
	let callers = 0;
	for (const reference of helperReferences) {
		if (sameNode(reference, helperName, adapter)) continue;
		const call = directCallForIdentifier(reference, adapter);
		const args = call && callArguments(call, adapter);
		const callback = args?.[forwardedParameterIndex];
		if (!call || adapter.start(call) <= adapter.start(helper) || containsNode(helper, call, adapter) ||
			!callback || !isInlineFunction(callback, adapter) ||
			!callbackUsesOnlyStaticSql(callback, callbackArgumentIndex, root, adapter, budget, depth + 1)) return false;
		callers++;
	}
	return callers > 0;
}

function resolveStaticSqlExpression<Node>(
	node: Node | null,
	root: Node,
	adapter: SqlSyntaxAdapter<Node>,
	seen = new Set<string>(),
	budget: ResolutionBudget,
	depth = 0,
): boolean {
	if (!node || depth > MAX_RESOLUTION_DEPTH || !spend(budget)) return false;
	const kind = adapter.kind(node);
	if (kind === "string" || kind === "number") return true;
	if (kind === "parenthesized_expression") {
		return resolveStaticSqlExpression(adapter.children(node).find(adapter.isNamed) ?? null, root, adapter, seen, budget, depth + 1);
	}
	if (kind === "binary_expression") {
		if (!adapter.children(node).some(child => !adapter.isNamed(child) && adapter.text(child) === "+")) return false;
		return resolveStaticSqlExpression(adapter.field(node, "left"), root, adapter, new Set(seen), budget, depth + 1) &&
			resolveStaticSqlExpression(adapter.field(node, "right"), root, adapter, new Set(seen), budget, depth + 1);
	}
	if (kind === "template_string") {
		for (const child of adapter.children(node).filter(part => adapter.kind(part) === "template_substitution")) {
			if (!resolveStaticSqlExpression(adapter.children(child).find(adapter.isNamed) ?? null, root, adapter, new Set(seen), budget, depth + 1)) return false;
		}
		return true;
	}
	if (kind !== "identifier") return false;
	const name = adapter.text(node);
	if (seen.has(name)) return false;
	const value = resolveVisibleConst(name, node, root, adapter, budget);
	if (!value) return isProvenPrivateCallbackSql(node, root, adapter, budget, depth + 1);
	seen.add(name);
	return resolveStaticSqlExpression(value, root, adapter, seen, budget, depth + 1);
}

export function isStaticSqlExpression<Node>(
	node: Node | null,
	root: Node,
	adapter: SqlSyntaxAdapter<Node>,
): boolean {
	const budget = { remaining: MAX_TRAVERSED_NODES };
	return !hasParseErrorOrExhaustedBudget(root, adapter, budget) &&
		resolveStaticSqlExpression(node, root, adapter, new Set(), budget);
}

const napiAdapter: SqlSyntaxAdapter<SgNode> = {
	kind: node => String(node.kind()),
	text: node => node.text(),
	children: node => node.children(),
	field: (node, name) => node.field(name as never),
	parent: node => node.parent(),
	isNamed: node => node.isNamed(),
	key: node => `${node.kind()}:${node.range().start.index}:${node.range().end.index}`,
	start: node => node.range().start.index,
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
