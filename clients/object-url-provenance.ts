import { createHash } from "node:crypto";
import * as path from "node:path";
import type { SgNode } from "./deps/ast-grep-napi.js";
import { loadAstGrepNapi } from "./deps/ast-grep-napi.js";
import type { LSPDiagnostic } from "./lsp/client.js";
import type { PositionEncoding } from "./lsp/position-encoding.js";

const MAX_TRAVERSED_NODES = 50_000;
const OBJECT_URL_RULE_IDS = new Set([
	"no-open-redirect",
	"no-open-redirect-js",
]);
const SCOPE_KINDS = new Set([
	"program",
	"statement_block",
	"switch_body",
	"for_statement",
	"for_in_statement",
	"for_of_statement",
	"catch_clause",
	"function_declaration",
	"function_expression",
	"generator_function_declaration",
	"generator_function",
	"arrow_function",
	"method_definition",
	"class",
]);
const FUNCTION_KINDS = new Set([
	"function_declaration",
	"function_expression",
	"generator_function_declaration",
	"generator_function",
	"arrow_function",
	"method_definition",
]);

interface Budget {
	remaining: number;
}

interface Binding {
	name: string;
	scope: SgNode;
	node: SgNode;
	value?: SgNode;
	provenConst: boolean;
}

interface Analysis {
	bindings: Map<string, Map<string, Binding[]>>;
	writes: SgNode[];
	dynamicScopes: Set<string>;
	budget: Budget;
	valid: boolean;
}

function spend(budget: Budget): boolean {
	budget.remaining--;
	return budget.remaining >= 0;
}

function key(node: SgNode): string {
	const range = node.range();
	return `${node.kind()}:${range.start.index}:${range.end.index}`;
}

function field(node: SgNode, name: string): SgNode | null {
	return node.field(name as never) as SgNode | null;
}

function addBinding(index: Analysis["bindings"], binding: Binding): void {
	const scopeKey = key(binding.scope);
	const byName = index.get(scopeKey) ?? new Map<string, Binding[]>();
	const matches = byName.get(binding.name) ?? [];
	matches.push(binding);
	byName.set(binding.name, matches);
	index.set(scopeKey, byName);
}

function identifiers(node: SgNode, budget: Budget): string[] | undefined {
	const names: string[] = [];
	const stack = [node];
	while (stack.length > 0) {
		if (!spend(budget)) return undefined;
		const current = stack.pop();
		if (!current) return undefined;
		if (
			["identifier", "shorthand_property_identifier_pattern"].includes(
				String(current.kind()),
			)
		)
			names.push(current.text());
		stack.push(...current.children());
	}
	return names;
}

function nearestScope(node: SgNode | null, budget: Budget): SgNode | undefined {
	for (let current = node; current; current = current.parent()) {
		if (!spend(budget)) return undefined;
		if (SCOPE_KINDS.has(String(current.kind()))) return current;
	}
	return undefined;
}

function enclosingFunction(node: SgNode, budget: Budget): SgNode | undefined {
	for (let current = node.parent(); current; current = current.parent()) {
		if (!spend(budget)) return undefined;
		if (FUNCTION_KINDS.has(String(current.kind()))) return current;
	}
	return undefined;
}

function enclosingFunctionOrProgram(
	node: SgNode,
	budget: Budget,
): SgNode | undefined {
	for (let current = node.parent(); current; current = current.parent()) {
		if (!spend(budget)) return undefined;
		if (
			FUNCTION_KINDS.has(String(current.kind())) ||
			current.kind() === "program"
		)
			return current;
	}
	return undefined;
}

function collectAnalysis(root: SgNode): Analysis {
	const budget = { remaining: MAX_TRAVERSED_NODES };
	const bindings: Analysis["bindings"] = new Map();
	const writes: SgNode[] = [];
	const dynamicScopes = new Set<string>();
	const stack = [root];
	let valid = true;
	while (stack.length > 0) {
		if (!spend(budget))
			return { bindings, writes, dynamicScopes, budget, valid: false };
		const node = stack.pop();
		if (!node) return { bindings, writes, dynamicScopes, budget, valid: false };
		const kind = String(node.kind());
		if (kind === "ERROR") valid = false;
		if (kind === "with_statement") dynamicScopes.add(key(node));
		if (kind === "variable_declarator") {
			const name = field(node, "name");
			const declaration = node.parent();
			const scope =
				declaration?.kind() === "variable_declaration"
					? enclosingFunctionOrProgram(declaration, budget)
					: declaration && nearestScope(declaration.parent(), budget);
			if (!name || !scope)
				return { bindings, writes, dynamicScopes, budget, valid: false };
			const names = identifiers(name, budget);
			if (!names)
				return { bindings, writes, dynamicScopes, budget, valid: false };
			const directName = name.kind() === "identifier";
			const provenConst =
				directName &&
				declaration?.kind() === "lexical_declaration" &&
				declaration.children().some((child) => child.text() === "const");
			for (const bindingName of names) {
				addBinding(bindings, {
					name: bindingName,
					scope,
					node,
					value: directName ? (field(node, "value") ?? undefined) : undefined,
					provenConst,
				});
			}
		} else if (kind === "arrow_function") {
			const parameter = field(node, "parameter");
			if (parameter) {
				const names = identifiers(parameter, budget);
				if (!names)
					return { bindings, writes, dynamicScopes, budget, valid: false };
				for (const name of names)
					addBinding(bindings, {
						name,
						scope: node,
						node: parameter,
						provenConst: false,
					});
			}
		} else if (kind === "formal_parameters") {
			const scope = enclosingFunction(node, budget);
			const names = identifiers(node, budget);
			if (!scope || !names)
				return { bindings, writes, dynamicScopes, budget, valid: false };
			for (const name of names)
				addBinding(bindings, { name, scope, node, provenConst: false });
		} else if (kind === "catch_clause") {
			const parameter = field(node, "parameter");
			if (parameter) {
				const names = identifiers(parameter, budget);
				if (!names)
					return { bindings, writes, dynamicScopes, budget, valid: false };
				for (const name of names)
					addBinding(bindings, {
						name,
						scope: node,
						node: parameter,
						provenConst: false,
					});
			}
		} else if (kind === "import_statement") {
			const names = identifiers(node, budget);
			const scope = nearestScope(node.parent(), budget);
			if (!names || !scope)
				return { bindings, writes, dynamicScopes, budget, valid: false };
			for (const name of names)
				addBinding(bindings, { name, scope, node, provenConst: false });
		} else if (
			[
				"function_declaration",
				"generator_function_declaration",
				"class_declaration",
				"enum_declaration",
				"internal_module",
			].includes(kind)
		) {
			const name = field(node, "name");
			const scope = nearestScope(node.parent(), budget);
			if (
				name &&
				["identifier", "type_identifier"].includes(String(name.kind())) &&
				scope
			) {
				addBinding(bindings, {
					name: name.text(),
					scope,
					node: name,
					provenConst: false,
				});
			}
		} else if (
			["function_expression", "generator_function", "class"].includes(kind)
		) {
			const name = field(node, "name");
			if (
				name &&
				["identifier", "type_identifier"].includes(String(name.kind()))
			) {
				addBinding(bindings, {
					name: name.text(),
					scope: node,
					node: name,
					provenConst: false,
				});
			}
		} else if (
			[
				"assignment_expression",
				"augmented_assignment_expression",
				"update_expression",
			].includes(kind)
		) {
			writes.push(node);
		}
		if (budget.remaining < 0)
			return { bindings, writes, dynamicScopes, budget, valid: false };
		stack.push(...node.children());
	}
	return { bindings, writes, dynamicScopes, budget, valid };
}

function visibleBinding(
	name: string,
	use: SgNode,
	analysis: Analysis,
): Binding | null | undefined {
	for (let scope: SgNode | null = use; scope; scope = scope.parent()) {
		if (!spend(analysis.budget)) return undefined;
		if (!SCOPE_KINDS.has(String(scope.kind()))) continue;
		const scopeKey = key(scope);
		if (!spend(analysis.budget)) return undefined;
		const matches = analysis.bindings.get(scopeKey)?.get(name) ?? [];
		if (matches.length === 0) continue;
		return matches.length === 1 ? matches[0] : undefined;
	}
	return null;
}

function writtenBinding(
	write: SgNode,
	analysis: Analysis,
): Binding | null | undefined {
	const target =
		field(write, "left") ??
		field(write, "argument") ??
		write.children().find((child) => child.kind() === "identifier") ??
		null;
	if (target?.kind() !== "identifier") return null;
	return visibleBinding(target.text(), target, analysis);
}

function isUnshadowedGlobal(
	name: string,
	use: SgNode,
	analysis: Analysis,
): boolean | undefined {
	const binding = visibleBinding(name, use, analysis);
	return binding === undefined ? undefined : binding === null;
}

function memberPath(
	target: SgNode,
	budget: Budget,
): { root: SgNode; properties: (string | undefined)[] } | undefined {
	const properties: (string | undefined)[] = [];
	let current = target;
	while (
		["member_expression", "subscript_expression"].includes(
			String(current.kind()),
		)
	) {
		if (!spend(budget)) return undefined;
		if (current.kind() === "member_expression") {
			const property = field(current, "property");
			properties.unshift(
				property?.kind() === "property_identifier"
					? property.text()
					: undefined,
			);
		} else {
			const index = field(current, "index");
			const text = index?.kind() === "string" ? index.text() : undefined;
			properties.unshift(
				text && !text.includes("\\") ? text.slice(1, -1) : undefined,
			);
		}
		const object = field(current, "object");
		if (!object) return undefined;
		current = object;
	}
	return { root: current, properties };
}

function hasUnsafeGlobalWrite(
	write: SgNode,
	analysis: Analysis,
): boolean | undefined {
	const target = field(write, "left") ?? field(write, "argument") ?? null;
	if (!target) return false;
	if (
		target.kind() === "identifier" &&
		["URL", "window"].includes(target.text())
	)
		return isUnshadowedGlobal(target.text(), target, analysis);
	if (["object_pattern", "array_pattern"].includes(String(target.kind()))) {
		const names = identifiers(target, analysis.budget);
		if (!names) return undefined;
		for (const name of names.filter((candidate) =>
			["URL", "window"].includes(candidate),
		)) {
			const global = isUnshadowedGlobal(name, target, analysis);
			if (global !== false) return global;
		}
		return false;
	}
	if (
		!["member_expression", "subscript_expression"].includes(
			String(target.kind()),
		)
	)
		return false;
	const path = memberPath(target, analysis.budget);
	if (!path) return undefined;
	if (path.root.kind() !== "identifier") return false;
	const [first, second] = path.properties;
	const couldBe = (actual: string | undefined, expected: string) =>
		actual === undefined || actual === expected;
	if (
		path.root.text() === "URL" &&
		path.properties.length === 1 &&
		couldBe(first, "createObjectURL")
	)
		return isUnshadowedGlobal("URL", path.root, analysis);
	if (
		["window", "globalThis"].includes(path.root.text()) &&
		((path.properties.length === 1 && couldBe(first, "URL")) ||
			(path.properties.length === 2 &&
				couldBe(first, "URL") &&
				couldBe(second, "createObjectURL")))
	)
		return isUnshadowedGlobal(path.root.text(), path.root, analysis);
	return false;
}

function hasDynamicScope(use: SgNode, analysis: Analysis): boolean | undefined {
	for (let current: SgNode | null = use; current; current = current.parent()) {
		if (!spend(analysis.budget)) return undefined;
		if (analysis.dynamicScopes.has(key(current))) return true;
	}
	return false;
}

function memberCall(
	node: SgNode,
	objectName: string,
	propertyName: string,
): boolean {
	if (node.kind() !== "call_expression") return false;
	const callee = field(node, "function");
	if (callee?.kind() !== "member_expression") return false;
	const object = field(callee, "object");
	const property = field(callee, "property");
	return (
		object?.kind() === "identifier" &&
		object.text() === objectName &&
		property?.kind() === "property_identifier" &&
		property.text() === propertyName
	);
}

function firstArgument(call: SgNode): SgNode | null {
	const args = field(call, "arguments");
	return args?.children().find((child) => child.isNamed()) ?? null;
}

export function isProvenObjectUrlNapiMatch(match: SgNode): boolean {
	if (!memberCall(match, "window", "open")) return false;
	const target = firstArgument(match);
	if (target?.kind() !== "identifier") return false;
	const root = match.getRoot().root();
	const analysis = collectAnalysis(root);
	if (!analysis.valid) return false;
	if (hasDynamicScope(match, analysis) !== false) return false;
	if (visibleBinding("window", match, analysis) !== null) return false;
	const binding = visibleBinding(target.text(), target, analysis);
	if (!binding?.provenConst || !binding.value) return false;
	if (hasDynamicScope(binding.value, analysis) !== false) return false;
	if (binding.node.range().start.index >= match.range().start.index)
		return false;
	if (!memberCall(binding.value, "URL", "createObjectURL")) return false;
	const callee = field(binding.value, "function");
	const url = callee && field(callee, "object");
	if (!url || visibleBinding("URL", url, analysis) !== null) return false;
	for (const write of analysis.writes) {
		const unsafeGlobalWrite = hasUnsafeGlobalWrite(write, analysis);
		if (unsafeGlobalWrite !== false) return false;
		const written = writtenBinding(write, analysis);
		if (written && key(written.node) === key(binding.node)) return false;
		if (written === undefined) return false;
	}
	return analysis.budget.remaining >= 0;
}

function isObjectUrlCandidate(diagnostic: LSPDiagnostic): boolean {
	return (
		diagnostic.source === "ast-grep" &&
		OBJECT_URL_RULE_IDS.has(String(diagnostic.code ?? ""))
	);
}

export function hasAstGrepObjectUrlCandidate(
	diagnostics: readonly LSPDiagnostic[],
): boolean {
	return diagnostics.some(isObjectUrlCandidate);
}

function languageForFile(
	sg: Awaited<ReturnType<typeof loadAstGrepNapi>>,
	filePath: string,
) {
	const ext = path.extname(filePath).toLowerCase();
	if (ext === ".tsx") return sg.tsx;
	if ([".ts", ".mts", ".cts"].includes(ext)) return sg.ts;
	if (ext === ".jsx") return sg.jsx;
	if ([".js", ".mjs", ".cjs"].includes(ext)) return sg.js;
	return undefined;
}

function encodedColumn(
	line: string,
	utf8Column: number,
	encoding: PositionEncoding,
): number | undefined {
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
	const start = encodedColumn(
		lines[range.start.line] ?? "",
		range.start.column,
		encoding,
	);
	const end = encodedColumn(
		lines[range.end.line] ?? "",
		range.end.column,
		encoding,
	);
	return (
		start !== undefined &&
		end !== undefined &&
		diagnostic.range.start.line === range.start.line &&
		diagnostic.range.start.character === start &&
		diagnostic.range.end.line === range.end.line &&
		diagnostic.range.end.character === end
	);
}

export async function filterBoundAstGrepObjectUrlDiagnostics(
	diagnostics: LSPDiagnostic[],
	filePath: string,
	content: string,
	astGrepContentHash: string | undefined,
	encoding: PositionEncoding,
): Promise<LSPDiagnostic[]> {
	if (!hasAstGrepObjectUrlCandidate(diagnostics)) return diagnostics;
	if (astGrepContentHash !== createHash("sha256").update(content).digest("hex"))
		return diagnostics;
	try {
		const sg = await loadAstGrepNapi();
		const language = languageForFile(sg, filePath);
		if (!language) return diagnostics;
		const root = language.parse(content).root();
		const calls = root.findAll({ rule: { kind: "call_expression" } } as never);
		return diagnostics.filter((diagnostic) => {
			if (!isObjectUrlCandidate(diagnostic)) return true;
			const candidates = calls.filter((call) =>
				exactRangeMatches(diagnostic, call, content, encoding),
			);
			return (
				candidates.length !== 1 || !isProvenObjectUrlNapiMatch(candidates[0])
			);
		});
	} catch {
		return diagnostics;
	}
}
