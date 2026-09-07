import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import { removeTempDirSync } from "./test-utils.js";

const tmpDirs: string[] = [];

async function count(ruleId: string, source: string): Promise<number> {
	const loader = new TreeSitterQueryLoader();
	const queries = await loader.loadQueries(process.cwd());
	const query = [...queries.values()]
		.flat()
		.find((candidate) => candidate.id === ruleId);
	if (!query) throw new Error(`missing query ${ruleId}`);
	const dir = fs.mkdtempSync(
		path.join(os.tmpdir(), "pi-lens-java-applicability-"),
	);
	tmpDirs.push(dir);
	const file = path.join(dir, "Sample.java");
	fs.writeFileSync(file, source);
	const client = getSharedTreeSitterClient();
	if (!client) throw new Error("shared TreeSitterClient unavailable");
	return (await client.runQueryOnFile(query, file, "java")).length;
}

afterAll(() => {
	for (const dir of tmpDirs) removeTempDirSync(dir);
});

describe("Java rule applicability", () => {
	it("checks only the first JDBC index argument", async () => {
		await expect(
			count(
				"prepared-statement-valid-indices",
				'class T { void f() { prefs.getInt("key", 0); prefs.getInt(key, 0); } }',
			),
		).resolves.toBe(0);
		await expect(
			count(
				"prepared-statement-valid-indices",
				"class T { void f() { prefs.getInt(1, 0); } }",
			),
		).resolves.toBe(0);
		await expect(
			count(
				"prepared-statement-valid-indices",
				"class T { void f() { rs.getInt(0); stmt.setInt(0, value); } }",
			),
		).resolves.toBe(2);
		await expect(
			count(
				"prepared-statement-valid-indices",
				"class T { void f() { prefs.getInt(0, 0); } }",
			),
		).resolves.toBe(1);
	});

	it("ignores block and line comments when locating the first argument", async () => {
		await expect(
			count(
				"prepared-statement-valid-indices",
				`class T { void f() {
					rs.getInt(/* index */ 0);
					stmt.setInt(
						// index
						0, value);
					prefs.getInt("key", /* default */ 0);
					prefs.getInt("key",
						// default
						0);
				} }`,
			),
		).resolves.toBe(2);
	});

	it("excludes only proven fixed-arity overload delegation", async () => {
		await expect(
			count(
				"infinite-recursion",
				"class T { Object buildDeviceInfo(Context context) { return buildDeviceInfo(context, false); } Object buildDeviceInfo(Context context, boolean full) { return null; } }",
			),
		).resolves.toBe(0);
		await expect(
			count("infinite-recursion", "class T { int f() { return f(); } }"),
		).resolves.toBe(1);
		await expect(
			count(
				"infinite-recursion",
				"class T { int f() { return this.f(1); } int f(int value) { return value; } }",
			),
		).resolves.toBe(0);
		await expect(
			count("infinite-recursion", "class T { int f() { return this.f(); } }"),
		).resolves.toBe(1);
		await expect(
			count(
				"infinite-recursion",
				"class T { static int f() { return T.f(); } }",
			),
		).resolves.toBe(1);
		await expect(
			count(
				"infinite-recursion",
				"class T { static int f() { return T.f(1); } static int f(int value) { return value; } }",
			),
		).resolves.toBe(0);
		await expect(
			count(
				"infinite-recursion",
				"class T { int f() { return other.f(1); } int f(int value) { return value; } }",
			),
		).resolves.toBe(1);
		await expect(
			count(
				"infinite-recursion",
				"class T { int f() { return Other.f(1); } static int f(int value) { return value; } }",
			),
		).resolves.toBe(1);
	});

	it("retains same-arity recursion when another overload exists", async () => {
		await expect(
			count(
				"infinite-recursion",
				"class T { int f(int value) { return f(value); } int f(String value) { return 0; } }",
			),
		).resolves.toBe(1);
	});

	it("retains recursion from a current varargs method", async () => {
		await expect(
			count(
				"infinite-recursion",
				"class T { int f(int... values) { return f(1, 2); } int f(int first, int second) { return 0; } }",
			),
		).resolves.toBe(1);
	});

	it("excludes comments when counting call arguments", async () => {
		await expect(
			count(
				"infinite-recursion",
				"class T { int f(int value) { return f(value, /* default */ 0); } int f(int value, int mode) { return 0; } }",
			),
		).resolves.toBe(0);
	});

	it("retains conservative findings for varargs, ambiguous overloads, and recovery", async () => {
		await expect(
			count(
				"infinite-recursion",
				"class T { int f() { return f(1); } int f(int... values) { return 0; } }",
			),
		).resolves.toBe(1);
		await expect(
			count(
				"infinite-recursion",
				"class T { int f() { return f(1); } int f(int value) { return value; } int f(long value) { return 0; } }",
			),
		).resolves.toBe(1);
		await expect(
			count(
				"infinite-recursion",
				"class T { int f() { return f(1); } int f(int value { return value; } }",
			),
		).resolves.toBe(1);
	});

	it("retains the finding when bounded method traversal is exhausted", async () => {
		const statements = "use(value);".repeat(10_100);
		await expect(
			count(
				"infinite-recursion",
				`class T { int f() { return f(); ${statements} } }`,
			),
		).resolves.toBe(1);
	});

	it("rejects a wide Java node before materializing its children", () => {
		const client = getSharedTreeSitterClient();
		if (!client) throw new Error("shared TreeSitterClient unavailable");
		let childrenRead = false;
		const containingType = {
			type: "class_declaration",
			text: "class T {}",
			parent: null,
			childCount: 10_001,
			get children() {
				childrenRead = true;
				return [];
			},
		};
		const classBody = {
			type: "class_body",
			text: "{}",
			parent: containingType,
			childCount: 0,
			children: [],
		};
		const declaration = {
			type: "method_declaration",
			text: "int f() { return f(); }",
			parent: classBody,
			childCount: 0,
			children: [],
		};
		const call = {
			type: "method_invocation",
			text: "f()",
			parent: declaration,
			childCount: 0,
			children: [],
		};
		const keep = (
			client as unknown as {
				applyPostFilter(
					name: string,
					params: unknown,
					captures: Record<string, unknown>,
				): boolean;
			}
		).applyPostFilter("same_method_no_base_case", undefined, {
			NAME: { text: "f" },
			RECURSE: { text: "f" },
			CALL: call,
		});
		expect(keep).toBe(true);
		expect(childrenRead).toBe(false);
	});
});
