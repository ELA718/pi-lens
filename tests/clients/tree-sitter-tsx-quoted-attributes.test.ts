import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import {
	assertGrammarAvailable,
	makeRealRunnerEnv,
} from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();
const client = getSharedTreeSitterClient()!;

function errorCount(node: {
	type: string;
	isMissing?: boolean;
	children?: unknown[];
}): number {
	let count = node.type === "ERROR" || node.isMissing ? 1 : 0;
	for (const child of node.children ?? [])
		count += errorCount(child as typeof node);
	return count;
}

beforeAll(async () => {
	await assertGrammarAvailable("tsx");
	await loader.loadQueries(process.cwd());
	for (const [name, language, source] of [
		["first.py", "python", "value = 1\n"],
		["second.js", "javascript", "const value = 1;\n"],
	] as const) {
		const { filePath } = env.addFile(name, source);
		await client.parseFile(filePath, language, source);
	}
});

afterAll(() => env.cleanup());

describe("TSX quoted attributes", () => {
	it.each(["plain", "[&_img]:h-auto", "a > b", "a & b", "&amp;"])(
		"parses %j without recovery and retains unsafe HTML findings",
		async (value) => {
			const source = `const view=<div className="${value}" dangerouslySetInnerHTML={{__html: raw}} />;`;
			const { filePath } = env.addFile(
				`quoted-${encodeURIComponent(value)}.tsx`,
				source,
			);
			const tree = await client.parseFile(filePath, "tsx", source);
			expect(tree).toBeTruthy();
			expect(errorCount(tree!.rootNode)).toBe(0);
			const query = loader.getQueryById("dangerously-set-inner-html");
			if (!query) throw new Error("dangerously-set-inner-html query missing");
			expect(await client.runQueryOnFile(query, filePath, "tsx")).toHaveLength(
				1,
			);
		},
	);

	it("keeps malformed quoted attributes in an error tree", async () => {
		const source = 'const view=<div className="unterminated />;';
		const { filePath } = env.addFile("malformed.tsx", source);
		const tree = await client.parseFile(filePath, "tsx", source);
		expect(tree).toBeTruthy();
		expect(errorCount(tree!.rootNode)).toBeGreaterThan(0);
	});
});
