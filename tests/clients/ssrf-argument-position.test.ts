import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import { assertGrammarAvailable, makeRealRunnerEnv } from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();
beforeAll(async () => { await assertGrammarAvailable("typescript"); await loader.loadQueries(process.cwd()); });
afterAll(() => env.cleanup());

async function findings(code: string) {
	const { filePath } = env.addFile("request.ts", code);
	const query = loader.getQueryById("ts-ssrf");
	if (!query) throw new Error("SSRF rule missing");
	return getSharedTreeSitterClient()!.runQueryOnFile(query, filePath, "typescript");
}

describe("SSRF URL argument position", () => {
	it.each([
		"fetch('https://service.example', userOptions);",
		"fetch(`https://service.example/chat`, withHeaders({ body: JSON.stringify(input) }));",
		"axios.post('https://service.example', request.body);",
	])("does not classify options or request bodies as destinations: %s", async code => {
		expect(await findings(code)).toHaveLength(0);
	});
	it.each([
		"fetch(userUrl, {});",
		"fetch(request.query.target, userOptions);",
		"axios.post(request.query.target, {});",
	])("retains untrusted destinations: %s", async code => {
		expect((await findings(code)).length).toBeGreaterThan(0);
	});
});
