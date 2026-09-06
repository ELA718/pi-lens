import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import { assertGrammarAvailable, makeRealRunnerEnv } from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv(); const loader = new TreeSitterQueryLoader();
beforeAll(async () => { await assertGrammarAvailable("typescript"); await loader.loadQueries(process.cwd()); env.addFile("package.json", "{}"); });
afterAll(() => env.cleanup());

async function findings(code: string) {
	const { filePath } = env.addFile("client.ts", code);
	const query = loader.getQueryById("ts-ssrf"); if (!query) throw new Error("missing SSRF rule");
	return getSharedTreeSitterClient()!.runQueryOnFile(query, filePath, "typescript");
}
const code = `import { createClient } from '@supabase/supabase-js';
const url = import.meta.env.VITE_SUPABASE_URL;
const decoratedFetch: typeof fetch = async (input, init) => fetch(input, init);
export const client = createClient(url, 'public-key', {global: {fetch: decoratedFetch}});`;

describe("private SDK fetch hooks", () => {
	it("recognizes a private transport hook with a configured SDK destination", async () => {
		expect(await findings(code)).toHaveLength(0);
	});
	it("follows a readonly imported configuration and rejects a changed initializer", async () => {
		const caller = code.replace("const url = import.meta.env.VITE_SUPABASE_URL;", "import { config } from './config';").replace("createClient(url,", "createClient(config.url,");
		env.addFile("config.ts", "export const config = {url: import.meta.env.VITE_SUPABASE_URL} as const;");
		expect(await findings(caller)).toHaveLength(0);
		env.addFile("config.ts", "export const config = {url: request.query.target} as const;");
		expect((await findings(caller)).length).toBeGreaterThan(0);
	});
	it.each([
		code.replace("const decoratedFetch", "export const decoratedFetch"),
		code + "\ndecoratedFetch(request.query.target);",
		code + "\nexport const hooks = { decoratedFetch };",
		code.replace("=> fetch(input, init)", "=> { function forward(input) { return fetch(input, init); } return forward(request.query.target); }"),
		code.replace("import.meta.env.VITE_SUPABASE_URL", "request.query.target"),
		code.replace("=> fetch(input, init)", "=> { input = request.query.target; return fetch(input, init); }"),
		code.replace("'@supabase/supabase-js'", "'./fake-sdk'"),
	])("retains exported, independently callable, tainted or unproven hooks", async source => {
		expect((await findings(source)).length).toBeGreaterThan(0);
	});
});
