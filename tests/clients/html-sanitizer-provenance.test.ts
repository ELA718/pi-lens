import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import { assertGrammarAvailable, makeRealRunnerEnv } from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();
beforeAll(async () => { await assertGrammarAvailable("tsx"); await loader.loadQueries(process.cwd()); env.addFile("package.json", "{}"); });
afterAll(() => env.cleanup());

async function findings(code: string, wrapper?: string) {
	if (wrapper !== undefined) env.addFile("sanitize.ts", wrapper);
	const { filePath } = env.addFile("preview.tsx", code);
	const query = loader.getQueryById("dangerously-set-inner-html");
	if (!query) throw new Error("HTML rule missing");
	return getSharedTreeSitterClient()!.runQueryOnFile(query, filePath, "tsx");
}

describe("HTML sanitizer provenance", () => {
	it("accepts an imported DOMPurify sanitizer", async () => {
		expect(await findings("import purifier from 'dompurify'; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;")).toHaveLength(0);
	});
	it("follows a local wrapper and rechecks it after a cached caller is reused", async () => {
		const caller = "import { sanitizeHtml } from './sanitize'; const view = <div dangerouslySetInnerHTML={{__html: sanitizeHtml(input)}} />;";
		expect(await findings(caller, "import purifier from 'dompurify'; export function sanitizeHtml(input: string) { return purifier.sanitize(input); }")).toHaveLength(0);
		expect((await findings(caller, "export function sanitizeHtml(input: string) { return input; }")).length).toBeGreaterThan(0);
	});
	it.each([
		"const DOMPurify = {sanitize: value => value}; const view = <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(input)}} />;",
		"import purifier from 'dompurify'; function render(purifier) { return <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />; }",
		"import purifier from 'dompurify'; purifier.sanitize = value => value; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
		"import purifier from 'dompurify'; const alias = purifier; alias.sanitize = value => value; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
		"import purifier from 'dompurify'; configure(purifier); const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
		"import purifier from 'dompurify'; purifier['addHook']('uponSanitizeAttribute', hook); const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
		"import { unexpected as purifier } from 'dompurify'; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
		"import purifier from 'dompurify'; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input, {ADD_TAGS: ['script']})}} />;",
		"import purifier from 'dompurify'; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input) + input}} />;",
		"const view = <div dangerouslySetInnerHTML={{__html: input}} />;",
	])("retains unsafe or unproven HTML: %s", async code => {
		expect((await findings(code)).length).toBeGreaterThan(0);
	});
});
