import * as fs from "node:fs";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import {
	assertGrammarAvailable,
	makeRealRunnerEnv,
} from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();
beforeAll(async () => {
	await assertGrammarAvailable("tsx");
	await loader.loadQueries(process.cwd());
	env.addFile("package.json", "{}");
});
afterAll(() => env.cleanup());

async function findingsAt(file: string, code: string) {
	const { filePath } = env.addFile(file, code);
	const query = loader.getQueryById("dangerously-set-inner-html");
	if (!query) throw new Error("HTML rule missing");
	return getSharedTreeSitterClient()!.runQueryOnFile(query, filePath, "tsx");
}

async function findings(code: string, wrapper?: string) {
	if (wrapper !== undefined) env.addFile("sanitize.ts", wrapper);
	return findingsAt("preview.tsx", code);
}

describe("HTML sanitizer provenance", () => {
	it("accepts an imported DOMPurify sanitizer", async () => {
		expect(
			await findings(
				"import purifier from 'dompurify'; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
			),
		).toHaveLength(0);
	});
	it("follows a local wrapper and rechecks it after a cached caller is reused", async () => {
		const caller =
			"import { sanitizeHtml } from './sanitize'; const view = <div dangerouslySetInnerHTML={{__html: sanitizeHtml(input)}} />;";
		expect(
			await findings(
				caller,
				"import purifier from 'dompurify'; export function sanitizeHtml(input: string) { return purifier.sanitize(input); }",
			),
		).toHaveLength(0);
		expect(
			(
				await findings(
					caller,
					"export function sanitizeHtml(input: string) { return input; }",
				)
			).length,
		).toBeGreaterThan(0);
	});
	it("excludes the five reviewed TB sinks only after their complete paths are proven", async () => {
		env.addFile(
			"tsconfig.json",
			JSON.stringify({
				compilerOptions: { baseUrl: ".", paths: { "@/*": ["./src/*"] } },
			}),
		);
		env.addFile(
			"src/lib/utils/sanitize-html.ts",
			`
			import purifier from 'dompurify';
			const TAGS = ['p', 'br', 'strong'];
			const ATTRS = ['title', 'class'];
			export function sanitizeHtml(input: string) { return purifier.sanitize(input, { USE_PROFILES: { html: true }, ALLOWED_TAGS: ['p', 'img'], ALLOWED_ATTR: ['src', 'alt'] }); }
			export function sanitizeEmailPreviewHtml(input: string) { return purifier.sanitize(input, { USE_PROFILES: { html: true }, ALLOWED_TAGS: TAGS, ALLOWED_ATTR: ATTRS, ALLOW_DATA_ATTR: false, FORBID_TAGS: ['script', 'img'], FORBID_ATTR: ['src', 'onerror'] }); }
		`,
		);
		env.addFile(
			"src/pages/settings/email-templates/desktop/email-template-preview.ts",
			`
			import { sanitizeEmailPreviewHtml } from '@/lib/utils/sanitize-html';
			export function buildEmailTemplateSamplePreview(body: string) {
				const errors = validate(body);
				if (errors.length > 0) { throw new Error('invalid'); }
				return sanitizeEmailPreviewHtml(substitute(body));
			}
		`,
		);
		const cases = [
			[
				"src/pages/marketing/templates/desktop/TemplateDetailDesktop.tsx",
				"import { sanitizeHtml } from '@/lib/utils/sanitize-html'; const view = <div dangerouslySetInnerHTML={{__html: sanitizeHtml(template.content)}} />;",
			],
			[
				"src/pages/sales/estimates/desktop/SendEstimateToCustomerDialog.tsx",
				"import { useMemo as memo } from 'react'; import { sanitizeHtml } from '@/lib/utils/sanitize-html'; const previewHtml = input; const sanitizedPreviewHtml = memo(() => sanitizeHtml(previewHtml), [previewHtml]); const view = <div dangerouslySetInnerHTML={{__html: sanitizedPreviewHtml}} />;",
			],
			[
				"src/pages/settings/email-templates/desktop/EditEmailTemplateDesktop.tsx",
				"import { useMemo } from 'react'; import { sanitizeEmailPreviewHtml } from '@/lib/utils/sanitize-html'; const previewHtml = useMemo(() => sanitizeEmailPreviewHtml(substitute(body)), [body]); const view = <div dangerouslySetInnerHTML={{__html: previewHtml}} />;",
			],
			[
				"src/pages/settings/email-templates/desktop/EmailTemplateDetailDesktop.tsx",
				"import { useMemo } from 'react'; import { buildEmailTemplateSamplePreview } from './email-template-preview'; const previewHtml = useMemo(() => ready ? buildEmailTemplateSamplePreview(body) : '', [ready, body]); const view = <div dangerouslySetInnerHTML={{__html: previewHtml || '—'}} />;",
			],
			[
				"src/pages/settings/email-templates/mobile/EmailTemplateDetailMobile.tsx",
				"import { sanitizeHtml } from '@/lib/utils/sanitize-html'; const view = <div dangerouslySetInnerHTML={{__html: body ? sanitizeHtml(body) : '—'}} />;",
			],
		] as const;
		for (const [file, code] of cases)
			expect(await findingsAt(file, code), file).toHaveLength(0);
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
	])("retains unsafe or unproven HTML: %s", async (code) => {
		expect((await findings(code)).length).toBeGreaterThan(0);
	});
	it.each([
		"import purifier from 'dompurify'; purifier.addHook('uponSanitizeAttribute', hook); const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
		"import purifier from 'dompurify'; purifier.setConfig(config); const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
		"import purifier from 'dompurify'; const escaped = purifier.sanitize; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;",
		"import purifier from 'dompurify'; const options = getOptions(); const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input, options)}} />;",
		"import purifier from 'dompurify'; const tags = ['p']; tags.push('script'); const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input, {ALLOWED_TAGS: tags})}} />;",
		"const sanitizeHtml: (value: string) => string = value => value; const view = <div dangerouslySetInnerHTML={{__html: sanitizeHtml(input)}} />;",
		"import { useMemo } from 'not-react'; import purifier from 'dompurify'; const html = useMemo(() => purifier.sanitize(input), []); const view = <div dangerouslySetInnerHTML={{__html: html}} />;",
		"import purifier from 'dompurify'; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}}",
		"const view = <div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}} />;",
		"const view = <div dangerouslySetInnerHTML={{__html: `<img src=x onerror=alert(1)>`}} />;",
		"import purifier from 'dompurify'; const tags = ['p']; mutate({tags}); const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input, {ALLOWED_TAGS: tags})}} />;",
		"import purifier from 'dompurify'; class Set { constructor(tags) { tags.push('script'); } } const tags = ['p']; new Set(tags); const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input, {ALLOWED_TAGS: tags})}} />;",
		"import purifier from 'dompurify'; const view = <div dangerouslySetInnerHTML={{__html: flag ? purifier.sanitize(input) : '<img src=x onerror=alert(1)>'}} />;",
	])(
		"retains mutation, escape, dynamic configuration, names, uncertain imports, and malformed syntax: %s",
		async (code) => {
			expect((await findings(code)).length).toBeGreaterThan(0);
		},
	);

	it("fails closed for symlinked and oversized sanitizer dependencies", async () => {
		const safe = "import purifier from 'dompurify'; export function clean(value: string) { return purifier.sanitize(value); }";
		const real = env.addFile("real-sanitizer.ts", safe).filePath;
		fs.symlinkSync(real, path.join(env.cwd, "linked-sanitizer.ts"));
		expect((await findings("import { clean } from './linked-sanitizer'; const view = <div dangerouslySetInnerHTML={{__html: clean(input)}} />;")).length).toBeGreaterThan(0);
		env.addFile("oversized-sanitizer.ts", `${" ".repeat(256_001)}${safe}`);
		expect((await findings("import { clean } from './oversized-sanitizer'; const view = <div dangerouslySetInnerHTML={{__html: clean(input)}} />;")).length).toBeGreaterThan(0);
	});

	it("retains cyclic and traversal-exhausted provenance", async () => {
		env.addFile(
			"a.ts",
			"import { b } from './b'; export function a(value: string) { return b(value); }",
		);
		env.addFile(
			"b.ts",
			"import { a } from './a'; export function b(value: string) { return a(value); }",
		);
		expect(
			(
				await findings(
					"import { a } from './a'; const view = <div dangerouslySetInnerHTML={{__html: a(input)}} />;",
				)
			).length,
		).toBeGreaterThan(0);
		const declarations = `const filler = [${Array.from({ length: 50_001 }, () => "0").join(",")}];`;
		expect(
			(
				await findings(
					`${declarations}\nimport purifier from 'dompurify'; const view = <div dangerouslySetInnerHTML={{__html: purifier.sanitize(input)}} />;`,
				)
			).length,
		).toBeGreaterThan(0);
	});
});
