import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KnipClient } from "../../clients/knip-client.js";
import type { KnipResult } from "../../clients/knip-client.js";
import { safeSpawnAsync } from "../../clients/safe-spawn.js";
import { setupTestEnvironment } from "./test-utils.js";

vi.mock("../../clients/safe-spawn.js", () => ({ safeSpawnAsync: vi.fn() }));

describe("Knip protocol imports in Deno projects", () => {
	afterEach(() => vi.resetAllMocks());

	async function scan(options: { boundary?: "deno" | "node" | "nested-node"; code?: string; resolver?: "fail" | "malformed" | "module-error" | "changed" } = {}) {
		const env = setupTestEnvironment("knip-deno-runtime-");
		try {
			fs.writeFileSync(path.join(env.tmpDir, "package.json"), "{}");
			const dir = path.join(env.tmpDir, "edge");
			fs.mkdirSync(dir);
			if (options.boundary !== "node") fs.writeFileSync(path.join(dir, "deno.json"), "{}");
			const sourceDir = options.boundary === "nested-node" ? path.join(dir, "node") : dir;
			fs.mkdirSync(sourceDir, { recursive: true });
			if (options.boundary === "nested-node") fs.writeFileSync(path.join(sourceDir, "package.json"), "{}");
			const file = path.join(sourceDir, "main.ts");
			fs.writeFileSync(file, options.code ?? "import { x } from 'npm:package@1';\n");
			vi.mocked(safeSpawnAsync).mockImplementation(async (command, args) => {
				if (command === "knip") return { status: 1, stdout: JSON.stringify({ issues: [{ file, unlisted: [{ name: "npm", line: 1 }] }] }), stderr: "" };
				if (options.resolver === "changed") fs.appendFileSync(file, "// changed during resolution\n");
				if (options.resolver === "fail") return { status: 1, stdout: "", stderr: "not cached" };
				if (options.resolver === "malformed") return { status: 0, stdout: "{", stderr: "" };
				return { status: 0, stdout: JSON.stringify({ roots: [args.at(-1)], modules: [{ specifier: args.at(-1), ...(options.resolver === "module-error" ? { error: "unresolved import" } : {}) }] }), stderr: "" };
			});
			const client = new KnipClient() as unknown as { runAnalyze(cwd: string): Promise<KnipResult> };
			const result = await client.runAnalyze(env.tmpDir);
			return { result, calls: vi.mocked(safeSpawnAsync).mock.calls.map(([command, args]) => ({ command, args })) };
		} finally { env.cleanup(); }
	}

	it("removes a resolved protocol finding and updates every result view", async () => {
		const { result, calls } = await scan();
		expect(result.issues).toEqual([]);
		expect(result.unlistedDeps).toEqual([]);
		expect(result.summary).toBe("Found 0 issues");
		expect(calls[1].command).toBe("deno");
		expect(calls[1].args).toEqual(expect.arrayContaining(["info", "--no-lock", "--node-modules-dir=none", "--json"]));
	});

	it.each(["node", "nested-node"] as const)("retains imports owned by a %s project", async boundary => {
		const { result, calls } = await scan({ boundary });
		expect(result.unlistedDeps).toHaveLength(1);
		expect(calls).toHaveLength(1);
	});

	it.each(["fail", "malformed", "module-error", "changed"] as const)("retains findings when validation is %s", async resolver => {
		expect((await scan({ resolver })).result.unlistedDeps).toHaveLength(1);
	});

	it.each(["import x from 'npm';", "// import x from 'npm:package@1';", "const text = 'npm:package@1';", "import x from 'npm:package@1'; import y from 'npm:other@2';"])("does not infer a runtime import from ambiguous source: %s", async code => {
		const { result, calls } = await scan({ code });
		expect(result.unlistedDeps).toHaveLength(1);
		expect(calls).toHaveLength(1);
	});
});
