import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KnipClient, type KnipResult } from "../../clients/knip-client.js";
import { safeSpawnAsync } from "../../clients/safe-spawn.js";
import { tokenizeShellCommand } from "../../clients/bash-file-access.js";
import { setupTestEnvironment } from "./test-utils.js";

vi.mock("../../clients/safe-spawn.js", () => ({ safeSpawnAsync: vi.fn() }));
afterEach(() => vi.resetAllMocks());

async function scan(script?: string, shell?: string, code = "import http from 'k6/http';\nimport { check } from 'k6';") {
	const env = setupTestEnvironment("knip-k6-");
	try {
		fs.writeFileSync(path.join(env.tmpDir, "package.json"), JSON.stringify({ scripts: script ? { load: script } : {} }));
		if (shell) fs.writeFileSync(path.join(env.tmpDir, "load.sh"), shell);
		fs.writeFileSync(path.join(env.tmpDir, "load.js"), code);
		vi.mocked(safeSpawnAsync).mockResolvedValue({ status: 1, stdout: JSON.stringify({ issues: [{ file: "load.js", unlisted: [{ name: "k6", line: 1 }] }] }), stderr: "" });
		return await (new KnipClient() as unknown as { runAnalyze(cwd: string): Promise<KnipResult> }).runAnalyze(env.tmpDir);
	} finally { env.cleanup(); }
}

describe("declared k6 runtime imports", () => {
	it("recognizes a direct k6 script without running it", async () => {
		expect((await scan("k6 run load.js")).unlistedDeps).toEqual([]);
		expect(safeSpawnAsync).toHaveBeenCalledTimes(1);
	});
	it("recognizes a conditional k6 invocation in the declared shell script", async () => {
		expect((await scan("bash load.sh", "echo prepare\nif ! k6 run load.js; then exit 1; fi")).unlistedDeps).toEqual([]);
	});
	it.each([undefined, "node load.js"])("retains imports with no k6 runtime declaration: %s", async script => {
		expect((await scan(script)).unlistedDeps).toHaveLength(1);
	});
	it.each(["# k6 run load.js\nnode load.js", "cat <<EOF\nk6 run load.js\nEOF", "echo 'k6 run load.js'"])("does not infer an invocation from data or comments", async shell => {
		expect((await scan("bash load.sh", shell)).unlistedDeps).toHaveLength(1);
	});
	it("retains an unknown k6 module alongside known builtins", async () => {
		expect((await scan("k6 run load.js", undefined, "import http from 'k6/http';\nimport bad from 'k6/not-a-module';")).unlistedDeps).toHaveLength(1);
	});
	it("treats newlines as command boundaries while retaining quoted newlines", () => {
		expect(tokenizeShellCommand("echo first\nk6 run load.js").map(segment => segment.tokens)).toEqual([["echo", "first"], ["k6", "run", "load.js"]]);
		expect(tokenizeShellCommand("echo 'first\nk6 run load.js'").map(segment => segment.tokens)).toEqual([["echo", "first\nk6 run load.js"]]);
	});
});
