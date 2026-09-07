import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { removeTempDirSync } from "../clients/test-utils.js";

const repoRoot = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	"../..",
);
const cliPath = path.join(repoRoot, "dist", "mcp", "cli.js");
const livePids = new Set<number>();
let tmp = "";

function isAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

async function waitForFile(file: string, timeoutMs: number): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!fs.existsSync(file)) {
		if (Date.now() >= deadline)
			throw new Error(`Timed out waiting for ${file}`);
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

async function terminate(child: ChildProcess | undefined): Promise<void> {
	if (!child?.pid || !isAlive(child.pid)) return;
	child.kill("SIGTERM");
	await new Promise((resolve) => setTimeout(resolve, 100));
	if (isAlive(child.pid)) child.kill("SIGKILL");
}

afterEach(async () => {
	for (const pid of livePids) {
		if (isAlive(pid)) process.kill(pid, "SIGKILL");
	}
	livePids.clear();
	if (tmp) removeTempDirSync(tmp);
	tmp = "";
});

const posixIt = process.platform === "win32" ? it.skip : it;

describe("diagnostics CLI owned-child lifecycle", () => {
	posixIt(
		"emits JSON after owned cleanup, exits naturally, and leaves unrelated children alone",
		async () => {
			tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-cli-lifecycle-"));
			const unrelated = spawn(
				process.execPath,
				["-e", "setInterval(() => {}, 1000)"],
				{ detached: true, stdio: "ignore" },
			);
			if (unrelated.pid) livePids.add(unrelated.pid);
			const binDir = path.join(tmp, "bin");
			const receipt = path.join(tmp, "trivy-child.json");
			const lspReceipt = path.join(tmp, "lsp-child.json");
			fs.mkdirSync(binDir);
			fs.writeFileSync(path.join(tmp, "package.json"), '{"name":"fixture"}\n');
			fs.writeFileSync(
				path.join(tmp, "package-lock.json"),
				'{"name":"fixture","lockfileVersion":3,"packages":{}}\n',
			);
			fs.writeFileSync(
				path.join(tmp, ".pi-lens.json"),
				'{"trivy":{"enabled":true}}\n',
			);
			const fakeTrivy = path.join(binDir, "trivy");
			fs.writeFileSync(
				fakeTrivy,
				`#!${process.execPath}\n` +
					`const fs=require("node:fs");\n` +
					`if(process.argv.includes("--version")){console.log("Version: hermetic");process.exitCode=0;}else{fs.writeFileSync(process.env.PI_LENS_TEST_CHILD_RECEIPT,JSON.stringify({pid:process.pid,ppid:process.ppid,startedAt:new Date().toISOString(),argv:process.argv.slice(2)})+"\\n");setInterval(()=>{},1000);}\n`,
			);
			fs.chmodSync(fakeTrivy, 0o755);
			const fakeJsonLsp = path.join(binDir, "vscode-json-language-server");
			fs.writeFileSync(
				fakeJsonLsp,
				`#!${process.execPath}\n` +
					`const fs=require("node:fs"),{spawn}=require("node:child_process");\n` +
					`const child=spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"ignore"});\n` +
					`fs.writeFileSync(process.env.PI_LENS_TEST_LSP_RECEIPT,JSON.stringify({pid:process.pid,ppid:process.ppid,childPid:child.pid})+"\\n");\n` +
					`process.stdin.resume();setInterval(()=>{},1000);\n`,
			);
			fs.chmodSync(fakeJsonLsp, 0o755);
			const fakeOpengrep = path.join(binDir, "opengrep");
			fs.writeFileSync(
				fakeOpengrep,
				`#!${process.execPath}\n` +
					`const fs=require("node:fs");\n` +
					`if(process.argv.includes("--version")){console.log("hermetic");}else{const i=process.argv.indexOf("--json-output");fs.writeFileSync(process.argv[i+1],'{"results":[]}');}\n`,
			);
			fs.chmodSync(fakeOpengrep, 0o755);
			for (const tool of ["knip", "jscpd", "madge"]) {
				const executable = path.join(binDir, tool);
				fs.writeFileSync(
					executable,
					`#!${process.execPath}\nif(process.argv.includes("--version")){console.log("hermetic");}else{process.exitCode=1;}\n`,
				);
				fs.chmodSync(executable, 0o755);
			}

			const argv = [
				cliPath,
				"diagnostics",
				"--cwd",
				tmp,
				"--format",
				"json",
				"--max-lsp-files",
				"1",
				"--max-project-files",
				"1",
			];
			const startedAt = new Date().toISOString();
			const cli = spawn(process.execPath, argv, {
				cwd: tmp,
				env: {
					...process.env,
					PATH: [binDir, "/usr/bin", "/bin"].join(path.delimiter),
					PI_LENS_HOME: path.join(tmp, "pi-lens-home"),
					PI_LENS_LENS_DIAGNOSTICS_FULL_TIMEOUT_MS: "2000",
					PI_LENS_LSP_WARMUP_TIMEOUT_MS: "500",
					PI_LENS_TEST_CHILD_RECEIPT: receipt,
					PI_LENS_TEST_LSP_RECEIPT: lspReceipt,
				},
				stdio: ["ignore", "pipe", "pipe"],
			});
			let stdout = "";
			let stderr = "";
			let ownedPids: number[] = [];
			let ownedAliveAtOutput: number[] | undefined;
			cli.stdout?.on("data", (chunk) => {
				stdout += chunk;
				ownedAliveAtOutput = ownedPids.filter(isAlive);
			});
			cli.stderr?.on("data", (chunk) => (stderr += chunk));

			try {
				await Promise.all([
					waitForFile(receipt, 5_000),
					waitForFile(lspReceipt, 5_000),
				]);
				const child = JSON.parse(fs.readFileSync(receipt, "utf8")) as {
					pid: number;
					ppid: number;
				};
				const lsp = JSON.parse(fs.readFileSync(lspReceipt, "utf8")) as {
					pid: number;
					ppid: number;
					childPid: number;
				};
				livePids.add(child.pid);
				livePids.add(lsp.pid);
				livePids.add(lsp.childPid);
				ownedPids = [child.pid, lsp.pid, lsp.childPid];
				expect(child.ppid).toBe(cli.pid);
				expect(lsp.ppid).toBe(cli.pid);
				expect(isAlive(unrelated.pid!)).toBe(true);
				const outcome = await Promise.race([
					new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
						(resolve) =>
							cli.once("close", (code, signal) => resolve({ code, signal })),
					),
					new Promise<never>((_, reject) =>
						setTimeout(() => {
							const processRows = execFileSync("/bin/ps", [
								"-axo",
								"pid=,ppid=,pgid=,state=,command=",
							])
								.toString()
								.split("\n")
								.filter((line) => line.includes(tmp));
							reject(
								new Error(
									`CLI stayed alive after its full-scan deadline\nstdout=${stdout}\nstderr=${stderr}\nprocesses=${processRows.join("\n")}`,
								),
							);
						}, 6_000),
					),
				]);
				const payload = JSON.parse(stdout.trim()) as {
					exitCode: number;
					details: { partial?: boolean; timedOut?: boolean };
				};
				expect({
					startedAt,
					argv: [process.execPath, ...argv],
					cwd: tmp,
				}).toBeTruthy();
				expect(stderr).toBe("");
				expect(outcome).toEqual({ code: 2, signal: null });
				expect(payload.exitCode).toBe(2);
				expect(payload.details).toMatchObject({
					partial: true,
					timedOut: true,
				});
				expect(ownedAliveAtOutput).toEqual([]);
				expect(isAlive(child.pid)).toBe(false);
				expect(isAlive(lsp.pid)).toBe(false);
				expect(isAlive(lsp.childPid)).toBe(false);
				expect(isAlive(unrelated.pid!)).toBe(true);
				livePids.delete(child.pid);
				livePids.delete(lsp.pid);
				livePids.delete(lsp.childPid);
			} finally {
				await terminate(cli);
				await terminate(unrelated);
				if (unrelated.pid) livePids.delete(unrelated.pid);
			}
		},
		12_000,
	);
});
