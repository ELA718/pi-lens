import { spawn, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { safeSpawnAsync } from "../../clients/safe-spawn.js";
import { removeTempDirSync } from "./test-utils.js";

const describePosix = process.platform === "win32" ? describe.skip : describe;
const processes = new Set<ChildProcess>();
const ownedPids = new Set<number>();
const tempDirs = new Set<string>();

function isAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

async function waitFor<T>(
	readValue: () => T | undefined,
	timeoutMs = 3_000,
): Promise<T> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const value = readValue();
		if (value !== undefined) return value;
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`Timed out after ${timeoutMs}ms`);
}

function makeFixture(): { dir: string; wrapper: string; receipt: string } {
	const dir = fs.mkdtempSync(
		path.join(os.tmpdir(), "pi-lens-safe-spawn-tree-"),
	);
	tempDirs.add(dir);
	const wrapper = path.join(dir, "wrapper.mjs");
	const descendant = path.join(dir, "descendant.mjs");
	const receipt = path.join(dir, "receipt.json");
	fs.writeFileSync(
		descendant,
		[
			'import { writeFileSync } from "node:fs";',
			'process.on("SIGTERM", () => {});',
			"writeFileSync(process.argv[2], JSON.stringify({ wrapperPid: process.ppid, descendantPid: process.pid, readyAt: new Date().toISOString() }));",
			"setInterval(() => {}, 1000);",
		].join("\n"),
	);
	fs.writeFileSync(
		wrapper,
		[
			'import { spawn } from "node:child_process";',
			'spawn(process.execPath, [process.argv[2], process.argv[3]], { stdio: "ignore" });',
			'process.on("SIGTERM", () => process.exit(0));',
			"setInterval(() => {}, 1000);",
		].join("\n"),
	);
	return { dir, wrapper, receipt };
}

function readReceipt(
	receipt: string,
): { wrapperPid: number; descendantPid: number; readyAt: string } | undefined {
	try {
		const pids = JSON.parse(fs.readFileSync(receipt, "utf8")) as {
			wrapperPid: number;
			descendantPid: number;
			readyAt: string;
		};
		ownedPids.add(pids.wrapperPid);
		ownedPids.add(pids.descendantPid);
		return pids;
	} catch {
		return undefined;
	}
}

async function expectTreeStopped(receipt: string): Promise<void> {
	const pids = readReceipt(receipt);
	expect(pids).toBeDefined();
	await waitFor(() =>
		pids && !isAlive(pids.wrapperPid) && !isAlive(pids.descendantPid)
			? true
			: undefined,
	);
}

afterEach(() => {
	for (const pid of ownedPids) {
		if (isAlive(pid)) process.kill(pid, "SIGKILL");
	}
	ownedPids.clear();
	for (const child of processes) {
		if (child.pid && isAlive(child.pid)) child.kill("SIGKILL");
	}
	processes.clear();
	for (const dir of tempDirs) removeTempDirSync(dir);
	tempDirs.clear();
});

describePosix("safeSpawnAsync POSIX process-group ownership", () => {
	it("stops its wrapper and descendant on abort without stopping an unrelated process", async () => {
		const { wrapper, receipt } = makeFixture();
		const unrelated = spawn(
			process.execPath,
			["-e", "setInterval(() => {}, 1000)"],
			{
				stdio: "ignore",
			},
		);
		processes.add(unrelated);
		await waitFor(() =>
			unrelated.pid && isAlive(unrelated.pid) ? unrelated.pid : undefined,
		);

		const controller = new AbortController();
		const resultPromise = safeSpawnAsync(
			process.execPath,
			[wrapper, path.join(path.dirname(wrapper), "descendant.mjs"), receipt],
			{
				signal: controller.signal,
				timeout: 5_000,
			},
		);
		const ready = await waitFor(() => readReceipt(receipt), 1_000);
		expect(ready.readyAt).toBeTruthy();
		controller.abort();

		await expect(resultPromise).resolves.toMatchObject({ failure: "aborted" });
		expect(isAlive(ready.wrapperPid)).toBe(false);
		expect(isAlive(ready.descendantPid)).toBe(true);
		await expectTreeStopped(receipt);
		expect(unrelated.pid && isAlive(unrelated.pid)).toBe(true);
	});

	it("stops its wrapper and descendant on timeout", async () => {
		const { wrapper, receipt } = makeFixture();
		const resultPromise = safeSpawnAsync(
			process.execPath,
			[wrapper, path.join(path.dirname(wrapper), "descendant.mjs"), receipt],
			{ timeout: 1_500 },
		);
		const ready = await waitFor(() => readReceipt(receipt), 1_000);
		expect(ready.readyAt).toBeTruthy();

		await expect(resultPromise).resolves.toMatchObject({ failure: "timeout" });
		expect(isAlive(ready.wrapperPid)).toBe(false);
		expect(isAlive(ready.descendantPid)).toBe(true);
		await expectTreeStopped(receipt);
	});

	it("does not spawn when the signal is already aborted", async () => {
		const dir = fs.mkdtempSync(
			path.join(os.tmpdir(), "pi-lens-safe-spawn-aborted-"),
		);
		tempDirs.add(dir);
		const marker = path.join(dir, "spawned");
		const controller = new AbortController();
		controller.abort();

		const result = await safeSpawnAsync(
			process.execPath,
			[
				"-e",
				'require("node:fs").writeFileSync(process.argv[1], "yes")',
				marker,
			],
			{ signal: controller.signal },
		);

		expect(result.failure).toBe("aborted");
		expect(fs.existsSync(marker)).toBe(false);
	});
});
