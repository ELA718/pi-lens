import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the launch primitive and the latency logger so we can drive the
// candidate fallback chain and inspect what gets logged.
const { launchLSP } = vi.hoisted(() => ({ launchLSP: vi.fn() }));
const { logLatency } = vi.hoisted(() => ({ logLatency: vi.fn() }));
vi.mock("../../../clients/lsp/launch.js", () => ({ launchLSP }));
vi.mock("../../../clients/latency-logger.js", () => ({ logLatency }));
const { ensureTool } = vi.hoisted(() => ({ ensureTool: vi.fn(async () => null) }));
vi.mock("../../../clients/installer/index.js", () => ({
	ensureTool,
	getToolEnvironment: () => ({}),
}));

import { resolveAndLaunch } from "../../../clients/lsp/server.ts";
import { SpawnFailureError } from "../../../clients/safe-spawn.js";

const fakeProc = { stdout: {}, stderr: {} } as never;
const toolNotFound = (message: string) =>
	Object.assign(new Error(message), { kind: "tool-not-found" as const });
const failedPhases = () =>
	logLatency.mock.calls.filter(
		(c) => c[0]?.phase === "lsp_launch_candidate_failed",
	);
const unavailablePhases = () =>
	logLatency.mock.calls.filter(
		(c) => c[0]?.phase === "lsp_launch_candidate_unavailable",
	);

// #(bash-noise): a candidate that fails while a LATER candidate succeeds is just
// fallback — it must NOT be logged as a failure (that flooded the logs and read
// as an lsp-availability smell). Failures are surfaced only when ALL candidates fail.
describe("resolveAndLaunch — fallback failures are deferred", () => {
	beforeEach(() => {
		launchLSP.mockReset();
		logLatency.mockReset();
		ensureTool.mockReset();
		ensureTool.mockResolvedValue(null);
	});

	it("skips an absent explicit candidate before launching the next one", async () => {
		const missing = "/definitely/missing/node_modules/.bin/test-lsp";
		launchLSP.mockResolvedValue(fakeProc);

		const result = await resolveAndLaunch(
			{ candidates: [missing, process.execPath], args: [], cwd: "/tmp" },
			false,
		);

		expect(result?.source).toBe("direct");
		expect(launchLSP).toHaveBeenCalledTimes(1);
		expect(launchLSP).toHaveBeenCalledWith(process.execPath, [], {
			cwd: "/tmp",
			env: undefined,
		});
		expect(unavailablePhases()).toHaveLength(1);
	});

	it("skips an absent bare candidate without a spawn attempt", async () => {
		const result = await resolveAndLaunch(
			{ candidates: ["missing-test-lsp"], args: [], cwd: "/tmp" },
			false,
		);

		expect(result).toBeUndefined();
		expect(launchLSP).not.toHaveBeenCalled();
		expect(unavailablePhases()).toHaveLength(1);
	});

	it("does NOT log candidate-failed when a later candidate succeeds", async () => {
		launchLSP
			.mockRejectedValueOnce(new Error("npm .cmd shim failed")) // idx 0
			.mockRejectedValueOnce(new Error("binary not found")) // idx 1
			.mockResolvedValueOnce(fakeProc); // idx 2 succeeds

		const result = await resolveAndLaunch(
			{ candidates: ["x.cmd", "x.exe", "x"], args: [], cwd: "/tmp/p" },
			false,
		);

		expect(result?.source).toBe("direct");
		expect(failedPhases()).toHaveLength(0); // the two fallbacks are NOT logged as failures
	});

	it("logs every candidate failure when ALL candidates fail", async () => {
		launchLSP
			.mockRejectedValueOnce(toolNotFound("fail a"))
			.mockRejectedValueOnce(toolNotFound("fail b"));

		const result = await resolveAndLaunch(
			{ candidates: ["a", "b"], args: [], cwd: "/tmp/p" }, // no managedToolId
			false,
		);

		expect(result).toBeUndefined();
		expect(failedPhases()).toHaveLength(2);
	});

	it("does not install when a present tool fails because cwd is unresolvable", async () => {
		const cause = Object.assign(new Error("spawn node ENOENT"), { code: "ENOENT" });
		launchLSP.mockRejectedValue(
			new SpawnFailureError("cwd-unresolvable", "working directory missing", cause),
		);

		await expect(
			resolveAndLaunch({
				candidates: [process.execPath],
				args: ["--version"],
				cwd: "/definitely/missing/pi-lens-cwd",
				managedToolId: "typescript-language-server",
			}, true),
		).rejects.toMatchObject({ kind: "cwd-unresolvable" });

		expect(ensureTool).not.toHaveBeenCalled();
	});

	it("launches present relative symlinks with the selected command and root", async () => {
		const root = await mkdtemp(path.join(os.tmpdir(), "pi-lens-lsp-link-"));
		try {
			await symlink(process.execPath, path.join(root, "test-lsp"));
			launchLSP.mockResolvedValue(fakeProc);

			await resolveAndLaunch(
				{ candidates: ["./test-lsp"], args: [], cwd: root },
				false,
			);

			expect(launchLSP).toHaveBeenCalledWith("./test-lsp", [], {
				cwd: root,
				env: undefined,
			});
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("resolves relative PATH entries from the selected command root", async () => {
		const root = await mkdtemp(path.join(os.tmpdir(), "pi-lens-lsp-path-"));
		const bin = path.join(root, "bin");
		const suffix = process.platform === "win32" ? ".CMD" : "";
		const env = {
			PATH: "./bin",
			...(process.platform === "win32" ? { PATHEXT: ".CMD" } : {}),
		};
		try {
			await mkdir(bin);
			await writeFile(path.join(bin, `test-lsp${suffix}`), "");
			launchLSP.mockResolvedValue(fakeProc);

			await resolveAndLaunch(
				{ candidates: ["test-lsp"], args: [], cwd: root, env },
				false,
			);

			expect(launchLSP).toHaveBeenCalledWith("test-lsp", [], { cwd: root, env });
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it.runIf(process.platform === "win32")(
		"preserves explicit executable suffixes during PATH lookup",
		async () => {
			const root = await mkdtemp(path.join(os.tmpdir(), "pi-lens-lsp-pathext-"));
			const bin = path.join(root, "bin");
			const env = { PATH: "./bin", PATHEXT: ".EXE" };
			try {
				await mkdir(bin);
				await writeFile(path.join(bin, "test-lsp.exe"), "");
				launchLSP.mockResolvedValue(fakeProc);

				await resolveAndLaunch(
					{ candidates: ["test-lsp.exe"], args: [], cwd: root, env },
					false,
				);

				expect(launchLSP).toHaveBeenCalledWith("test-lsp.exe", [], {
					cwd: root,
					env,
				});
			} finally {
				await rm(root, { recursive: true, force: true });
			}
		},
	);

	it("resolves inherited relative PATH entries from the selected command root", async () => {
		const root = await mkdtemp(path.join(os.tmpdir(), "pi-lens-lsp-inherited-path-"));
		const bin = path.join(root, "bin");
		const suffix = process.platform === "win32" ? ".CMD" : "";
		const savedPath = process.env.PATH;
		const savedPathExt = process.env.PATHEXT;
		try {
			await mkdir(bin);
			await writeFile(path.join(bin, `test-lsp${suffix}`), "");
			process.env.PATH = "./bin";
			if (process.platform === "win32") process.env.PATHEXT = ".CMD";
			launchLSP.mockResolvedValue(fakeProc);

			await resolveAndLaunch(
				{ candidates: ["test-lsp"], args: [], cwd: root },
				false,
			);

			expect(launchLSP).toHaveBeenCalledWith("test-lsp", [], {
				cwd: root,
				env: undefined,
			});
		} finally {
			if (savedPath === undefined) delete process.env.PATH;
			else process.env.PATH = savedPath;
			if (savedPathExt === undefined) delete process.env.PATHEXT;
			else process.env.PATHEXT = savedPathExt;
			await rm(root, { recursive: true, force: true });
		}
	});

	it.skipIf(process.platform === "win32")(
		"skips dangling symlinks as unavailable",
		async () => {
			const root = await mkdtemp(path.join(os.tmpdir(), "pi-lens-lsp-dangle-"));
			const dangling = path.join(root, "test-lsp");
			try {
				await symlink(path.join(root, "missing-target"), dangling);

				const result = await resolveAndLaunch(
					{ candidates: [dangling], args: [], cwd: root },
					false,
				);

				expect(result).toBeUndefined();
				expect(launchLSP).not.toHaveBeenCalled();
				expect(unavailablePhases()).toHaveLength(1);
			} finally {
				await rm(root, { recursive: true, force: true });
			}
		},
	);

	it("keeps typed launch failures for present malformed candidates", async () => {
		const root = await mkdtemp(path.join(os.tmpdir(), "pi-lens-lsp-bad-"));
		const malformed = path.join(root, "test-lsp");
		try {
			await writeFile(malformed, "not executable\n");
			const cause = Object.assign(new Error("spawn EACCES"), { code: "EACCES" });
			launchLSP.mockRejectedValue(
				new SpawnFailureError("permission-denied", "permission denied", cause),
			);

			await expect(
				resolveAndLaunch(
					{ candidates: [malformed], args: [], cwd: root },
					false,
				),
			).rejects.toMatchObject({ kind: "permission-denied" });
			expect(launchLSP).toHaveBeenCalledTimes(1);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("passes present directories to launch for typed failure classification", async () => {
		const root = await mkdtemp(path.join(os.tmpdir(), "pi-lens-lsp-dir-"));
		const candidate = path.join(root, "test-lsp");
		try {
			await mkdir(candidate);
			const cause = Object.assign(new Error("spawn EACCES"), { code: "EACCES" });
			launchLSP.mockRejectedValue(
				new SpawnFailureError("permission-denied", "permission denied", cause),
			);

			await expect(
				resolveAndLaunch(
					{ candidates: [candidate], args: [], cwd: root },
					false,
				),
			).rejects.toMatchObject({ kind: "permission-denied" });
			expect(launchLSP).toHaveBeenCalledTimes(1);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it.skipIf(process.platform === "win32")(
		"passes inaccessible parent traversal to launch for typed classification",
		async () => {
			const root = await mkdtemp(path.join(os.tmpdir(), "pi-lens-lsp-eacces-"));
			const parent = path.join(root, "locked");
			const candidate = path.join(parent, "test-lsp");
			try {
				await mkdir(parent);
				await writeFile(candidate, "");
				await chmod(parent, 0o000);
				const cause = Object.assign(new Error("spawn EACCES"), { code: "EACCES" });
				launchLSP.mockRejectedValue(
					new SpawnFailureError("permission-denied", "permission denied", cause),
				);

				await expect(
					resolveAndLaunch(
						{ candidates: [candidate], args: [], cwd: root },
						false,
					),
				).rejects.toMatchObject({ kind: "permission-denied" });
				expect(launchLSP).toHaveBeenCalledTimes(1);
			} finally {
				await chmod(parent, 0o700).catch(() => {});
				await rm(root, { recursive: true, force: true });
			}
		},
	);

	it("keeps spawn-time failures after a successful availability check", async () => {
		launchLSP.mockRejectedValue(toolNotFound("removed before spawn"));

		const result = await resolveAndLaunch(
			{ candidates: [process.execPath], args: [], cwd: "/tmp" },
			false,
		);

		expect(result).toBeUndefined();
		expect(launchLSP).toHaveBeenCalledTimes(1);
	});
});
