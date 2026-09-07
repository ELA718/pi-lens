import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BootstrapClients } from "../../../clients/bootstrap.js";
import { snapshotAdvisoryProvenance } from "../../../clients/advisory-provenance.js";
import { fetchFreshProjectDiagnostics } from "../../../clients/project-diagnostics/fresh-fetch.js";
import { RuntimeCoordinator } from "../../../clients/runtime-coordinator.js";
import { SecurityScanClient } from "../../../clients/security-scan-client.js";
import { removeTempDirSync } from "../test-utils.js";

// fetchFreshProjectDiagnostics calls each client through the plain
// `BootstrapClients` interface, so a hand-rolled stub (not a real client
// instance) is enough to exercise the orchestration — only the module-level
// static gates (GitleaksClient.hasGitRepo — #608's mode=full smart-default,
// GovulncheckClient.hasGoModule, TrivyClient.shouldScan) run for real, against
// a real tmp-dir fixture.

class DedupeProbe extends SecurityScanClient<string> {
	constructor() {
		super("probe");
	}

	protected doEnsureAvailable(): Promise<boolean> {
		return Promise.resolve(true);
	}

	run(key: string, start: () => Promise<string>): Promise<string> {
		return this.dedupeScan(key, start);
	}
}

let tmp: string;

beforeEach(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-fresh-fetch-"));
});

afterEach(() => {
	removeTempDirSync(tmp);
});

function makeCacheManager() {
	return {
		writeCache: vi.fn(),
		readCache: vi.fn(),
	} as unknown as import("../../../clients/cache-manager.js").CacheManager & {
		writeCache: ReturnType<typeof vi.fn>;
	};
}

function makeClients(
	overrides: Partial<{
		knipIssues: unknown[];
		knipResult: unknown;
		jscpdAvailable: boolean;
		jscpdResult: unknown;
		madgeAvailable: boolean;
		madgeResult: unknown;
	}> = {},
): BootstrapClients {
	return {
		knipClient: {
			analyze: vi.fn().mockResolvedValue(
				overrides.knipResult ?? {
					success: true,
					issues: overrides.knipIssues ?? [],
					unusedExports: [],
					unusedFiles: [],
					unusedDeps: [],
					unlistedDeps: [],
					summary: "ok",
				},
			),
		},
		jscpdClient: {
			ensureAvailable: vi
				.fn()
				.mockResolvedValue(overrides.jscpdAvailable ?? false),
			scan: vi.fn().mockResolvedValue(
				overrides.jscpdResult ?? {
					success: true,
					duplicatedLines: 0,
					totalLines: 0,
					percentage: 0,
					clones: [],
				},
			),
		},
		depChecker: {
			ensureAvailable: vi
				.fn()
				.mockResolvedValue(overrides.madgeAvailable ?? false),
			scanProject: vi
				.fn()
				.mockResolvedValue(overrides.madgeResult ?? { circular: [], count: 0 }),
		},
		govulncheckClient: {
			ensureAvailable: vi.fn().mockResolvedValue(true),
			analyze: vi.fn().mockResolvedValue({
				success: true,
				findings: [],
				scannedAt: "now",
			}),
		},
		gitleaksClient: {
			ensureAvailable: vi.fn().mockResolvedValue(true),
			scan: vi.fn().mockResolvedValue({
				success: true,
				findings: [],
				scannedAt: "now",
			}),
		},
		trivyClient: {
			ensureAvailable: vi.fn().mockResolvedValue(true),
			scan: vi.fn().mockResolvedValue({
				success: true,
				findings: [],
				scannedAt: "now",
			}),
		},
		// opengrep is structurally always-on (no static project gate) — the stub
		// defaults to available + a clean scan; individual tests override `scan`.
		opengrepClient: {
			ensureAvailable: vi.fn().mockResolvedValue(true),
			scan: vi.fn().mockResolvedValue({
				success: true,
				findings: [],
				scannedAt: "now",
			}),
		},
		deadCodeClients: [],
		// The remaining BootstrapClients fields are unused by fetchFreshProjectDiagnostics.
	} as unknown as BootstrapClients;
}

describe("fetchFreshProjectDiagnostics (#585)", () => {
	it("runs knip fresh and writes its result to cache", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients({
			knipIssues: [
				{ type: "file", name: "dead.ts", file: "dead.ts" },
			],
		});

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.knipClient.analyze).toHaveBeenCalledTimes(1);
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"knip",
			expect.objectContaining({ success: true }),
			path.resolve(tmp),
			expect.objectContaining({ scanDurationMs: expect.any(Number) }),
		);
		expect(result.runners).toContain("knip");
		expect(result.diagnostics.length).toBeGreaterThan(0);
		expect(result.timings.knip).toBeGreaterThanOrEqual(0);
	});

	it("reports a failed knip run and does not cache it (#925)", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients({
			knipResult: {
				success: false,
				issues: [],
				summary: "knip process failed",
			},
		});

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(result.failed).toEqual([
			{ id: "knip", summary: "knip process failed" },
		]);
		expect(result.runners).not.toContain("knip");
		expect(cacheManager.writeCache).not.toHaveBeenCalledWith(
			"knip",
			expect.anything(),
			expect.anything(),
			expect.anything(),
		);
	});

	// #747: cwd at — or above — $HOME must never spawn a single analyzer; the
	// observed failure was a jscpd walk of an entire WSL home (44 GB RSS, OOM
	// kill of the whole instance).
	it("refuses to run anything when cwd IS the home directory (#747)", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients({ jscpdAvailable: true, madgeAvailable: true });

		const result = await fetchFreshProjectDiagnostics(
			cacheManager,
			tmp,
			clients,
			undefined,
			{ homeDir: tmp },
		);

		expect(result.unsafeRoot).toBe(true);
		expect(result.diagnostics).toEqual([]);
		expect(result.runners).toEqual([]);
		expect(result.cold).toEqual([
			"knip",
			"jscpd",
			"madge",
			"gitleaks",
			"govulncheck",
			"opengrep",
			"trivy",
			"dead-code",
			"test-runner",
		]);
		expect(clients.knipClient.analyze).not.toHaveBeenCalled();
		expect(clients.jscpdClient.ensureAvailable).not.toHaveBeenCalled();
		expect(clients.jscpdClient.scan).not.toHaveBeenCalled();
		expect(clients.depChecker.scanProject).not.toHaveBeenCalled();
		expect(clients.gitleaksClient.scan).not.toHaveBeenCalled();
		expect(cacheManager.writeCache).not.toHaveBeenCalled();
	});

	it("refuses to run anything when cwd is an ANCESTOR of the home directory (#747)", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients({ jscpdAvailable: true });
		const fakeHome = path.join(tmp, "home", "user");
		fs.mkdirSync(fakeHome, { recursive: true });

		const result = await fetchFreshProjectDiagnostics(
			cacheManager,
			tmp,
			clients,
			undefined,
			{ homeDir: fakeHome },
		);

		expect(result.unsafeRoot).toBe(true);
		expect(clients.knipClient.analyze).not.toHaveBeenCalled();
		expect(cacheManager.writeCache).not.toHaveBeenCalled();
	});

	it("runs normally for a project directory UNDER the home directory (#747)", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients();
		const fakeHome = path.join(tmp, "home", "user");
		const project = path.join(fakeHome, "code", "app");
		fs.mkdirSync(project, { recursive: true });

		const result = await fetchFreshProjectDiagnostics(
			cacheManager,
			project,
			clients,
			undefined,
			{ homeDir: fakeHome },
		);

		expect(result.unsafeRoot).toBeUndefined();
		expect(clients.knipClient.analyze).toHaveBeenCalledTimes(1);
	});

	it("reports jscpd cold when the tool isn't available, without writing cache", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients({ jscpdAvailable: false });

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.jscpdClient.scan).not.toHaveBeenCalled();
		expect(result.cold).toContain("jscpd");
		expect(cacheManager.writeCache).not.toHaveBeenCalledWith(
			expect.stringMatching(/^jscpd/),
			expect.anything(),
			expect.anything(),
			expect.anything(),
		);
	});

	it("writes to the jscpd-ts cache key when a tsconfig.json is present", async () => {
		fs.writeFileSync(path.join(tmp, "tsconfig.json"), "{}");
		const cacheManager = makeCacheManager();
		const clients = makeClients({
			jscpdAvailable: true,
			jscpdResult: {
				success: true,
				duplicatedLines: 4,
				totalLines: 10,
				percentage: 40,
				clones: [
					{
						fileA: "a.ts",
						startA: 1,
						fileB: "b.ts",
						startB: 2,
						lines: 4,
						tokens: 10,
					},
				],
			},
		});

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.jscpdClient.scan).toHaveBeenCalledWith(
			path.resolve(tmp),
			undefined,
			undefined,
			true,
			{ signal: undefined },
		);
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"jscpd-ts",
			expect.anything(),
			path.resolve(tmp),
			expect.anything(),
		);
		expect(result.runners).toContain("jscpd");
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"jscpd-ts",
			expect.objectContaining({ duplicatedLines: 4, percentage: 40 }),
			path.resolve(tmp),
			expect.anything(),
		);
	});

	it("persists the present madge result for downstream diagnostics", async () => {
		const cacheManager = makeCacheManager();
		const madgeResult = {
			circular: [[path.join(tmp, "src", "a.ts"), path.join(tmp, "src", "b.ts")]],
			count: 1,
		};
		const clients = makeClients({ madgeAvailable: true, madgeResult });

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.depChecker.scanProject).toHaveBeenCalledWith(
			path.resolve(tmp),
			undefined,
		);
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"madge",
			madgeResult,
			path.resolve(tmp),
			expect.anything(),
		);
		expect(result.cold).not.toContain("madge");
	});

	it("gates govulncheck/trivy on their own static signals, without cache reads", async () => {
		// No go.mod, no .pi-lens.json trivy.enabled — both should report cold
		// and never call analyze()/scan().
		const cacheManager = makeCacheManager();
		const clients = makeClients();

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.govulncheckClient.analyze).not.toHaveBeenCalled();
		expect(clients.trivyClient.scan).not.toHaveBeenCalled();
		expect(result.cold).toEqual(
			expect.arrayContaining(["govulncheck", "trivy"]),
		);
	});

	it("gates gitleaks on hasGitRepo (#608): cold when tmp isn't a git repo at all", async () => {
		// tmp has no .git and no explicit gitleaks marker either — cold either way.
		const cacheManager = makeCacheManager();
		const clients = makeClients();

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.gitleaksClient.scan).not.toHaveBeenCalled();
		expect(result.cold).toContain("gitleaks");
	});

	it("runs gitleaks fresh on a bare git repo with NO explicit gitleaks config (#608 smart-default)", async () => {
		// The whole point of #608: mode=full uses the looser gate (any tracked
		// git repo), not #130's strict opt-in-config gate — no .gitleaks* marker
		// here, only .git, and gitleaks should still run.
		fs.mkdirSync(path.join(tmp, ".git"));
		const cacheManager = makeCacheManager();
		const clients = makeClients();
		(clients.gitleaksClient.scan as ReturnType<typeof vi.fn>).mockResolvedValue({
			success: true,
			findings: [{ ruleId: "aws-key", file: "a.ts", startLine: 1 }],
			scannedAt: "now",
		});

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.gitleaksClient.scan).toHaveBeenCalledTimes(1);
		expect(clients.gitleaksClient.scan).toHaveBeenCalledWith(
			path.resolve(tmp),
			{ requireSignal: false, signal: undefined },
		);
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"gitleaks",
			expect.objectContaining({ success: true }),
			path.resolve(tmp),
			expect.anything(),
		);
		expect(result.runners).toContain("gitleaks");
	});

	it("still runs gitleaks fresh when both .git and an explicit gitleaks marker are present", async () => {
		fs.mkdirSync(path.join(tmp, ".git"));
		fs.writeFileSync(path.join(tmp, ".gitleaksignore"), "");
		const cacheManager = makeCacheManager();
		const clients = makeClients();
		(clients.gitleaksClient.scan as ReturnType<typeof vi.fn>).mockResolvedValue({
			success: true,
			findings: [],
			scannedAt: "now",
		});

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.gitleaksClient.scan).toHaveBeenCalledTimes(1);
		// A clean scan (no findings) doesn't land in `runners` by design (that
		// list means "contributed a finding"), but `timings` proves it ran.
		expect(result.timings.gitleaks).toBeDefined();
	});

	it("runs govulncheck fresh only when go.mod is present", async () => {
		fs.writeFileSync(path.join(tmp, "go.mod"), "module demo\n\ngo 1.21\n");
		const cacheManager = makeCacheManager();
		const clients = makeClients();

		await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.govulncheckClient.analyze).toHaveBeenCalledTimes(1);
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"govulncheck",
			expect.anything(),
			path.resolve(tmp),
			expect.anything(),
		);
	});

	it("runs trivy fresh only when opted-in AND a dependency manifest exists", async () => {
		fs.writeFileSync(
			path.join(tmp, ".pi-lens.json"),
			JSON.stringify({ trivy: { enabled: true } }),
		);
		fs.writeFileSync(path.join(tmp, "package.json"), "{}");
		const cacheManager = makeCacheManager();
		const clients = makeClients();

		await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.trivyClient.scan).toHaveBeenCalledTimes(1);
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"trivy",
			expect.anything(),
			path.resolve(tmp),
			expect.anything(),
		);
	});

	// #585 regression: opengrep was registered in the cache-only extractor
	// registry (extractors.ts) but MISSING from this fresh-fetch path, so its
	// session-start scan cached findings that `lens_diagnostics mode=full` never
	// read back — a scan-and-orphan honesty gap (#533). It must surface here the
	// same way gitleaks/trivy do: fresh scan → cache write → adapted diagnostics.
	it("surfaces opengrep findings (ERROR→blocking, CWE-tagged) and caches them (#585)", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients();
		(clients.opengrepClient.scan as ReturnType<typeof vi.fn>).mockResolvedValue({
			success: true,
			scannedAt: "now",
			findings: [
				{
					checkId: "python.lang.security.audit.subprocess-shell-true",
					path: "src/run.py",
					startLine: 7,
					startCol: 3,
					endLine: 7,
					endCol: 20,
					message: "shell=True is dangerous",
					severity: "ERROR",
					cwe: ["CWE-78: OS Command Injection"],
				},
			],
		});

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		// Structurally always-on: no static project gate, only an availability
		// probe — the scan runs even on a bare tmp dir with no manifest/marker.
		expect(clients.opengrepClient.scan).toHaveBeenCalledTimes(1);
		expect(clients.opengrepClient.scan).toHaveBeenCalledWith(
			path.resolve(tmp),
			undefined,
		);
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"opengrep",
			expect.objectContaining({ success: true }),
			path.resolve(tmp),
			expect.objectContaining({ scanDurationMs: expect.any(Number) }),
		);
		expect(result.runners).toContain("opengrep");
		const diag = result.diagnostics.find((d) => d.runner === "opengrep");
		expect(diag).toMatchObject({
			filePath: path.join(path.resolve(tmp), "src/run.py"),
			line: 7,
			column: 3,
			severity: "error",
			semantic: "blocking",
			tool: "opengrep",
			rule: "opengrep:python.lang.security.audit.subprocess-shell-true",
			message: "shell=True is dangerous (CWE-78: OS Command Injection)",
		});
	});

	it("reports opengrep cold (not clean) when the tool isn't available (#585)", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients();
		(
			clients.opengrepClient.ensureAvailable as ReturnType<typeof vi.fn>
		).mockResolvedValue(false);

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(clients.opengrepClient.scan).not.toHaveBeenCalled();
		expect(result.cold).toContain("opengrep");
		expect(result.runners).not.toContain("opengrep");
	});

	// #1004 regression: test-runner was omitted from ANALYZER_IDS (the same
	// #585-class gap opengrep had) — the turn_end test fire cached findings
	// under "test-runner-findings" but nothing in fetchFreshProjectDiagnostics
	// read them back, so mode=full silently dropped test failures for
	// unedited/project-wide calls. This must FAIL on pre-fix code (ANALYZER_IDS
	// missing "test-runner") and pass once the cache-read task is wired.
	it("surfaces cached test-runner findings via mode=full without re-running the suite (#1004)", async () => {
		const cacheManager = makeCacheManager();
		fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
		fs.writeFileSync(path.join(tmp, "src/foo.test.ts"), "test('foo', () => {});\n");
		const testResult = {
			file: path.join(path.resolve(tmp), "src/foo.test.ts"),
			runner: "vitest",
			passed: 1,
			failed: 1,
			duration: 42,
			failures: [
				{
					name: "foo works",
					message: "expected true to be false",
					location: "src/foo.test.ts:17",
				},
			],
		};
		const provenance = snapshotAdvisoryProvenance({
			cwd: tmp,
			runtime: { telemetrySessionId: "scan", projectSeq: 0, turnIndex: 0 },
			generation: 1,
			files: [{ path: testResult.file, role: "test" }],
		});
		(cacheManager.readCache as ReturnType<typeof vi.fn>).mockImplementation(
			(scanner: string) => {
				if (scanner === "test-runner-findings") {
					return {
						data: { content: "FAIL", stale: false, results: [testResult], provenance },
						meta: { timestamp: new Date().toISOString() },
					};
				}
				return null;
			},
		);
		const clients = makeClients();

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		// Cache-read only — no client method exists to "run" test-runner here,
		// and this must NOT write back to the cache (nothing fresher to write).
		expect(cacheManager.writeCache).not.toHaveBeenCalledWith(
			"test-runner-findings",
			expect.anything(),
			expect.anything(),
			expect.anything(),
		);
		expect(result.runners).toContain("test-runner");
		const diag = result.diagnostics.find((d) => d.tool === "test-runner");
		// #1004 review follow-up: `TestFailure.location` ("relPath:line") must
		// reach `ProjectDiagnostic.line` — before the fix every test-runner
		// finding rendered as `L?:` in lens-diagnostics, unlike jscpd/knip/madge
		// which all carry real line numbers.
		expect(diag).toMatchObject({
			filePath: testResult.file,
			line: 17,
			severity: "error",
			semantic: "blocking",
			tool: "test-runner",
			runner: "vitest",
			rule: "test:vitest",
			message: "foo works: expected true to be false",
		});

		const mismatched = await fetchFreshProjectDiagnostics(
			cacheManager,
			tmp,
			clients,
			undefined,
			{ runtime: new RuntimeCoordinator() },
		);
		expect(mismatched.diagnostics.find((d) => d.tool === "test-runner"))
			.toMatchObject({ severity: "info", semantic: "none" });
	});

	// #1004 review follow-up (honesty gap, #533): test-runner's cache can be
	// STALE (the turn advanced before the test run finished —
	// `runtime-turn.ts`'s `stale` flag) — mode=full must not present a stale
	// result as if it were fresh, the same way the one-shot turn-context
	// message already prefixes stale failures.
	it("prefixes test-runner findings with a stale marker when the cache says stale (#1004)", async () => {
		const cacheManager = makeCacheManager();
		const testResult = {
			file: path.join(path.resolve(tmp), "src/bar.test.ts"),
			runner: "vitest",
			passed: 0,
			failed: 1,
			duration: 10,
			failures: [{ name: "bar works", message: "boom" }],
		};
		(cacheManager.readCache as ReturnType<typeof vi.fn>).mockImplementation(
			(scanner: string) => {
				if (scanner === "test-runner-findings") {
					return {
						data: { content: "FAIL", stale: true, results: [testResult] },
						meta: { timestamp: new Date().toISOString() },
					};
				}
				return null;
			},
		);
		const clients = makeClients();

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		const diag = result.diagnostics.find((d) => d.tool === "test-runner");
		expect(diag?.message).toMatch(/^\[stale/);
	});

	it("reports test-runner cold (not clean) when no turn_end cache exists yet (#1004)", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients();

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(result.cold).toContain("test-runner");
		expect(result.runners).not.toContain("test-runner");
	});

	it("runs every applicable dead-code language client and reports 'dead-code' cold only when none apply", async () => {
		const cacheManager = makeCacheManager();
		const pythonClient = {
			id: "python",
			language: "python",
			detect: vi.fn().mockReturnValue(true),
			analyze: vi.fn().mockResolvedValue({
				success: true,
				language: "python",
				summary: "",
				unusedExports: [
					{ category: "export", kind: "func", name: "x", file: "z.py", line: 9 },
				],
				unusedFiles: [],
				unusedDeps: [],
				unlistedDeps: [],
			}),
		};
		const clients = makeClients();
		(clients as unknown as { deadCodeClients: unknown[] }).deadCodeClients = [
			pythonClient,
		];

		const result = await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);

		expect(pythonClient.detect).toHaveBeenCalledWith(path.resolve(tmp));
		expect(pythonClient.analyze).toHaveBeenCalledTimes(1);
		expect(cacheManager.writeCache).toHaveBeenCalledWith(
			"dead-code-python",
			expect.anything(),
			path.resolve(tmp),
			expect.anything(),
		);
		expect(result.runners).toContain("dead-code");
	});

	it("runs all analyzers in parallel, not serially", async () => {
		// Regression guard for the issue's core ask: total wall time should be
		// bounded by the single slowest analyzer, not their sum. Simulate each
		// analyzer taking ~20ms; if they ran serially (7 analyzers) the whole
		// call would take >100ms. In parallel it should stay close to 20ms.
		fs.writeFileSync(path.join(tmp, ".gitleaksignore"), "");
		fs.writeFileSync(path.join(tmp, "go.mod"), "module demo\n\ngo 1.21\n");
		fs.writeFileSync(
			path.join(tmp, ".pi-lens.json"),
			JSON.stringify({ trivy: { enabled: true } }),
		);
		fs.writeFileSync(path.join(tmp, "package.json"), "{}");

		const delay = () => new Promise((res) => setTimeout(res, 20));
		const cacheManager = makeCacheManager();
		const clients = makeClients({ jscpdAvailable: true, madgeAvailable: true });
		for (const key of [
			"knipClient",
			"jscpdClient",
			"depChecker",
			"gitleaksClient",
			"govulncheckClient",
			"trivyClient",
		] as const) {
			const c = clients[key] as unknown as Record<string, ReturnType<typeof vi.fn>>;
			for (const methodName of ["analyze", "scan", "scanProject"]) {
				if (c[methodName]) {
					const original = c[methodName].getMockImplementation() as
						| ((...args: unknown[]) => unknown)
						| undefined;
					c[methodName].mockImplementation(async (...args: unknown[]) => {
						await delay();
						return original ? original(...args) : undefined;
					});
				}
			}
		}

		const start = Date.now();
		await fetchFreshProjectDiagnostics(cacheManager, tmp, clients);
		const elapsed = Date.now() - start;

		// Generous ceiling: serial execution of 6 x 20ms would be >=120ms.
		expect(elapsed).toBeLessThan(100);
	});

	it("does not start analyzers when the request signal is already aborted", async () => {
		const cacheManager = makeCacheManager();
		const clients = makeClients({ jscpdAvailable: true, madgeAvailable: true });
		const controller = new AbortController();
		controller.abort();

		const result = await fetchFreshProjectDiagnostics(
			cacheManager,
			tmp,
			clients,
			controller.signal,
		);

		expect(result.aborted).toBe(true);
		expect(result.abortedIds).toEqual(result.cold);
		expect(clients.knipClient.analyze).not.toHaveBeenCalled();
		expect(clients.jscpdClient.ensureAvailable).not.toHaveBeenCalled();
		expect(clients.depChecker.ensureAvailable).not.toHaveBeenCalled();
		expect(clients.opengrepClient.ensureAvailable).not.toHaveBeenCalled();
		expect(cacheManager.writeCache).not.toHaveBeenCalled();
	});

	it("does not let an aborting joiner cancel an incumbent scan", async () => {
		const client = new DedupeProbe();
		let finishIncumbent: ((value: string) => void) | undefined;
		const incumbent = client.run(
			"root",
			() =>
				new Promise((resolve) => {
					finishIncumbent = resolve;
				}),
		);
		const controller = new AbortController();
		let joinerStarted = false;
		const joined = client.run("root", async () => {
			joinerStarted = true;
			throw new Error(`joining signal: ${controller.signal.aborted}`);
		});

		controller.abort();
		expect(joined).toBe(incumbent);
		expect(joinerStarted).toBe(false);
		finishIncumbent?.("incumbent-result");
		await expect(joined).resolves.toBe("incumbent-result");
	});

	it("returns promptly with partial results when the signal aborts mid-scan, instead of waiting for every analyzer (#585 follow-up)", async () => {
		fs.writeFileSync(path.join(tmp, "tsconfig.json"), "{}");
		const cacheManager = makeCacheManager();
		const clients = makeClients({ jscpdAvailable: true });

		// knip resolves fast (well within the abort budget); jscpd is mocked to
		// take far longer than the abort fires, simulating a slow analyzer still
		// in flight when mode=full's wall-clock ceiling / Escape fires.
		let jscpdResolve: (() => void) | undefined;
		(clients.jscpdClient.scan as ReturnType<typeof vi.fn>).mockImplementation(
			() =>
				new Promise((resolve) => {
					jscpdResolve = () =>
						resolve({
							success: true,
							duplicatedLines: 0,
							totalLines: 0,
							percentage: 0,
							clones: [],
						});
					// Deliberately never auto-resolves within the test — only via
					// jscpdResolve(), called explicitly after assertions below so
					// the process doesn't leak a dangling timer.
				}),
		);

		const controller = new AbortController();
		const start = Date.now();
		const resultPromise = fetchFreshProjectDiagnostics(
			cacheManager,
			tmp,
			clients,
			controller.signal,
		);
		setTimeout(() => controller.abort(), 20);

		const result = await resultPromise;
		const elapsed = Date.now() - start;

		// Returned promptly around the abort, not waiting for jscpd's still-
		// pending promise (which would hang the test if awaited directly).
		expect(elapsed).toBeLessThan(500);
		expect(result.aborted).toBe(true);
		expect(result.abortedIds).toContain("jscpd");
		expect(clients.jscpdClient.scan).toHaveBeenCalledWith(
			path.resolve(tmp),
			undefined,
			undefined,
			true,
			{ signal: controller.signal },
		);
		// knip had time to settle before the abort fired.
		expect(result.abortedIds).not.toContain("knip");
		// Aborted analyzers are folded into `cold` too, so a caller that only
		// checks `cold` still treats them as "not a clean verdict" rather than
		// silently absent.
		expect(result.cold).toContain("jscpd");

		// Let the still-in-flight jscpd promise resolve so it doesn't leak
		// across tests / trigger an unhandled rejection warning.
		jscpdResolve?.();
	});
});
