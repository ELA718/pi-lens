/**
 * opengrep CLI client for pi-lens — bulk/full-workspace project-diagnostics
 * extractor (#584).
 *
 * opengrep already runs as an always-on LSP auxiliary (`clients/lsp/server.ts`
 * `OpengrepServer`) for real-time per-edit feedback, and this client does NOT
 * touch that path. It exists solely so `lens_diagnostics mode=full` /
 * `lsp_diagnostics` full-workspace scans can read opengrep's findings from a
 * single project-wide CLI scan instead of one LSP touch per file.
 *
 * Why: opengrep has no `workspace/diagnostic` pull support (push-only, per
 * `docs/servercapabilities.md`), and `reopenOnResync: true`
 * (`clients/lsp/wait-policy/strategies.ts`) means every LSP touch already forces a
 * full re-scan of that one file — there's no incremental efficiency lost by
 * moving bulk scans off the per-file touch loop. On a full sweep the old path
 * instead paid opengrep's full per-file wait-tier budget serially, one file at
 * a time within its server group (#387's deliberate single-flight-per-server
 * serialization) — on a real 50-file sweep this produced 49/50 files reporting
 * "unconfirmed (timed out)".
 *
 * Lifecycle mirrors gitleaks/trivy/knip:
 *   - session_start scan (via `runTask`/`runHeavyweightTask` in
 *     runtime-session.ts), cached via `cacheManager`
 *   - `lens_diagnostics mode=full` reads the cache through the extractor
 *     registry (`project-diagnostics/extractors.ts`) — never launches a scan
 *   - per-edit LSP path (real-time feedback) is untouched
 *
 * Enablement mirrors the LSP server (`opengrepInitialization` in server.ts):
 * opengrep is structurally always-on — `resolveOpengrepConfig` only chooses
 * WHICH rules run (a local `.opengrep.yml`/`.semgrep.yml` rule file if
 * present, else the `auto` registry ruleset), not whether it runs at all.
 *
 * `// nosemgrep` / `# nosemgrep` suppression: unlike opengrep's LSP mode
 * (which does NOT honor it natively — that gap is exactly why
 * `isNosemgrepSuppressed`/`applyAuxiliarySuppressions` exist in
 * `clients/dispatch/auxiliary-lsp.ts`, #441/#586/#587), the CLI `scan --json`
 * path DOES suppress `nosemgrep`-annotated findings itself, before they ever
 * reach `--json` output — verified empirically against the real installed
 * opengrep 1.25.0 binary (see the captured raw JSON in
 * `tests/clients/opengrep-client.test.ts`: an annotated line's finding is
 * absent from `results` while an identical unannotated twin still appears).
 * So `opengrepResultToProjectDiagnostics` deliberately applies NO suppression
 * filtering of its own — doing so would be redundant at best.
 *
 * Refs: #584, #111 (opengrep adoption), #387 (workspace-sweep serialization)
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { mkdtempSync } from "node:fs";
import { resolveOpengrepConfig } from "./opengrep-config.js";
import {
	safeSpawnAsync,
	type SpawnFailureKind,
	type SpawnResult,
} from "./safe-spawn.js";
import { SecurityScanClient } from "./security-scan-client.js";

// --- Types ---

/** A single opengrep finding location (semgrep-compatible JSON schema). */
export interface OpengrepPosition {
	line: number;
	col: number;
}

/**
 * Subset of fields opengrep emits per finding in its `--json` report. Schema
 * is semgrep-compatible (opengrep is a semgrep fork) — verified against the
 * real installed binary (opengrep 1.25.0), not assumed from upstream docs.
 */
export interface OpengrepFinding {
	checkId: string;
	path: string;
	startLine: number;
	startCol: number;
	endLine: number;
	endCol: number;
	message: string;
	severity: string;
	/** e.g. ["CWE-78: ..."] — carried through for the diagnostic message. */
	cwe?: string[];
}

export interface OpengrepResult {
	success: boolean;
	findings: OpengrepFinding[];
	/** Optional for compatibility with caches written before scan receipts. */
	reportErrors?: OpengrepReportError[];
	reportIntegrity?: "complete" | "partial" | "missing" | "malformed";
	scannedPathCount?: number;
	exitCode?: number | null;
	processFailure?: SpawnFailureKind;
	outputTruncated?: boolean;
	scannedAt: string;
	summary?: string;
}

export interface OpengrepReportError {
	type: string;
	level: string;
	message: string;
	path?: string;
	line?: number;
}

const EMPTY_RESULT: Omit<OpengrepResult, "scannedAt"> = {
	success: false,
	findings: [],
	reportErrors: [],
	reportIntegrity: "missing",
	exitCode: null,
};

// opengrep loads/compiles a full rule pack (1000+ rules for `auto`) before
// scanning; generous budget for a large tree, matching trivy's CVE-DB-fetch
// allowance rather than the lighter jscpd/gitleaks scans.
const SCAN_TIMEOUT_MS = 180_000;
const SUPPORTED_SEVERITIES = new Set(["ERROR", "WARNING", "INFO"]);

// --- Client ---

export class OpengrepClient extends SecurityScanClient<OpengrepResult> {
	constructor(verbose = false) {
		super("opengrep", verbose);
	}

	/**
	 * Structurally always-on (mirrors `opengrepInitialization` in
	 * `clients/lsp/server.ts`) — `resolveOpengrepConfig(cwd, { enabled: true })`
	 * only resolves WHICH rules to run, not whether opengrep runs at all.
	 * Exported as a static so callers can gate/log without constructing.
	 */
	static resolveConfig(cwd: string): ReturnType<typeof resolveOpengrepConfig> {
		return resolveOpengrepConfig(cwd, { enabled: true });
	}

	/**
	 * opengrep's top-level `--version` (no `scan` subcommand) — matches the
	 * installer's `checkArgs: ["--version"]` entry (`installer/index.ts`).
	 */
	protected doEnsureAvailable(): Promise<boolean> {
		return this.ensureViaInstaller(["--version"]);
	}

	/**
	 * Scan a directory tree with opengrep's rule set (local config or `auto`).
	 * Re-entrancy safe: concurrent calls against the same root share a single
	 * opengrep process (mirrors `GitleaksClient`/`JscpdClient`).
	 */
	async scan(cwd: string, signal?: AbortSignal): Promise<OpengrepResult> {
		const targetDir = path.resolve(cwd);
		const scannedAt = new Date().toISOString();

		if (!(await this.ensureAvailable())) {
			return {
				...EMPTY_RESULT,
				scannedAt,
				summary: "opengrep not installed",
			};
		}

		return this.dedupeScan(targetDir, () => this.runScan(targetDir, signal));
	}

	private async runScan(
		cwd: string,
		signal?: AbortSignal,
	): Promise<OpengrepResult> {
		const scannedAt = new Date().toISOString();
		const bin = this.binaryPath ?? "opengrep";
		const resolved = OpengrepClient.resolveConfig(cwd);
		const outDir = mkdtempSync(path.join(os.tmpdir(), "pi-lens-opengrep-"));
		const reportPath = path.join(outDir, "opengrep-report.json");
		try {
			const result = await safeSpawnAsync(
				bin,
				[
					"scan",
					"--config",
					resolved.configArg ?? "auto",
					"--json",
					"--json-output",
					reportPath,
					// Never fail the scan on findings — this is a read, not a gate
					// (matches gitleaks's `--exit-code 0` intent).
					"--no-error",
					"--quiet",
					"--disable-version-check",
					cwd,
				],
				{ cwd, timeout: SCAN_TIMEOUT_MS, signal },
			);

			if (!fs.existsSync(reportPath)) {
				return {
					...EMPTY_RESULT,
					exitCode: result.status,
					processFailure: result.failure,
					outputTruncated: result.outputTruncated,
					scannedAt,
					summary: processSummary("no report produced", result),
				};
			}

			const report = parseOpengrepReportResult(
				fs.readFileSync(reportPath, "utf-8"),
			);
			if (!report) {
				return {
					...EMPTY_RESULT,
					reportIntegrity: "malformed",
					exitCode: result.status,
					processFailure: result.failure,
					outputTruncated: result.outputTruncated,
					scannedAt,
					summary: processSummary("malformed opengrep report", result),
				};
			}

			const success = result.status === 0 && !result.error;
			const reportIntegrity =
				success && report.reportErrors.length === 0 ? "complete" : "partial";
			const summary = success
				? `opengrep report is partial; ${report.reportErrors.length} report error(s)`
				: processSummary("opengrep failed", result);
			return {
				success,
				...report,
				reportIntegrity,
				exitCode: result.status,
				processFailure: result.failure,
				outputTruncated: result.outputTruncated,
				scannedAt,
				...(reportIntegrity === "partial" ? { summary } : {}),
			};
		} catch (err) {
			return {
				...EMPTY_RESULT,
				scannedAt,
				summary: err instanceof Error ? err.message.slice(0, 200) : String(err),
			};
		} finally {
			try {
				fs.rmSync(outDir, { recursive: true, force: true });
			} catch {
				// non-fatal
			}
		}
	}
}

function processSummary(prefix: string, result: SpawnResult): string {
	const details = [
		result.status === null ? "no exit code" : `exit ${result.status}`,
		result.failure,
		result.error?.message,
		result.stderr.trim().split("\n")[0],
	].filter((detail): detail is string => Boolean(detail));
	return `${prefix}; ${details.join("; ")}`.slice(0, 500);
}

export interface ParsedOpengrepReport {
	findings: OpengrepFinding[];
	reportErrors: OpengrepReportError[];
	scannedPathCount?: number;
}

// --- Parser ---

/**
 * Map opengrep's `--json` report (semgrep-compatible schema: top-level
 * `results: [{ check_id, path, start:{line,col}, end:{line,col}, extra:{
 * message, severity, metadata:{cwe} } }]`) to our structured
 * `OpengrepFinding[]` shape. Exported for unit tests.
 *
 * Verified against the real installed opengrep 1.25.0 binary's own `--json`
 * output (not assumed from upstream semgrep docs — opengrep is a fork and its
 * CLI surface has drifted in places, e.g. `--files-with-matches` requires
 * `--experimental` where semgrep's doesn't).
 */
/**
 * Compatibility parser for callers that only need findings. It accepts the
 * historical results-only fixture shape. Native scans use the strict receipt
 * parser below and never infer complete coverage from absent receipt fields.
 */
export function parseOpengrepReport(raw: string): OpengrepFinding[] {
	return parseOpengrepReportEnvelope(raw, false)?.findings ?? [];
}

/** Parse a native report only when results, errors, and scanned-path receipts exist. */
export function parseOpengrepReportResult(
	raw: string,
): ParsedOpengrepReport | undefined {
	return parseOpengrepReportEnvelope(raw, true);
}

function parseOpengrepReportEnvelope(
	raw: string,
	requireReceipt: boolean,
): ParsedOpengrepReport | undefined {
	if (!raw.trim()) return undefined;
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return undefined;
	}
	if (!parsed || typeof parsed !== "object") return undefined;
	const root = parsed as Record<string, unknown>;
	if (!Array.isArray(root.results)) return undefined;
	const paths = root.paths as Record<string, unknown> | undefined;
	if (
		requireReceipt &&
		(!Array.isArray(root.errors) || !Array.isArray(paths?.scanned))
	) {
		return undefined;
	}
	const reportErrors: OpengrepReportError[] = [];
	const findings: OpengrepFinding[] = [];
	for (const entry of root.results) {
		if (!entry || typeof entry !== "object") {
			if (requireReceipt) reportErrors.push(malformedReportError("Result"));
			continue;
		}
		const e = entry as Record<string, unknown>;
		const checkId = typeof e.check_id === "string" ? e.check_id : undefined;
		const filePath = typeof e.path === "string" ? e.path : undefined;
		const start = e.start as { line?: unknown; col?: unknown } | undefined;
		const end = e.end as { line?: unknown; col?: unknown } | undefined;
		const startLine = typeof start?.line === "number" ? start.line : undefined;
		if (!checkId || !filePath || !Number.isFinite(startLine)) {
			if (requireReceipt) reportErrors.push(malformedReportError("Result"));
			continue;
		}
		const extra = (e.extra as Record<string, unknown> | undefined) ?? {};
		const rawSeverity = extra.severity;
		const severity =
			typeof rawSeverity === "string" ? rawSeverity.toUpperCase() : "WARNING";
		if (
			requireReceipt &&
			(typeof rawSeverity !== "string" ||
				!SUPPORTED_SEVERITIES.has(severity))
		) {
			reportErrors.push({
				type: "MalformedSeverity",
				level: "warn",
				message: `opengrep finding has unsupported severity: ${String(rawSeverity)}`,
				path: filePath,
				line: startLine,
			});
		}
		const metadata =
			(extra.metadata as Record<string, unknown> | undefined) ?? {};
		const cwe = Array.isArray(metadata.cwe)
			? metadata.cwe.filter((c): c is string => typeof c === "string")
			: undefined;
		findings.push({
			checkId,
			path: filePath,
			startLine: startLine as number,
			startCol: typeof start?.col === "number" ? start.col : 1,
			endLine: typeof end?.line === "number" ? end.line : (startLine as number),
			endCol: typeof end?.col === "number" ? end.col : 1,
			message:
				typeof extra.message === "string" ? extra.message : "opengrep finding",
			severity,
			cwe,
		});
	}
	for (const entry of Array.isArray(root.errors) ? root.errors : []) {
		const parsedError = parseReportError(entry);
		if (parsedError) reportErrors.push(parsedError);
		else if (requireReceipt) reportErrors.push(malformedReportError("ReportError"));
	}
	const scannedPaths = paths?.scanned as unknown[];
	if (
		requireReceipt &&
		Array.isArray(scannedPaths) &&
		scannedPaths.some((entry) => typeof entry !== "string")
	) {
		reportErrors.push(malformedReportError("ScannedPath"));
	}
	return {
		findings,
		reportErrors,
		...(Array.isArray(scannedPaths)
			? {
					scannedPathCount: scannedPaths.filter(
						(entry) => typeof entry === "string",
					).length,
				}
			: {}),
	};
}

function parseReportError(entry: unknown): OpengrepReportError | undefined {
	if (!entry || typeof entry !== "object") return undefined;
	const error = entry as Record<string, unknown>;
	const type = Array.isArray(error.type) ? error.type[0] : error.type;
	const spans = Array.isArray(error.spans) ? error.spans : [];
	const firstSpan = spans[0] as Record<string, unknown> | undefined;
	const start = firstSpan?.start as Record<string, unknown> | undefined;
	return {
		type: typeof type === "string" ? type : "ReportError",
		level: typeof error.level === "string" ? error.level : "warn",
		message:
			typeof error.message === "string"
				? error.message.slice(0, 1_000)
				: "opengrep reported incomplete coverage",
		...(typeof error.path === "string" ? { path: error.path } : {}),
		...(typeof start?.line === "number" ? { line: start.line } : {}),
	};
}

function malformedReportError(part: string): OpengrepReportError {
	return {
		type: `Malformed${part}`,
		level: "warn",
		message: `opengrep report contains a malformed ${part.toLowerCase()} entry`,
	};
}
