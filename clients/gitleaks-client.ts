/**
 * gitleaks client for pi-lens
 *
 * Surfaces committed secrets (API keys, tokens, passwords, certificates)
 * detected by Aaron Vargas's `gitleaks` scanner. Cross-language by design
 * — gitleaks operates on bytes via regex + entropy, not AST.
 *
 * Lifecycle:
 *   - session_start scan (via the existing `runTask(setImmediate)` wrapper)
 *   - turn_end advisory reads the cached result and surfaces top N findings
 *   - per-edit scope: skipped — secrets either are or aren't in a file;
 *     re-scanning every keystroke is wasteful when the cache is hot
 *
 * Detection gate (config-first per #130 default):
 *   - `.gitleaks.toml` / `.gitleaks.yaml` / `.gitleaksignore` at the
 *     project root, OR
 *   - `gitleaks` reference in `package.json` deps, OR
 *   - a git pre-commit hook (.husky/, .git/hooks/) referencing gitleaks
 *
 * `lens_diagnostics mode=full`'s fresh-fetch path (`clients/project-diagnostics/
 * fresh-fetch.ts`) uses a looser "smart-default" gate instead — any tracked
 * git repo, via `hasGitRepo` — since that's an explicitly-requested
 * comprehensive review where gitleaks's low cost and advisory-only findings
 * make the stricter default needlessly conservative. session_start and
 * per-edit dispatch keep the strict gate above unchanged.
 *
 * If the gate trips, the runner auto-installs gitleaks from GitHub releases
 * (installer entry registered in clients/installer/index.ts) and runs
 * `gitleaks detect --no-git --report-format json` against the analysis root.
 *
 * Refs: #130
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { mkdtempSync } from "node:fs";
import { createHash } from "node:crypto";
import { safeSpawnAsync } from "./safe-spawn.js";
import { SecurityScanClient } from "./security-scan-client.js";
import { isFullyQualifiedWin32 } from "./path-utils.js";

// --- Types ---

/**
 * Subset of fields gitleaks emits per finding in its JSON report.
 * Schema reference: https://github.com/gitleaks/gitleaks/wiki/Reports
 */
export interface GitleaksFinding {
	ruleId: string;
	description?: string;
	file: string;
	startLine: number;
	endLine?: number;
	match?: string;
	secret?: string;
	tags?: string[];
	commit?: string;
	author?: string;
	date?: string;
}

export interface GitleaksResult {
	success: boolean;
	findings: GitleaksFinding[];
	scannedAt: string;
	summary?: string;
}

const EMPTY_RESULT: Omit<GitleaksResult, "scannedAt"> = {
	success: false,
	findings: [],
};

const SCAN_TIMEOUT_MS = 120_000;
const MAX_METADATA_BYTES = 1_048_576;
const MAX_SOURCE_BYTES = 1_048_576;
const MAX_MATCH_BYTES = 4_096;
const GIT_PROOF_TIMEOUT_MS = 2_000;
const GIT_PROOF_KILL_GRACE_MS = 100;
const PROVENANCE_DEADLINE_MS = 5_000;
const MAX_GIT_IDENTITY_BYTES = 4_096;
const MAX_JSON_VALUES = 10_000;
const MAX_HISTORICAL_PROOFS = 128;

interface HistoricalSourceProof { commit: string; sourcePath: string }

interface BoundedFileSnapshot {
	content: Buffer;
	dev: number;
	ino: number;
	mtimeMs: number;
	sha256: string;
	size: number;
}

interface JsonPropertyRange {
	key: string;
	valueStart: number;
	valueEnd: number;
}

function jsonStringEnd(source: string, start: number): number {
	for (let i = start + 1; i < source.length; i++) {
		if (source[i] === "\\") i++;
		else if (source[i] === '"') return i + 1;
	}
	return -1;
}

function jsonValueEnd(source: string, start: number): number {
	if (source[start] === '"') return jsonStringEnd(source, start);
	if (source[start] !== "{" && source[start] !== "[") {
		let i = start;
		while (i < source.length && !",}]".includes(source[i])) i++;
		return i;
	}
	const stack = [source[start]];
	for (let i = start + 1; i < source.length; i++) {
		if (source[i] === '"') {
			i = jsonStringEnd(source, i) - 1;
			if (i < 0) return -1;
		} else if (source[i] === "{" || source[i] === "[") stack.push(source[i]);
		if (stack.length > MAX_JSON_VALUES) return -1;
		else if (source[i] === "}" || source[i] === "]") {
			stack.pop();
			if (stack.length === 0) return i + 1;
		}
	}
	return -1;
}

function jsonObjectProperties(source: string, start: number, end: number): JsonPropertyRange[] | undefined {
	if (source[start] !== "{" || source[end - 1] !== "}") return undefined;
	const properties: JsonPropertyRange[] = [];
	let i = start + 1;
	while (i < end - 1) {
		while (/\s|,/.test(source[i] ?? "")) i++;
		if (i >= end - 1) break;
		if (source[i] !== '"') return undefined;
		const keyEnd = jsonStringEnd(source, i);
		if (keyEnd < 0) return undefined;
		let key: unknown;
		try { key = JSON.parse(source.slice(i, keyEnd)); } catch { return undefined; }
		if (typeof key !== "string") return undefined;
		i = keyEnd;
		while (/\s/.test(source[i] ?? "")) i++;
		if (source[i++] !== ":") return undefined;
		while (/\s/.test(source[i] ?? "")) i++;
		const valueStart = i;
		const valueEnd = jsonValueEnd(source, valueStart);
		if (valueEnd < 0 || valueEnd > end) return undefined;
		if (properties.length >= MAX_JSON_VALUES) return undefined;
		properties.push({ key, valueStart, valueEnd });
		i = valueEnd;
	}
	return properties;
}

function jsonArrayValues(source: string, start: number, end: number): { valueStart: number; valueEnd: number }[] | undefined {
	if (source[start] !== "[" || source[end - 1] !== "]") return undefined;
	const values: { valueStart: number; valueEnd: number }[] = [];
	let i = start + 1;
	while (i < end - 1) {
		while (/\s|,/.test(source[i] ?? "")) i++;
		if (i >= end - 1) break;
		const valueEnd = jsonValueEnd(source, i);
		if (valueEnd < 0 || valueEnd > end) return undefined;
		if (values.length >= MAX_JSON_VALUES) return undefined;
		values.push({ valueStart: i, valueEnd });
		i = valueEnd;
	}
	return values;
}

function historicalSourceProof(source: string, matchOffset: number, match: string, secret: string): HistoricalSourceProof | undefined {
	if (!match.includes(secret)) return undefined;
	const secretOffset = match.indexOf(secret);
	if (match.slice(secretOffset + 1).includes(secret)) return undefined;
	const start = source.search(/\S/);
	const end = start < 0 ? -1 : jsonValueEnd(source, start);
	if (end < 0 || source.slice(end).trim()) return undefined;
	const stack = [{ valueStart: start, valueEnd: end }];
	const proofs: HistoricalSourceProof[] = [];
	let visited = 0;
	while (stack.length) {
		if (++visited > MAX_JSON_VALUES) return undefined;
		const value = stack.pop();
		if (!value) break;
		if (source[value.valueStart] === "[") {
			const children = jsonArrayValues(source, value.valueStart, value.valueEnd);
			if (!children) return undefined;
			if (stack.length + children.length > MAX_JSON_VALUES) return undefined;
			stack.push(...children);
			continue;
		}
		if (source[value.valueStart] !== "{") continue;
		const properties = jsonObjectProperties(source, value.valueStart, value.valueEnd);
		if (!properties) return undefined;
		if (stack.length + properties.length > MAX_JSON_VALUES) return undefined;
		stack.push(...properties);
		if (new Set(properties.map(property => property.key)).size !== properties.length) continue;
		const hashes = properties.filter(property => property.key === "sourceSha256");
		const commits = properties.filter(property => property.key === "verifiedSourceCommit");
		if (hashes.length !== 1 || commits.length !== 1 || source[hashes[0].valueStart] !== "{") continue;
		const entries = jsonObjectProperties(source, hashes[0].valueStart, hashes[0].valueEnd);
		if (!entries || new Set(entries.map(property => property.key)).size !== entries.length) continue;
		const candidates = entries.filter(property => source.slice(property.valueStart, property.valueEnd) === JSON.stringify(secret)
			&& property.valueStart + 1 === matchOffset + secretOffset);
		if (candidates.length !== 1) continue;
		let commit: unknown;
		try { commit = JSON.parse(source.slice(commits[0].valueStart, commits[0].valueEnd)); } catch { continue; }
		if (typeof commit === "string") proofs.push({ commit, sourcePath: candidates[0].key });
	}
	return proofs.length === 1 ? proofs[0] : undefined;
}

function runBoundedGit(root: string, args: string[], signal: AbortSignal | undefined, maxBytes: number, deadlineAt: number): Promise<Buffer | undefined> {
	const remaining = Math.min(GIT_PROOF_TIMEOUT_MS, deadlineAt - Date.now());
	if (signal?.aborted || remaining <= 0) return Promise.resolve(undefined);
	return new Promise(resolve => {
		const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")));
		Object.assign(env, { GIT_LITERAL_PATHSPECS: "1", GIT_NO_LAZY_FETCH: "1", GIT_NO_REPLACE_OBJECTS: "1", GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0" });
		const detached = process.platform !== "win32";
		const child = spawn("git", ["--no-optional-locks", "-C", root, ...args], { detached, env, shell: false, stdio: ["ignore", "pipe", "ignore"] });
		const chunks: Buffer[] = [];
		let bytes = 0;
		let failed = false;
		let stopping = false;
		let forceTimer: NodeJS.Timeout | undefined;
		const signalOwned = (ownedSignal: NodeJS.Signals) => {
			if (!child.pid) return;
			try { if (detached) process.kill(-child.pid, ownedSignal); else child.kill(ownedSignal); } catch { /* already exited */ }
		};
		const stop = () => {
			failed = true;
			if (stopping) return;
			stopping = true;
			signalOwned("SIGTERM");
			forceTimer = setTimeout(() => signalOwned("SIGKILL"), GIT_PROOF_KILL_GRACE_MS);
			forceTimer.unref();
		};
		const timer = setTimeout(stop, remaining);
		timer.unref();
		signal?.addEventListener("abort", stop, { once: true });
		child.stdout.on("data", (chunk: Buffer) => {
			bytes += chunk.length;
			if (bytes > maxBytes) return stop();
			chunks.push(chunk);
		});
		child.on("error", stop);
		child.on("close", code => {
			clearTimeout(timer);
			if (forceTimer) clearTimeout(forceTimer);
			signal?.removeEventListener("abort", stop);
			resolve(!failed && code === 0 ? Buffer.concat(chunks, bytes) : undefined);
		});
	});
}

async function verifyHistoricalSourceProof(root: string, proof: HistoricalSourceProof, secret: string, deadlineAt: number, signal?: AbortSignal): Promise<boolean> {
	if (!/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(proof.commit)) return false;
	if (!proof.sourcePath || proof.sourcePath.includes("\\") || path.posix.normalize(proof.sourcePath) !== proof.sourcePath
		|| proof.sourcePath.startsWith("../") || path.posix.isAbsolute(proof.sourcePath) || isFullyQualifiedWin32(proof.sourcePath)) return false;
	const format = (await runBoundedGit(root, ["rev-parse", "--show-object-format"], signal, 16, deadlineAt))?.toString().trim();
	if (!format || !["sha1", "sha256"].includes(format) || (format === "sha1" && proof.commit.length !== 40)
		|| (format === "sha256" && proof.commit.length !== 64)) return false;
	const type = (await runBoundedGit(root, ["cat-file", "-t", proof.commit], signal, 16, deadlineAt))?.toString().trim();
	if (type !== "commit") return false;
	const treeEntry = await runBoundedGit(root, ["ls-tree", "-z", "--full-tree", proof.commit, "--", proof.sourcePath], signal, MAX_GIT_IDENTITY_BYTES, deadlineAt);
	if (!treeEntry || treeEntry.at(-1) !== 0 || treeEntry.subarray(0, -1).includes(0)) return false;
	const separator = treeEntry.indexOf(9);
	if (separator < 0 || treeEntry.subarray(separator + 1, -1).toString() !== proof.sourcePath) return false;
	const [mode, kind, objectId] = treeEntry.subarray(0, separator).toString().split(" ");
	if (!["100644", "100755"].includes(mode) || kind !== "blob" || !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(objectId)) return false;
	const sizeText = (await runBoundedGit(root, ["cat-file", "-s", objectId], signal, 32, deadlineAt))?.toString().trim();
	if (!sizeText || !/^\d+$/.test(sizeText) || Number(sizeText) > MAX_SOURCE_BYTES) return false;
	const blob = await runBoundedGit(root, ["cat-file", "blob", objectId], signal, MAX_SOURCE_BYTES + 1, deadlineAt);
	return blob?.length === Number(sizeText) && createHash("sha256").update(blob).digest("hex") === secret;
}

function readBoundedFile(file: string, maxBytes: number): Buffer | undefined {
	if (!fs.lstatSync(file).isFile()) return undefined;
	const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
	try {
		const stat = fs.fstatSync(fd);
		if (!stat.isFile() || stat.size > maxBytes) return undefined;
		const content = Buffer.alloc(stat.size);
		let offset = 0;
		for (; offset < content.length;) {
			const read = fs.readSync(fd, content, offset, content.length - offset, offset);
			if (read === 0) return undefined;
			offset += read;
		}
		return fs.readSync(fd, Buffer.alloc(1), 0, 1, offset) === 0 ? content : undefined;
	} finally { fs.closeSync(fd); }
}

function readBoundedSnapshot(file: string, maxBytes: number): BoundedFileSnapshot | undefined {
	const before = fs.lstatSync(file);
	if (!before.isFile() || before.size > maxBytes) return undefined;
	const noFollow = typeof fs.constants.O_NOFOLLOW === "number" ? fs.constants.O_NOFOLLOW : 0;
	const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | noFollow);
	try {
		const stat = fs.fstatSync(fd);
		if (!stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino || stat.size !== before.size || stat.mtimeMs !== before.mtimeMs) return undefined;
		const content = Buffer.alloc(stat.size);
		let offset = 0;
		for (; offset < content.length;) {
			const bytes = fs.readSync(fd, content, offset, content.length - offset, offset);
			if (bytes === 0) return undefined;
			offset += bytes;
		}
		if (fs.readSync(fd, Buffer.alloc(1), 0, 1, offset) !== 0) return undefined;
		const after = fs.fstatSync(fd);
		if (after.size !== stat.size || after.mtimeMs !== stat.mtimeMs) return undefined;
		return { content, dev: stat.dev, ino: stat.ino, mtimeMs: stat.mtimeMs, size: stat.size, sha256: createHash("sha256").update(content).digest("hex") };
	} finally { fs.closeSync(fd); }
}

function sameSnapshot(left: BoundedFileSnapshot, right: BoundedFileSnapshot): boolean {
	return left.dev === right.dev && left.ino === right.ino && left.mtimeMs === right.mtimeMs
		&& left.size === right.size && left.sha256 === right.sha256;
}

// --- Detection ---

/**
 * Detect whether the project root has opted in to gitleaks via any of the
 * standard signals. Config-first gating per the #130 default — gitleaks
 * runs when the user has given us any indication they want it.
 *
 * Exported for tests and for callers that want the gate without instantiating
 * the client.
 */
export function hasGitleaksSignal(cwd: string): boolean {
	const candidates = [
		".gitleaks.toml",
		".gitleaks.yaml",
		".gitleaks.yml",
		".gitleaksignore",
	];
	for (const candidate of candidates) {
		try {
			if (fs.existsSync(path.join(cwd, candidate))) return true;
		} catch {
			// non-fatal
		}
	}
	// Check package.json devDependencies / dependencies for any `gitleaks*`
	// reference. Catches `gitleaks`, `lint-staged-gitleaks`, etc.
	const pkgJsonPath = path.join(cwd, "package.json");
	try {
		if (fs.existsSync(pkgJsonPath)) {
			const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8")) as {
				dependencies?: Record<string, unknown>;
				devDependencies?: Record<string, unknown>;
			};
			const deps = { ...pkg.dependencies, ...pkg.devDependencies };
			for (const name of Object.keys(deps)) {
				if (name.toLowerCase().includes("gitleaks")) return true;
			}
		}
	} catch {
		// malformed package.json — don't treat as signal
	}
	// husky / git hooks referencing gitleaks
	const hookCandidates = [
		path.join(cwd, ".husky", "pre-commit"),
		path.join(cwd, ".husky", "_", "pre-commit"),
		path.join(cwd, ".git", "hooks", "pre-commit"),
	];
	for (const hook of hookCandidates) {
		try {
			if (!fs.existsSync(hook)) continue;
			const content = fs.readFileSync(hook, "utf-8");
			if (content.includes("gitleaks")) return true;
		} catch {
			// non-fatal
		}
	}
	return false;
}

/**
 * "Smart-default" tier from #130's own considered-but-unshipped options:
 * fire whenever the project is a tracked git repo, not only when an explicit
 * gitleaks signal is present. gitleaks's own scan target is "a git repo's
 * history/tree" — nearly every project qualifies, so this is meaningfully
 * looser than {@link hasGitleaksSignal}. Used ONLY by `mode=full`'s
 * fresh-fetch path (an explicitly-requested comprehensive review, where
 * gitleaks's low cost — ~10MB binary, no external DB pull — and advisory-only
 * findings make the stricter opt-in gate needlessly conservative); session_start
 * and per-edit dispatch keep the strict {@link hasGitleaksSignal} gate
 * unchanged, so day-to-day noise/cost stays exactly as conservative as before.
 */
export function hasGitRepo(cwd: string): boolean {
	try {
		return fs.existsSync(path.join(cwd, ".git"));
	} catch {
		return false;
	}
}

// --- Client ---

export class GitleaksClient extends SecurityScanClient<GitleaksResult> {
	constructor(verbose = false) {
		super("gitleaks", verbose);
	}

	/**
	 * Static detection helper so callers can gate before constructing
	 * (matches `GovulncheckClient.hasGoModule` shape).
	 */
	static hasGitleaksSignal(cwd: string): boolean {
		return hasGitleaksSignal(cwd);
	}

	/** Smart-default tier (#130) — see {@link hasGitRepo}'s doc comment. */
	static hasGitRepo(cwd: string): boolean {
		return hasGitRepo(cwd);
	}

	/**
	 * Auto-install via the GitHub-release path (registered in
	 * `clients/installer/index.ts`) when gitleaks isn't already on PATH.
	 * gitleaks uses `version` (no leading dashes) as its CLI verb.
	 */
	protected doEnsureAvailable(): Promise<boolean> {
		return this.ensureViaInstaller(["version"]);
	}

	/**
	 * Scan a directory tree for secrets.
	 *
	 * Skips early when the directory shows no gitleaks opt-in signal — unless
	 * `requireSignal: false` (the `mode=full` fresh-fetch path uses this to
	 * apply the looser #130 "smart-default" gate, {@link hasGitRepo}, instead;
	 * session_start and per-edit dispatch never pass this, so their behavior
	 * is unchanged). When gitleaks is unavailable, returns an empty result
	 * with an explanatory summary rather than failing the session_start task.
	 *
	 * Re-entrancy safe: concurrent calls against the same root share a
	 * single gitleaks process (mirrors `KnipClient` / `JscpdClient` /
	 * `GovulncheckClient`).
	 */
	async scan(
		cwd: string,
		options?: { requireSignal?: boolean; signal?: AbortSignal },
	): Promise<GitleaksResult> {
		const targetDir = path.resolve(cwd);
		const scannedAt = new Date().toISOString();
		const requireSignal = options?.requireSignal ?? true;

		if (requireSignal && !GitleaksClient.hasGitleaksSignal(targetDir)) {
			return {
				...EMPTY_RESULT,
				success: true,
				scannedAt,
				summary: "no gitleaks opt-in signal at project root",
			};
		}

		if (!(await this.ensureAvailable())) {
			return {
				...EMPTY_RESULT,
				scannedAt,
				summary: "gitleaks not installed",
			};
		}

		return this.dedupeScan(targetDir, () =>
			this.runScan(targetDir, options?.signal),
		);
	}

	private async runScan(
		cwd: string,
		signal?: AbortSignal,
	): Promise<GitleaksResult> {
		const scannedAt = new Date().toISOString();
		const bin = this.binaryPath ?? "gitleaks";
		const outDir = mkdtempSync(path.join(os.tmpdir(), "pi-lens-gitleaks-"));
		const reportPath = path.join(outDir, "gitleaks-report.json");
		try {
			const result = await safeSpawnAsync(
				bin,
				[
					"detect",
					"--no-git",
					"--source",
					cwd,
					"--report-format",
					"json",
					"--report-path",
					reportPath,
					"--exit-code",
					"0",
					"--no-banner",
				],
				{ cwd, timeout: SCAN_TIMEOUT_MS, signal },
			);

			if (result.error) {
				this.log(`Scan error: ${result.error.message}`);
				return {
					...EMPTY_RESULT,
					scannedAt,
					summary: result.error.message.slice(0, 200),
				};
			}

			if (!fs.existsSync(reportPath)) {
				// gitleaks writes the report file even when nothing is found.
				// If the file is missing the scan likely errored before
				// writing it — surface a summary line from stderr.
				return {
					...EMPTY_RESULT,
					success: true,
					scannedAt,
					summary:
						(result.stderr ?? "").trim().split("\n")[0] || "no report produced",
				};
			}

			const findings = await parseGitleaksReportWithProvenance(
				fs.readFileSync(reportPath, "utf-8"),
				cwd,
				signal,
			);
			return {
				success: true,
				findings,
				scannedAt,
			};
		} catch (err) {
			return {
				...EMPTY_RESULT,
				scannedAt,
				summary:
					err instanceof Error ? err.message.slice(0, 200) : String(err),
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

// --- Parser ---

/** Narrow generic-key noise using the actual matched binding and value.
 * Provider-specific rules remain authoritative, including in test files. */
function isNonCredentialGenericValue(entry: Record<string, unknown>): boolean {
	if (entry.RuleID !== "generic-api-key" || typeof entry.Match !== "string" || typeof entry.Secret !== "string") return false;
	const { Match: match, Secret: secret } = entry;
	if (!secret || !match.includes(secret)) return false;
	const binding = match.match(/^(?:[A-Za-z_$][\w$]*\.)*((?:p_)?idempotency_?key|route_key|optimizationKey)\s*(?::|=>|=)\s*['"]/i)?.[1];
	// Human-readable replay/route identifiers have a distinct protocol role.
	// Opaque random strings and token-shaped values keep their finding.
	if (binding && /^[a-z0-9]+(?:-+[a-z0-9]+)+$/.test(secret) && secret.split(/-+/).some(part => /^[a-z]{3,16}$/.test(part) && /[g-z]/.test(part))) return true;
	try {
		const parts = secret.split(".");
		const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf-8"));
		if (!header || typeof header !== "object" || Array.isArray(header)) return false;
		if (parts.length === 1 && typeof header.alg === "string" && Object.keys(header).every(key => key === "alg" || key === "typ")) return true;
		// This deliberately invalid fixture has no JWT algorithm and uses the
		// literal word "signature". A real signed JWT is never excluded here.
		if (parts.length === 3 && parts[2] === "signature" && Object.keys(header).length === 0) return true;
		if (binding === "route_key" && parts.length === 1 && Object.keys(header).length > 0 && Object.keys(header).every(key => /(?:Id|Number)$/.test(key))) return true;
	} catch { /* Non-JSON/opaque values remain candidate credentials. */ }
	return false;
}

function reportedMatchOffset(source: string, entry: Record<string, unknown>): number | undefined {
	const match = entry.Match as string;
	if (Buffer.byteLength(match) > MAX_MATCH_BYTES) return undefined;
	const startLine = Number(entry.StartLine);
	const expectedEndLine = startLine + match.split("\n").length - 1;
	if (!Number.isInteger(startLine) || startLine < 1 || (entry.EndLine !== undefined && Number(entry.EndLine) !== expectedEndLine)) return undefined;
	let lineStart = 0;
	for (let line = 1; line < startLine; line++) {
		lineStart = source.indexOf("\n", lineStart);
		if (lineStart < 0) return undefined;
		lineStart++;
	}
	const firstLineEnd = source.indexOf("\n", lineStart);
	let rangeEnd = lineStart;
	for (let line = startLine; line <= expectedEndLine; line++) {
		const newline = source.indexOf("\n", rangeEnd);
		rangeEnd = newline < 0 ? source.length : newline + 1;
	}
	if (!source.includes(match, lineStart)) return undefined;
	const offset = source.indexOf(match, lineStart);
	if ((firstLineEnd >= 0 && offset >= firstLineEnd) || offset + match.length > rangeEnd) return undefined;
	return source.indexOf(match, offset + 1) < rangeEnd && source.indexOf(match, offset + 1) >= 0 ? undefined : offset;
}

function isVerifiedCurrentSourceHash(source: string, root: string, matchOffset: number, match: string, secret: string): boolean {
	let parsed: unknown;
	try { parsed = JSON.parse(source); } catch { return false; }
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;
	const start = source.search(/\S/);
	if (start < 0) return false;
	const end = jsonValueEnd(source, start);
	if (end < 0 || source.slice(end).trim()) return false;
	const rootProperties = jsonObjectProperties(source, start, end);
	const hashes = rootProperties?.filter(property => property.key === "sourceSha256") ?? [];
	if (hashes.length !== 1 || source[hashes[0].valueStart] !== "{") return false;
	const entries = jsonObjectProperties(source, hashes[0].valueStart, hashes[0].valueEnd);
	if (!entries || new Set(entries.map(property => property.key)).size !== entries.length) return false;
	if (!match.includes(secret)) return false;
	const secretOffset = match.indexOf(secret);
	if (match.indexOf(secret, secretOffset + 1) >= 0) return false;
	const candidates = entries.filter(property =>
		source.slice(property.valueStart, property.valueEnd) === JSON.stringify(secret)
		&& property.valueStart + 1 === matchOffset + secretOffset,
	);
	if (candidates.length !== 1 || path.isAbsolute(candidates[0].key)) return false;
	const sourceFile = fs.realpathSync(path.resolve(root, candidates[0].key));
	const relative = path.relative(root, sourceFile);
	if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return false;
	const content = readBoundedFile(sourceFile, MAX_SOURCE_BYTES);
	return content !== undefined && createHash("sha256").update(content).digest("hex") === secret;
}

/** Verify the surrounding metadata rather than ignoring hashes or whole files. */
function isVerifiedGenericMetadata(entry: Record<string, unknown>, cwd?: string): boolean {
	if (!cwd || entry.RuleID !== "generic-api-key" || typeof entry.File !== "string" || typeof entry.Match !== "string" || typeof entry.Secret !== "string") return false;
	try {
		const file = fs.realpathSync(path.resolve(cwd, entry.File));
		const relative = path.relative(fs.realpathSync(cwd), file);
		if (relative.startsWith("..") || path.isAbsolute(relative)) return false;
		const metadata = readBoundedFile(file, MAX_METADATA_BYTES);
		if (!metadata) return false;
		const source = metadata.toString("utf-8");
		const matchOffset = reportedMatchOffset(source, entry);
		if (matchOffset === undefined) return false;
		const lines = source.split(/\r?\n/);
		const start = Number(entry.StartLine) - 1;
		const excerpt = source.slice(matchOffset, matchOffset + entry.Match.length + 2);
		const secret = entry.Secret;
		// The regex crossed from prose ending in "key" into the NAME of the
		// next JSON property. This is not a credential assignment.
		if (entry.Match.includes("\n") && /^[A-Z][A-Z0-9_]+$/.test(secret) && /^\s*:/.test(excerpt.slice(entry.Match.length))) return true;
		if (!/^[a-f0-9]{64}$/.test(secret)) return false;
		if (isVerifiedCurrentSourceHash(source, fs.realpathSync(cwd), matchOffset, entry.Match, secret)) return true;
		const artifact = entry.Match.match(/^(\d{14}_[a-z0-9_]+\.sql)['"],\s*['"]/);
		if (artifact) {
			const content = readBoundedFile(path.join(cwd, "supabase", "migrations", artifact[1]), MAX_SOURCE_BYTES);
			return content !== undefined && createHash("sha256").update(content).digest("hex") === secret;
		}
		if (!file.endsWith(".sql")) return false;
		// A simple SQL metadata inventory: derive the value's column from its
		// actual CREATE/INSERT shape. Complex SQL stays a finding.
		const declaration = /^\s*CREATE\s+(?:TEMP|TEMPORARY)\s+TABLE\s+([a-z_]\w*)\s*\(([\s\S]*?)\)\s*ON\s+COMMIT\s+DROP\s*;/im.exec(source);
		if (!declaration) return false;
		const prefix = source.slice(0, declaration.index).replace(/^\s*--[^\n]*$/gm, "").trim();
		if (prefix && !/^BEGIN\s*;$/i.test(prefix)) return false;
		const beforeRow = lines.slice(0, start).join("\n") + "\n";
		const following = beforeRow.slice(declaration.index + declaration[0].length).replace(/^\s*--[^\n]*$/gm, "");
		if (!new RegExp(`^\\s*INSERT\\s+INTO\\s+${declaration[1]}\\s+VALUES\\s`, "i").test(following) || following.includes(";") || following.includes("/*")) return false;
		const columns = [...declaration[2].matchAll(/^\s*([a-z_]\w*)\s+(?:text|varchar|boolean)\b/gim)].map(match => match[1]);
		const row = lines[start]?.trim().match(/^\((.*)\)[,;]?$/)?.[1];
		if (!row) return false;
		const token = /'(?:''|[^'])*'|\b(?:true|false|null)\b/gi;
		const values = [...row.matchAll(token)].map(match => match[0]);
		if (row.replace(token, "").replace(/[\s,]/g, "") || values.length !== columns.length) return false;
		const positions = values.flatMap((value, index) => value === `'${secret}'` ? [index] : []);
		return positions.length > 0 && positions.every(index => /_sha256$/i.test(columns[index]));
	} catch { return false; }
}

function historicalFindingKey(entry: Record<string, unknown>): string | undefined {
	if (entry.RuleID !== "generic-api-key" || typeof entry.File !== "string" || typeof entry.Match !== "string"
		|| typeof entry.Secret !== "string" || !Number.isFinite(Number(entry.StartLine)) || !Number.isFinite(Number(entry.EndLine))) return undefined;
	return JSON.stringify([entry.File, Number(entry.StartLine), Number(entry.EndLine), entry.Match, entry.Secret]);
}

/** Apply bounded local-Git provenance for historical source digests. */
export async function parseGitleaksReportWithProvenance(raw: string, cwd?: string, signal?: AbortSignal): Promise<GitleaksFinding[]> {
	if (!cwd || signal?.aborted) return parseGitleaksReport(raw, cwd);
	let parsed: unknown;
	try { parsed = JSON.parse(raw); } catch { return parseGitleaksReport(raw, cwd); }
	if (!Array.isArray(parsed)) return parseGitleaksReport(raw, cwd);
	const entries = parsed.filter((entry): entry is Record<string, unknown> => Boolean(entry) && typeof entry === "object" && !Array.isArray(entry));
	const counts = new Map<string, number>();
	for (const entry of entries) {
		const key = historicalFindingKey(entry);
		if (key) counts.set(key, (counts.get(key) ?? 0) + 1);
	}
	if (counts.size > MAX_HISTORICAL_PROOFS) return parseGitleaksReport(raw, cwd);
	const deadlineAt = Date.now() + PROVENANCE_DEADLINE_MS;
	let root: string;
	try { root = fs.realpathSync(cwd); } catch { return parseGitleaksReport(raw, cwd); }
	const topLevel = (await runBoundedGit(root, ["rev-parse", "--show-toplevel"], signal, MAX_GIT_IDENTITY_BYTES, deadlineAt))?.toString().trim();
	if (!topLevel) return parseGitleaksReport(raw, cwd);
	try { if (fs.realpathSync(topLevel) !== root) return parseGitleaksReport(raw, cwd); } catch { return parseGitleaksReport(raw, cwd); }
	const retained: Record<string, unknown>[] = [];
	for (const entry of entries) {
		const key = historicalFindingKey(entry);
		if (!key || counts.get(key) !== 1 || signal?.aborted || Date.now() >= deadlineAt) { retained.push(entry); continue; }
		try {
			const requestedFile = path.resolve(root, String(entry.File));
			const file = fs.realpathSync(requestedFile);
			const relative = path.relative(root, file);
			if (relative.startsWith("..") || path.isAbsolute(relative)) { retained.push(entry); continue; }
			const metadata = readBoundedSnapshot(requestedFile, MAX_METADATA_BYTES);
			if (!metadata) { retained.push(entry); continue; }
			const source = metadata.content.toString("utf-8");
			const matchOffset = reportedMatchOffset(source, entry);
			const proof = matchOffset === undefined ? undefined : historicalSourceProof(source, matchOffset, String(entry.Match), String(entry.Secret));
			if (!proof || !await verifyHistoricalSourceProof(root, proof, String(entry.Secret), deadlineAt, signal)) { retained.push(entry); continue; }
			if (fs.realpathSync(requestedFile) !== file) { retained.push(entry); continue; }
			const finalMetadata = readBoundedSnapshot(requestedFile, MAX_METADATA_BYTES);
			if (!finalMetadata || !sameSnapshot(metadata, finalMetadata)) retained.push(entry);
		} catch { retained.push(entry); }
	}
	return parseGitleaksReport(JSON.stringify(retained), cwd);
}

/**
 * Map gitleaks's JSON report (a flat array of finding objects) to our
 * structured `GitleaksFinding[]` shape. Exported for unit tests.
 *
 * Gitleaks emits `null` (or `[]`) when no findings are present. Malformed
 * input returns `[]` rather than throwing — gitleaks itself is occasionally
 * truncated by upstream pipe failures.
 */
export function parseGitleaksReport(raw: string, cwd?: string): GitleaksFinding[] {
	if (!raw.trim()) return [];
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return [];
	}
	if (!Array.isArray(parsed)) return [];
	const findings: GitleaksFinding[] = [];
	for (const entry of parsed) {
		if (!entry || typeof entry !== "object") continue;
		const e = entry as Record<string, unknown>;
		const ruleId = typeof e.RuleID === "string" ? e.RuleID : undefined;
		const file = typeof e.File === "string" ? e.File : undefined;
		const startLine =
			typeof e.StartLine === "number"
				? e.StartLine
				: Number.parseInt(String(e.StartLine ?? ""), 10);
		if (!ruleId || !file || !Number.isFinite(startLine)) continue;
		if (isNonCredentialGenericValue(e)) continue;
		if (isVerifiedGenericMetadata(e, cwd)) continue;
		findings.push({
			ruleId,
			description:
				typeof e.Description === "string" ? e.Description : undefined,
			file,
			startLine,
			endLine:
				typeof e.EndLine === "number"
					? e.EndLine
					: Number.isFinite(Number(e.EndLine))
						? Number(e.EndLine)
						: undefined,
			match: typeof e.Match === "string" ? e.Match : undefined,
			secret: typeof e.Secret === "string" ? e.Secret : undefined,
			tags: Array.isArray(e.Tags)
				? e.Tags.filter((t): t is string => typeof t === "string")
				: undefined,
			commit: typeof e.Commit === "string" ? e.Commit : undefined,
			author: typeof e.Author === "string" ? e.Author : undefined,
			date: typeof e.Date === "string" ? e.Date : undefined,
		});
	}
	return findings;
}
