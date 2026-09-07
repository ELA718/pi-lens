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

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { mkdtempSync } from "node:fs";
import { createHash } from "node:crypto";
import { safeSpawnAsync } from "./safe-spawn.js";
import { SecurityScanClient } from "./security-scan-client.js";

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
		properties.push({ key, valueStart, valueEnd });
		i = valueEnd;
	}
	return properties;
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

			const findings = parseGitleaksReport(
				fs.readFileSync(reportPath, "utf-8"),
				cwd,
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
