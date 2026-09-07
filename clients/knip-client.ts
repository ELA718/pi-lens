/**
 * Knip Client for pi-local
 *
 * Detects unused exports, files, dependencies, and more.
 * Essential for safe refactoring — I need to know what's dead code
 * before I can clean it up.
 *
 * Requires: npm install -D knip
 * Docs: https://knip.dev/
 */

import { createSubsystemLogger } from "./extension-log.js";
import * as fs from "node:fs";
import * as path from "node:path";
import { getProjectDataDir } from "./file-utils.js";
import { findNearestMarkerRoot } from "./path-utils.js";
import { safeSpawnAsync } from "./safe-spawn.js";
import { loadAstGrepNapi } from "./deps/ast-grep-napi.js";
import { tokenizeShellCommand } from "./bash-file-access.js";
import {
	createAvailabilityChecker,
	getManagedToolEnvironment,
	resolveAvailableOrInstall,
} from "./dispatch/runners/utils/runner-helpers.js";

// --- Types ---

export interface KnipIssue {
	type:
		| "export"
		| "file"
		| "dependency"
		| "devDependency"
		| "unlisted"
		| "bin"
		| "enumMember";
	name: string;
	file?: string;
	line?: number;
	package?: string;
}

export interface KnipResult {
	success: boolean;
	issues: KnipIssue[];
	unusedExports: KnipIssue[];
	unusedFiles: KnipIssue[];
	unusedDeps: KnipIssue[];
	unlistedDeps: KnipIssue[];
	summary: string;
}

const EMPTY_RESULT: Omit<KnipResult, "summary"> = {
	success: false,
	issues: [],
	unusedExports: [],
	unusedFiles: [],
	unusedDeps: [],
	unlistedDeps: [],
};

const ANALYSIS_TIMEOUT_MS = 30_000;

/**
 * Every package name referenced as a KEY (at any nesting depth — npm's
 * `overrides` and pnpm's `pnpm.overrides` allow nested "for this dependency's
 * sub-dependency" overrides) in `package.json`'s `overrides`, `resolutions`
 * (Yarn's equivalent), or `pnpm.overrides` fields. These are the project's
 * own explicit signal that a package is deliberately present to pin a
 * resolution — not a source-imported dependency knip's import graph can see.
 * Missing/malformed `package.json` degrades to an empty set (never throws) —
 * this is a best-effort narrowing, not a required input.
 */
export function readOverridePinnedPackageNames(targetDir: string): Set<string> {
	const names = new Set<string>();
	let pkg: Record<string, unknown>;
	try {
		pkg = JSON.parse(
			fs.readFileSync(path.join(targetDir, "package.json"), "utf-8"),
		);
	} catch {
		return names;
	}

	const collectKeys = (value: unknown): void => {
		if (!value || typeof value !== "object" || Array.isArray(value)) return;
		for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
			names.add(key);
			collectKeys(nested);
		}
	};

	collectKeys(pkg.overrides);
	collectKeys(pkg.resolutions);
	collectKeys((pkg.pnpm as { overrides?: unknown } | undefined)?.overrides);

	return names;
}

// --- Client ---

export class KnipClient {
	private readonly knipAvailability = createAvailabilityChecker(
		"knip",
		".cmd",
		["--version"],
		{
			environment: (cwd) => getManagedToolEnvironment("knip", cwd),
			unclassifiedFailureOutcome: "missing",
		},
	);
	private knipAvailable: boolean | null = null;
	private knipCommand = "knip";
	private ensureInFlight: Promise<boolean> | null = null;
	private log: (msg: string) => void;

	/**
	 * De-dupe concurrent `analyze()` calls against the same project root.
	 *
	 * Without this guard, two back-to-back turn_end events (or a turn_end
	 * firing while the session_start scan is still in flight) can each spawn
	 * a fresh `knip` process over the same tree. Two concurrent knip
	 * runs are CPU-bound and cause the exact pathology we're fixing: load
	 * averages >5, TUI freezes, and zombie processes reparented to init
	 * after pi exits mid-scan.
	 *
	 * Key: canonicalised project root (not the caller's cwd). Value is the
	 * in-flight promise; completing clears the slot.
	 */
	private inFlight = new Map<string, Promise<KnipResult>>();

	constructor(verbose = false) {
		this.log = verbose
			? createSubsystemLogger("knip")
			: () => {};
	}

	/**
	 * Find the nearest directory with a project/knip config marker.
	 *
	 * Returns `null` when no marker is found up to the filesystem root.
	 * Callers MUST treat a null return as "no project here, skip knip" —
	 * previously this fell back to `startDir`, which on a bare cwd like
	 * `/home/v` caused knip to recurse through every project and balloon
	 * memory/CPU.
	 *
	 * Delegates to the shared path-utils helper (refs #625) — never treats a
	 * package/knip config at or above $HOME as the project (escapes the
	 * workspace, #296/#250), and never walks past a `.git`/`.hg`/`.svn`
	 * boundary to pick up an unrelated parent's package.json (Unity/non-JS
	 * repos often have no package.json at their own root).
	 */
	private resolveProjectRoot(
		startDir: string,
		homeDirOverride?: string,
	): string | null {
		return findNearestMarkerRoot(
			startDir,
			["package.json", "knip.json", "knip.ts", "knip.config.js", "knip.config.ts"],
			{ boundaries: [".git", ".hg", ".svn"], homeDir: homeDirOverride },
		);
	}

	/**
	 * Check if knip CLI is available, auto-install if not
	 */
	async ensureAvailable(): Promise<boolean> {
		// Fast path: already checked
		if (this.knipAvailable !== null) return this.knipAvailable;
		if (this.ensureInFlight) return this.ensureInFlight;

		this.ensureInFlight = this.doEnsureAvailable();
		try {
			return await this.ensureInFlight;
		} finally {
			this.ensureInFlight = null;
		}
	}

	private async doEnsureAvailable(): Promise<boolean> {
		const resolved = await resolveAvailableOrInstall(
			this.knipAvailability,
			"knip",
			process.cwd(),
		);
		this.knipAvailable = resolved !== null;
		if (resolved) this.knipCommand = resolved;
		return this.knipAvailable;
	}

	/**
	 * Run knip analysis on the project.
	 *
	 * Async (uses `safeSpawnAsync`) so it never blocks the event loop —
	 * knip scans on large monorepos can take tens of seconds, and the
	 * previous `spawnSync` implementation froze the TUI for the entire
	 * duration.
	 *
	 * Re-entrancy safe: concurrent calls resolving to the same project
	 * root share a single knip process via `inFlight`.
	 */
	async analyze(
		cwd?: string,
		_ignore?: string[],
		signal?: AbortSignal,
	): Promise<KnipResult> {
		const targetDir = this.resolveProjectRoot(cwd || process.cwd());
		if (!targetDir) {
			// No package.json / knip config anywhere up the tree. Running knip
			// from an arbitrary cwd (e.g. $HOME) has no defined meaning and in
			// practice walks huge irrelevant trees — bail early.
			this.log(
				`No project root found from ${cwd || process.cwd()}; skipping knip`,
			);
			return {
				...EMPTY_RESULT,
				success: true,
				summary: "No project root found; knip skipped",
			};
		}

		if (!(await this.ensureAvailable())) {
			return {
				...EMPTY_RESULT,
				summary: "Knip not available. Install with: npm install -D knip",
			};
		}

		const key = path.resolve(targetDir);
		const existing = this.inFlight.get(key);
		if (existing) {
			this.log(`Analysis already in flight for ${key}; sharing result`);
			return existing;
		}

		const promise = this.runAnalyze(key, signal).finally(() => {
			this.inFlight.delete(key);
		});
		this.inFlight.set(key, promise);
		return promise;
	}

	private async runAnalyze(
		targetDir: string,
		signal?: AbortSignal,
	): Promise<KnipResult> {
		// Cache dir is routed through pi-lens's project-data-dir convention (NOT
		// knip's own default `./node_modules/.cache/knip`) so it lives alongside
		// every other project cache (see cache-manager.ts, call-graph.ts) and is
		// covered by the existing `.pi-lens/` gitignore entry.
		//
		// Caveat (per knip's docs): a cached run does NOT pick up newly-added
		// `.gitignore` files automatically — the cache must be deleted to detect
		// them. Not auto-handled here; this is a documented tradeoff, not a bug.
		const cacheLocation = path.join(getProjectDataDir(targetDir), "cache", "knip");

		// knip (verified against 6.26.0) silently fails to persist the cache when
		// `--cache-location` points at a directory that doesn't exist yet: its
		// internal auto-mkdir throws ENOENT (swallowed internally, debug-logged
		// only) on Windows, so the very first run — and every run after, since the
		// dir never gets created — degrades to an uncached scan with no error
		// surfaced. Pre-creating the dir avoids that path entirely; matches the
		// mkdirSync-before-spawn convention call-graph.ts already uses for its
		// cache file's parent dir.
		try {
			fs.mkdirSync(cacheLocation, { recursive: true });
		} catch (err) {
			this.log(`Failed to pre-create knip cache dir ${cacheLocation}: ${err}`);
		}

		const args = [
			"--reporter=json",
			"--include",
			// enumMembers surfaces unused enum members — finer-grained than
			// file-level exports. (knip 6.x has NO `classMembers` issue type; passing
			// it makes knip exit 2 with zero output, silently disabling the scan —
			// verified against knip 6.20. Valid member-level type here is enumMembers.)
			"files,exports,types,dependencies,unlisted,enumMembers",
			"--cache",
			"--cache-location",
			cacheLocation,
		];

		const result = await safeSpawnAsync(this.knipCommand, args, {
			timeout: ANALYSIS_TIMEOUT_MS,
			cwd: targetDir,
			env: await getManagedToolEnvironment("knip", targetDir),
			signal,
		});

		if (result.error) {
			this.log(`Analysis error: ${result.error.message}`);
			return {
				...EMPTY_RESULT,
				summary: `Error: ${result.error.message}`,
			};
		}

		// Knip exits 0 on success (even with issues), 1 on errors
		const output = result.stdout || "";
		this.log(`Knip output length: ${output.length}`);
		if (output.length < 500) {
			this.log(`Knip output sample: ${output}`);
		}
		if (!output.trim()) {
			return {
				...EMPTY_RESULT,
				success: true,
				summary: "No issues found",
			};
		}

		const runtimeResult = await this.dropResolvedDenoImports(
			this.dropOverridePinnedDeps(this.parseOutput(output), targetDir),
			targetDir,
		);
		return this.dropDeclaredK6Imports(runtimeResult, targetDir);
	}

	private async dropDeclaredK6Imports(result: KnipResult, targetDir: string): Promise<KnipResult> {
		if (!result.unlistedDeps.some(issue => issue.type === "unlisted" && issue.name === "k6")) return result;
		try {
			const root = fs.realpathSync(targetDir);
			const withinRoot = (file: string) => {
				const relative = path.relative(root, file);
				return !relative.startsWith("..") && !path.isAbsolute(relative);
			};
			const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf-8"));
			const declared = new Set<string>();
			const inspect = (source: string, followShell: boolean) => {
				// Heredocs and command redefinitions need a full shell evaluator;
				// never interpret their text as a runtime declaration.
				if (source.includes("<<") || /\bk6\s*\(\s*\)|\balias\s+k6\b/.test(source)) return;
				for (const segment of tokenizeShellCommand(source)) {
					if (segment.unsupported) continue;
					const tokens = [...segment.tokens];
					if (tokens[0] === "if") tokens.shift();
					if (tokens[0] === "!") tokens.shift();
					if (tokens.length === 3 && tokens[0] === "k6" && tokens[1] === "run" && /^[\w./-]+$/.test(tokens[2])) {
						const file = fs.realpathSync(path.resolve(root, tokens[2]));
						if (withinRoot(file)) declared.add(file);
					} else if (followShell && tokens.length === 2 && ["bash", "sh"].includes(tokens[0]) && /^[\w./-]+$/.test(tokens[1])) {
						const script = fs.realpathSync(path.resolve(root, tokens[1]));
						if (withinRoot(script) && fs.statSync(script).size < 256_000) inspect(fs.readFileSync(script, "utf-8"), false);
					}
				}
			};
			for (const command of Object.values(pkg.scripts ?? {})) {
				if (typeof command !== "string") continue;
				try { inspect(command, true); } catch { /* Invalid declarations do not establish a runtime. */ }
			}
			if (declared.size === 0) return result;
			const { parse, Lang } = await loadAstGrepNapi();
			const resolved = new Set<KnipIssue>();
			for (const issue of result.unlistedDeps) {
				if (issue.type !== "unlisted" || issue.name !== "k6" || !issue.file) continue;
				const file = fs.realpathSync(path.resolve(root, issue.file));
				if (!declared.has(file)) continue;
				const ast = parse(Lang.JavaScript, fs.readFileSync(file, "utf-8")).root();
				if (ast.find({ rule: { kind: "ERROR" } })) continue;
				const imports = ast.findAll({ rule: { kind: "import_statement" } }).map(node => node.field("source")?.text().slice(1, -1)).filter((source): source is string => !!source && (source === "k6" || source.startsWith("k6/")));
				if (imports.length > 0 && imports.every(source => ["k6", "k6/http", "k6/metrics"].includes(source))) resolved.add(issue);
			}
			const issues = result.issues.filter(issue => !resolved.has(issue));
			return { ...result, issues, unlistedDeps: result.unlistedDeps.filter(issue => !resolved.has(issue)), summary: `Found ${issues.length} issues` };
		} catch { return result; }
	}

	/** Knip treats npm:/jsr: protocols as Node package names. Remove that
	 * classification only after the owning runtime resolves the actual imports.
	 * A missing runtime, stale source, or incomplete graph retains the finding. */
	private async dropResolvedDenoImports(result: KnipResult, targetDir: string): Promise<KnipResult> {
		const candidates = result.unlistedDeps.filter(issue =>
			issue.type === "unlisted" && (issue.name === "npm" || issue.name === "jsr") && issue.file && issue.line,
		);
		if (candidates.length === 0) return result;
		const groups = new Map<string, { config: string; imports: { issue: KnipIssue; file: string; content: string; specifier: string; boundary: [string, boolean][] }[] }>();
		try {
			const { parse, Lang } = await loadAstGrepNapi();
			const root = fs.realpathSync(targetDir);
			for (const issue of candidates) {
				try {
					const file = fs.realpathSync(path.resolve(targetDir, issue.file!));
					const relative = path.relative(root, file);
					if (relative.startsWith("..") || path.isAbsolute(relative)) continue;
					let dir = path.dirname(file);
					let configPath: string | undefined;
					const boundary: [string, boolean][] = [];
					while (true) {
						for (const marker of ["deno.json", "deno.jsonc", "package.json"]) { const markerPath = path.join(dir, marker); boundary.push([markerPath, fs.existsSync(markerPath)]); }
						configPath = ["deno.json", "deno.jsonc"].map(name => path.join(dir, name)).find(candidate => fs.existsSync(candidate));
						if (configPath || fs.existsSync(path.join(dir, "package.json")) || dir === root) break;
						dir = path.dirname(dir);
					}
					if (!configPath) continue;
					const content = fs.readFileSync(file, "utf-8");
					const ast = parse(file.endsWith(".tsx") ? Lang.Tsx : Lang.TypeScript, content).root();
					if (ast.find({ rule: { kind: "ERROR" } })) continue;
					const imports = ast.findAll({ rule: { any: [{ kind: "import_statement" }, { kind: "export_statement" }] } })
						.filter(node => node.range().start.line + 1 <= issue.line! && node.range().end.line + 1 >= issue.line!)
						.map(node => node.field("source")?.text()).filter((text): text is string => !!text);
					if (imports.length !== 1) continue;
					const specifier = imports[0].slice(1, -1);
					if (!specifier.startsWith(`${issue.name}:`) || /[\\\s]/.test(specifier)) continue;
					let group = groups.get(configPath);
					if (!group) {
						group = { config: fs.readFileSync(configPath, "utf-8"), imports: [] };
						groups.set(configPath, group);
					}
					group.imports.push({ issue, file, content, specifier, boundary });
				} catch { /* Unreadable or malformed source cannot justify removal. */ }
			}
		} catch { return result; }

		const resolved = new Set<KnipIssue>();
		const deadline = Date.now() + ANALYSIS_TIMEOUT_MS;
		for (const [configPath, group] of groups) {
			const remaining = deadline - Date.now();
			if (remaining <= 0) break;
			const imports = [...new Set(group.imports.map(item => item.specifier))];
			const entrypoint = `data:application/typescript,${encodeURIComponent(imports.map(specifier => `import ${JSON.stringify(specifier)};`).join("\n"))}`;
			try {
				const validation = await safeSpawnAsync("deno", ["info", "--no-lock", "--node-modules-dir=none", "--json", "--config", configPath, entrypoint], { cwd: targetDir, timeout: remaining });
				if (validation.error || validation.status !== 0) continue;
				const graph = JSON.parse(validation.stdout ?? "");
				const hasError = (value: unknown): boolean => !!value && typeof value === "object" && Object.entries(value).some(([key, child]) => key === "error" || hasError(child));
				if (!Array.isArray(graph.modules) || graph.modules.length === 0 || !graph.roots?.includes(entrypoint) || hasError(graph)) continue;
				if (fs.readFileSync(configPath, "utf-8") !== group.config) continue;
				for (const item of group.imports) {
					if (fs.readFileSync(item.file, "utf-8") === item.content && fs.realpathSync(path.resolve(targetDir, item.issue.file!)) === item.file && item.boundary.every(([marker, existed]) => fs.existsSync(marker) === existed)) resolved.add(item.issue);
				}
			} catch { /* Failed validation is not evidence that an import is clean. */ }
		}
		if (resolved.size === 0) return result;
		const issues = result.issues.filter(issue => !resolved.has(issue));
		return { ...result, issues, unlistedDeps: result.unlistedDeps.filter(issue => !resolved.has(issue)), summary: `Found ${issues.length} issues` };
	}

	/**
	 * Drop `dependency`/`devDependency` issues for a package that's also
	 * referenced as an npm `overrides` (or Yarn `resolutions` / pnpm
	 * `pnpm.overrides`) key in this project's `package.json` (#968).
	 *
	 * A direct devDependency whose only job is pinning a vulnerable
	 * transitive/peer resolution has no source import — that's WORKING AS
	 * INTENDED, not dead code, and knip has no concept of "this dependency
	 * exists only to satisfy an overrides entry" (it only sees imports).
	 * `overrides`/`resolutions` are the project's own explicit, unambiguous
	 * signal that the package is deliberately present — the same class of
	 * signal `hardcoded-url`'s `SCREAMING_SNAKE_CASE` constant-name carve-out
	 * and `ts-ssrf`'s constant-identifier carve-out lean on elsewhere in this
	 * codebase — so this narrows the finding rather than suppressing
	 * `dependency`/`devDependency` issues wholesale: a devDependency that
	 * ISN'T also an overrides/resolutions key is still reported.
	 */
	private dropOverridePinnedDeps(
		result: KnipResult,
		targetDir: string,
	): KnipResult {
		if (result.unusedDeps.length === 0) return result;
		const pinned = readOverridePinnedPackageNames(targetDir);
		if (pinned.size === 0) return result;

		const isPinnedDepIssue = (issue: KnipIssue): boolean =>
			(issue.type === "dependency" || issue.type === "devDependency") &&
			(pinned.has(issue.name) || (!!issue.package && pinned.has(issue.package)));

		const issues = result.issues.filter((issue) => !isPinnedDepIssue(issue));
		const unusedDeps = result.unusedDeps.filter(
			(issue) => !isPinnedDepIssue(issue),
		);
		return unusedDeps.length === result.unusedDeps.length
			? result
			: { ...result, issues, unusedDeps };
	}

	/**
	 * Find unused exports in a specific file
	 */
	async findUnusedExports(filePath: string): Promise<string[]> {
		const result = await this.analyze(path.dirname(filePath));
		const basename = path.basename(filePath);

		return result.unusedExports
			.filter((e) => e.file?.includes(basename))
			.map((e) => e.name);
	}

	/**
	 * Format results for LLM consumption. Delegates to the pure
	 * `formatKnipResult` so callers (e.g. turn-end) can format without a live
	 * client instance.
	 */
	formatResult(result: KnipResult, maxItems = 20): string {
		return formatKnipResult(result, maxItems);
	}

	// --- Internal ---

	private parseOutput(output: string): KnipResult {
		try {
			const data = JSON.parse(output);
			const issues: KnipIssue[] = [];
			const unusedExports: KnipIssue[] = [];
			const unusedFiles: KnipIssue[] = [];
			const unusedDeps: KnipIssue[] = [];
			const unlistedDeps: KnipIssue[] = [];

			const addIssue = (issue: KnipIssue) => {
				issues.push(issue);
				if (issue.type === "export" || issue.type === "enumMember") {
					unusedExports.push(issue);
				}
				if (issue.type === "file") unusedFiles.push(issue);
				if (issue.type === "dependency" || issue.type === "devDependency") {
					unusedDeps.push(issue);
				}
				if (issue.type === "unlisted" || issue.type === "bin") {
					unlistedDeps.push(issue);
				}
			};

			// Knip JSON format (grouped): { issues: [ { file, exports:[], files:[], dependencies:[], ... } ] }
			const fileEntries: any[] = Array.isArray(data?.issues) ? data.issues : [];

			for (const entry of fileEntries) {
				const file: string = entry.file ?? "";

				const push = (
					arr: any[],
					type: KnipIssue["type"],
					_target: KnipIssue[],
				) => {
					for (const item of arr) {
						addIssue({
							type,
							name: item.name ?? item.symbol ?? String(item),
							file,
							line: item.line,
							package: item.package,
						});
					}
				};

				push(entry.exports ?? [], "export", unusedExports);
				push(entry.types ?? [], "export", unusedExports);
				push(entry.enumMembers ?? [], "enumMember", unusedExports);
				push(entry.files ?? [], "file", unusedFiles);
				push(entry.dependencies ?? [], "dependency", unusedDeps);
				push(entry.devDependencies ?? [], "devDependency", unusedDeps);
				push(entry.unlisted ?? [], "unlisted", unlistedDeps);
				push(entry.binaries ?? [], "bin", unlistedDeps);
			}

			// Fallback format: flat list of issue objects
			if (issues.length === 0 && Array.isArray(data)) {
				for (const item of data) {
					if (!item || typeof item !== "object") continue;
					const rawType = String(
						item.type ?? item.issueType ?? item.kind ?? "file",
					).toLowerCase();
					const type: KnipIssue["type"] =
						rawType === "export" || rawType === "exports"
							? "export"
							: rawType === "dependency"
								? "dependency"
								: rawType === "devdependency"
									? "devDependency"
									: rawType === "unlisted"
										? "unlisted"
										: rawType === "bin" || rawType === "binaries"
											? "bin"
											: "file";
					addIssue({
						type,
						name: String(
							item.name ??
								item.symbol ??
								item.package ??
								item.message ??
								"unknown",
						),
						file: item.file ?? item.path ?? item.location?.file,
						line: item.line ?? item.location?.line,
						package: item.package,
					});
				}
			}

			return {
				success: true,
				issues,
				unusedExports,
				unusedFiles,
				unusedDeps,
				unlistedDeps,
				summary: `Found ${issues.length} issues`,
			};
		} catch (err) {
			void err;
			this.log("Failed to parse knip JSON output");
			return {
				...EMPTY_RESULT,
				summary: "Failed to parse output",
			};
		}
	}
}

/**
 * Format a KnipResult for the agent (the FULL dead-code picture: all unused
 * exports/members, files, and deps — not a delta). Pure: no client instance or
 * `this`, so turn-end can surface findings without depending on the injected
 * client exposing the method. Returns "" when there is nothing to report.
 * Unlisted deps are intentionally omitted here — they're surfaced as a
 * delta-gated blocker (newly broken imports), not as cleanup advice.
 */
export function formatKnipResult(result: KnipResult, maxItems = 20): string {
	if (!result.success) return `[Knip] ${result.summary}`;
	if (result.issues.length === 0) return "";

	let output = `[Knip] ${result.issues.length} issue(s)`;
	if (result.unusedExports.length)
		output += ` — ${result.unusedExports.length} unused export(s)`;
	if (result.unusedFiles.length)
		output += ` — ${result.unusedFiles.length} unused file(s)`;
	if (result.unusedDeps.length)
		output += ` — ${result.unusedDeps.length} unused dep(s)`;
	if (result.unlistedDeps.length)
		output += ` — ${result.unlistedDeps.length} unlisted dep(s)`;
	output += ":\n";

	// Show unused exports first (most useful for refactoring)
	if (result.unusedExports.length > 0) {
		output += "\n  Unused exports:\n";
		for (const issue of result.unusedExports.slice(0, maxItems)) {
			const loc = issue.file ? ` (${path.basename(issue.file)})` : "";
			output += `    - ${issue.name}${loc}\n`;
		}
		if (result.unusedExports.length > maxItems) {
			output += `    ... and ${result.unusedExports.length - maxItems} more\n`;
		}
	}

	// Show unused files
	if (result.unusedFiles.length > 0) {
		output += "\n  Unused files:\n";
		for (const issue of result.unusedFiles.slice(0, 10)) {
			output += `    - ${issue.name}\n`;
		}
	}

	// Show unused deps (might be worth removing)
	if (result.unusedDeps.length > 0) {
		output += "\n  Unused dependencies:\n";
		for (const issue of result.unusedDeps) {
			output += `    - ${issue.package || issue.name}\n`;
		}
	}

	return output;
}
