#!/usr/bin/env node

// The CLI flushes the snapshot explicitly and verifies the write — a user
// debounce (especially 0) races the fire-and-forget background writer and can
// consume the pending payload before our flush sees it (#943 review). The
// builder reads this env lazily on every persist, so forcing it here (before
// any build runs; import hoisting is irrelevant) keeps the queued payload in
// place for flushReviewGraphPersist to claim.
process.env.PI_LENS_GRAPH_PERSIST_DEBOUNCE_MS = "3600000";

import * as fs from "node:fs";
import * as path from "node:path";
import { FactStore } from "../clients/dispatch/fact-store.js";
import {
	buildOrUpdateGraph,
	flushReviewGraphPersist,
	getLastGraphBuildInfo,
	getLastReviewGraphBuildAttempt,
	reviewGraphCachePath,
} from "../clients/review-graph/builder.js";
import { runDiagnostics } from "./diagnostics-cli.js";

function cwdArg(): string {
	return valueArg("--cwd") ?? process.cwd();
}

function valueArg(name: string): string | undefined {
	const equals = process.argv.find((arg) => arg.startsWith(`${name}=`));
	if (equals) return equals.slice(name.length + 1);
	const index = process.argv.indexOf(name);
	if (index < 0) return undefined;
	const value = process.argv[index + 1];
	if (!value || value.startsWith("-"))
		throw new Error(`${name} requires a value`);
	return value;
}

function positiveIntArg(name: string): number | undefined {
	const raw = valueArg(name);
	if (raw === undefined) return undefined;
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error(`${name} requires a positive integer`);
	}
	return value;
}

/** Sentinel so main()'s catch doesn't double-print a reason fail() already wrote. */
const FAILED = Symbol("pi-lens-cli-failed");
let activeCommand = "build-graph";

// Soft-fail: write the reason, set the exit code, and let the event loop
// drain naturally. A hard process.exit(1) here aborted with a libuv
// assertion on Windows whenever async fs handles (log appends) were still
// live (#943 review finding 3). Exit hooks (persist teardown, log flushSync)
// still run on natural exit.
function fail(reason: string, exitCode = 1): never {
	process.stderr.write(`pi-lens ${activeCommand} failed: ${reason}\n`);
	process.exitCode = exitCode;
	throw FAILED;
}

async function buildGraph(): Promise<void> {
	const cwd = path.resolve(cwdArg());
	let stat: fs.Stats;
	try {
		stat = fs.statSync(cwd);
	} catch (err) {
		fail(`cannot access cwd ${cwd}: ${(err as Error).message}`);
	}
	if (!stat.isDirectory()) fail(`cwd is not a directory: ${cwd}`);

	const startedAt = Date.now();
	const graph = await buildOrUpdateGraph(cwd, [], new FactStore());
	const attempt = getLastReviewGraphBuildAttempt(cwd);
	// "succeeded" can still carry a `reason` string — persistGraph() stamps one
	// on to explain a partial (over-cap) persist, which is NOT a failure (#960
	// made a capped persist honest-but-successful). Only "failed"/"skipped"
	// (unsafe_root, source-file cap, thrown build error) are real failures; a
	// benign reason on a succeeded build is surfaced later via coverage
	// instead of being treated as fatal here.
	if (!attempt || attempt.outcome !== "succeeded") {
		fail(attempt?.reason ?? attempt?.outcome ?? "build produced no result");
	}

	const persisted = flushReviewGraphPersist(cwd);
	if (!persisted.ok) {
		// An unchanged repo queues no persist — the disk-cache hit and the
		// pure-drift incremental path both deliberately skip rewriting the
		// blob. That is SUCCESS for a scheduled build (#943 review finding 1:
		// a nightly cron on a quiet repo must not fail every run), provided
		// the snapshot actually exists on disk.
		const buildInfo = getLastGraphBuildInfo();
		const snapshotPath = reviewGraphCachePath(cwd);
		if (!buildInfo.graphChanged && fs.existsSync(snapshotPath)) {
			const bytes = fs.statSync(snapshotPath).size;
			const durationMs = Date.now() - startedAt;
			process.stdout.write(
				`pi-lens build-graph: snapshot already current (mode=${buildInfo.mode}) ` +
					`files=${graph.fileNodes.size} nodes=${graph.nodes.size} ` +
					`edges=${graph.edges.length} jsonBytes=${bytes} durationMs=${durationMs}\n`,
			);
			return;
		}
		fail(persisted.reason ?? "graph snapshot was not persisted");
	}

	const durationMs = Date.now() - startedAt;
	const coverage = persisted.coverage;
	if (coverage?.partial) {
		// #533/#936 honesty: an over-cap build DID succeed and DID persist, but
		// only a subgraph — say so plainly instead of printing the same line a
		// full build would, which would silently misrepresent a capped repo as
		// fully covered.
		process.stdout.write(
			`pi-lens build-graph: PARTIAL persist (cap=${coverage.cap} exceeded) ` +
				`files=${graph.fileNodes.size} nodes=${graph.nodes.size} ` +
				`edges=${graph.edges.length} persistedNodes=${coverage.persistedNodes}/${coverage.totalNodes} ` +
				`persistedEdges=${coverage.persistedEdges}/${coverage.totalEdges} ` +
				`elements=${persisted.elements} jsonBytes=${persisted.bytes} durationMs=${durationMs}\n`,
		);
		return;
	}
	process.stdout.write(
		`pi-lens build-graph: files=${graph.fileNodes.size} nodes=${graph.nodes.size} ` +
			`edges=${graph.edges.length} elements=${persisted.elements} ` +
			`jsonBytes=${persisted.bytes} durationMs=${durationMs}\n`,
	);
}

async function diagnostics(): Promise<void> {
	const cwd = path.resolve(cwdArg());
	let stat: fs.Stats;
	try {
		stat = fs.statSync(cwd);
	} catch (err) {
		fail(`cannot access cwd ${cwd}: ${(err as Error).message}`, 2);
	}
	if (!stat.isDirectory()) fail(`cwd is not a directory: ${cwd}`, 2);

	const format = valueArg("--format") ?? "text";
	if (format !== "text" && format !== "json") {
		fail("--format must be text or json", 2);
	}
	const result = await runDiagnostics(cwd, {
		maxLspFiles: positiveIntArg("--max-lsp-files"),
		maxProjectFiles: positiveIntArg("--max-project-files"),
	});
	process.stdout.write(
		format === "json"
			? `${JSON.stringify({ cwd, ...result })}\n`
			: `${result.text}\n`,
	);
	process.exitCode = result.exitCode;
}

async function main(): Promise<void> {
	activeCommand = process.argv[2] ?? "cli";
	if (activeCommand === "build-graph") return buildGraph();
	if (activeCommand === "diagnostics") return diagnostics();
	fail(
		"usage: pi-lens build-graph [--cwd <dir>] | pi-lens diagnostics [--cwd <dir>] [--format text|json] [--max-lsp-files N] [--max-project-files N]",
	);
}

main().catch((err) => {
	if (err === FAILED) return;
	process.stderr.write(
		`pi-lens ${activeCommand} failed: ${err instanceof Error ? err.message : String(err)}\n`,
	);
	process.exitCode = 1;
});
