/**
 * #611/#707: classic typescript-language-server tsserver sync diagnostic
 * commands — shared between the `lsp_diagnostics` tool (where the escape hatch
 * was first introduced in #611) and the per-edit `touchFile` dispatch path
 * (wired in #707 to avoid burning the full wait budget on clean TS files).
 *
 * These are a genuine synchronous request/response tsserver protocol extension
 * exposed via `workspace/executeCommand` with command
 * `typescript.tsserverRequest`. Unlike the push-only LSP surface, calling them
 * gives a definitive answer only while both responses stay correlated to one
 * client/document generation and sent version/hash. Empty bodies then mean
 * confirmed clean; non-empty bodies are real diagnostics.
 *
 * Empirically verified live (2026-07, typescript-language-server 5.9.3, this
 * repo's own tsconfig.json as the fixture project):
 *
 *   workspace/executeCommand {
 *     command: "typescript.tsserverRequest",
 *     arguments: [
 *       "semanticDiagnosticsSync" | "syntacticDiagnosticsSync",
 *       { file: "<absolute path>", includeLinePosition: true }
 *     ]
 *   }
 *
 * resolves { executed: true, result: { seq, type: "response", command,
 * request_seq, success, body: [...] } }, where each body entry is tsserver's
 * NATIVE protocol diagnostic shape — `message`, `category`
 * ("error"|"warning"|"suggestion"), `code`, `startLocation`/`endLocation` as
 * `{ line, offset }` — NOT the LSP `Diagnostic` shape, and both `line`/`offset`
 * are 1-based (LSP is 0-based).
 *
 * All helpers here are pure-function and never throw (every error path returns
 * `undefined`). The caller must handle `undefined` as "sync path unavailable,
 * fall back to existing unconfirmed/timed-out behavior".
 */

import type { LSPDiagnostic, LSPDocumentSnapshot } from "./client.js";
import { normalizeMapKey, uriToPath } from "../path-utils.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TsserverSyncRawDiagnostic {
	message: string;
	category: string;
	code?: number;
	startLocation?: { line: number; offset: number };
	endLocation?: { line: number; offset: number };
}

/** Minimal LSP-service-shaped interface this module needs — avoids importing
 * the full LSPService class and keeps the extracted module test-friendly. */
export interface TsserverSyncCapableService {
	getAdvertisedCommands?: (filePath?: string) => Promise<string[]>;
	getDocumentSnapshot?: (
		filePath: string,
	) => Promise<LSPDocumentSnapshot | undefined>;
	executeCommand?: (
		filePath: string | undefined,
		command: string,
		args?: unknown[],
	) => Promise<{ executed: boolean; result?: unknown; reason?: string }>;
}

export interface TsserverSyncCommandReceipt {
	command: "semanticDiagnosticsSync" | "syntacticDiagnosticsSync";
	requestSeq: number;
	diagnostics: TsserverSyncRawDiagnostic[];
}

export interface TsserverSyncConfirmation {
	diagnostics: LSPDiagnostic[];
	binding: { version: number; contentHash: string };
	attribution: {
		clientInstanceId: string;
		filePath: string;
		uri: string;
		documentGeneration: number;
		semanticRequestSeq: number;
		syntacticRequestSeq: number;
	};
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const TSSERVER_REQUEST_COMMAND = "typescript.tsserverRequest";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function isTsserverSyncRawDiagnostic(
	value: unknown,
): value is TsserverSyncRawDiagnostic {
	if (!value || typeof value !== "object") return false;
	const v = value as Record<string, unknown>;
	return typeof v.message === "string" && typeof v.category === "string";
}

export function tsserverSeverityFromCategory(category: string): 1 | 2 | 3 | 4 {
	switch (category) {
		case "error":
			return 1;
		case "warning":
			return 2;
		case "suggestion":
			return 4; // Hint
		default:
			return 3; // "message" or unrecognized -> Info
	}
}

/**
 * Convert a tsserver-protocol sync diagnostic into pi-lens's LSP-shaped
 * `LSPDiagnostic`. Both `line`/`offset` are 1-based in tsserver's protocol
 * and 0-based in LSP — this conversion handles that.
 */
export function tsserverSyncDiagnosticToLsp(
	d: TsserverSyncRawDiagnostic,
): LSPDiagnostic {
	const startLine = Math.max(0, (d.startLocation?.line ?? 1) - 1);
	const startChar = Math.max(0, (d.startLocation?.offset ?? 1) - 1);
	const endLine = Math.max(
		0,
		(d.endLocation?.line ?? d.startLocation?.line ?? 1) - 1,
	);
	const endChar = Math.max(
		0,
		(d.endLocation?.offset ?? d.startLocation?.offset ?? 1) - 1,
	);
	return {
		severity: tsserverSeverityFromCategory(d.category),
		message: d.message,
		range: {
			start: { line: startLine, character: startChar },
			end: { line: endLine, character: endChar },
		},
		code: d.code,
		source: "typescript",
	};
}

/**
 * The awaited executeCommand promise is the primary attribution: JSON-RPC
 * correlates the outer response to this call, and typescript-language-server
 * correlates its inner tsserver response by request sequence. Command and
 * sequence checks below validate that transport result; they do not replace it.
 * A malformed body stays unavailable instead of being filtered into false clean.
 */
export async function runTsserverSyncCommand(
	svc: TsserverSyncCapableService,
	file: string,
	command: "semanticDiagnosticsSync" | "syntacticDiagnosticsSync",
): Promise<TsserverSyncCommandReceipt | undefined> {
	if (typeof svc.executeCommand !== "function") return undefined;
	const outcome = await svc.executeCommand(file, TSSERVER_REQUEST_COMMAND, [
		command,
		{ file, includeLinePosition: true },
	]);
	if (!outcome.executed) return undefined;
	const result = outcome.result as
		| {
				type?: unknown;
				command?: unknown;
				request_seq?: unknown;
				success?: boolean;
				body?: unknown;
		  }
		| undefined;
	if (
		!result ||
		result.type !== "response" ||
		result.command !== command ||
		!Number.isInteger(result.request_seq) ||
		(result.request_seq as number) < 0 ||
		result.success !== true ||
		!Array.isArray(result.body) ||
		!result.body.every(isTsserverSyncRawDiagnostic)
	) return undefined;
	return {
		command,
		requestSeq: result.request_seq as number,
		diagnostics: result.body,
	};
}

function snapshotsMatch(
	file: string,
	left: LSPDocumentSnapshot | undefined,
	right: LSPDocumentSnapshot | undefined,
): left is LSPDocumentSnapshot {
	if (!left || !right) return false;
	const expected = normalizeMapKey(file);
	return (
		normalizeMapKey(left.filePath) === expected &&
		normalizeMapKey(uriToPath(left.uri)) === expected &&
		left.clientInstanceId === right.clientInstanceId &&
		left.filePath === right.filePath &&
		left.uri === right.uri &&
		left.documentGeneration === right.documentGeneration &&
		left.version === right.version &&
		left.contentHash === right.contentHash
	);
}

/**
 * #611/#707: attempt classic typescript-language-server's
 * `typescript.tsserverRequest` escape hatch — a genuine synchronous
 * request/response tsserver command, not push/timing-dependent — to get a
 * definitive answer for a Tier-3 silent server's empty push-based result.
 * Runs BOTH `semanticDiagnosticsSync` and `syntacticDiagnosticsSync`
 * (mirroring what the server itself publishes on a dirty file) so a
 * syntax-only error isn't missed.
 *
 * Returns `undefined` (never throws, never hangs beyond the existing
 * `executeCommand` anti-deadlock backstop) when: the command isn't advertised
 * by this server (older/different server/config), `executeCommand` throws
 * (live-verified case: tsserver rejects with a `ResponseError` — "No
 * Project." — for a file outside any tsconfig project) or times out, or the
 * response shape isn't the expected `{success:true, body:[...]}` envelope.
 * Every one of these must fall through to the existing "unconfirmed" behavior
 * in the caller.
 *
 * Empty diagnostics are confirmed clean only when the client identity, file URI,
 * document generation, sent version/hash, response commands, and increasing
 * inner request sequence remain stable across both awaited responses. Any drift
 * returns undefined and preserves the caller's unconfirmed result.
 */
export async function attemptTsserverSyncConfirmation(
	file: string,
	svc: TsserverSyncCapableService,
): Promise<TsserverSyncConfirmation | undefined> {
	try {
		if (
			typeof svc.getAdvertisedCommands !== "function" ||
			typeof svc.getDocumentSnapshot !== "function"
		) return undefined;
		const advertised = await svc.getAdvertisedCommands(file);
		if (!advertised.includes(TSSERVER_REQUEST_COMMAND)) return undefined;

		const before = await svc.getDocumentSnapshot(file);
		const semantic = await runTsserverSyncCommand(
			svc,
			file,
			"semanticDiagnosticsSync",
		);
		const afterSemantic = await svc.getDocumentSnapshot(file);
		const syntactic = await runTsserverSyncCommand(
			svc,
			file,
			"syntacticDiagnosticsSync",
		);
		const afterSyntactic = await svc.getDocumentSnapshot(file);
		if (semantic === undefined || syntactic === undefined) return undefined;
		if (
			!snapshotsMatch(file, before, afterSemantic) ||
			!snapshotsMatch(file, before, afterSyntactic) ||
			syntactic.requestSeq <= semantic.requestSeq
		) return undefined;

		return {
			diagnostics: [
				...syntactic.diagnostics,
				...semantic.diagnostics,
			].map(tsserverSyncDiagnosticToLsp),
			binding: {
				version: before.version,
				contentHash: before.contentHash,
			},
			attribution: {
				clientInstanceId: before.clientInstanceId,
				filePath: before.filePath,
				uri: before.uri,
				documentGeneration: before.documentGeneration,
				semanticRequestSeq: semantic.requestSeq,
				syntacticRequestSeq: syntactic.requestSeq,
			},
		};
	} catch {
		return undefined;
	}
}

export async function attemptTsserverSyncDiagnostics(
	file: string,
	svc: TsserverSyncCapableService,
): Promise<LSPDiagnostic[] | undefined> {
	return (await attemptTsserverSyncConfirmation(file, svc))?.diagnostics;
}
