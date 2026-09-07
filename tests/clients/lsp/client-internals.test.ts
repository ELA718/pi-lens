/**
 * LSP Client Internals Tests
 *
 * Tests clientWaitForDiagnostics, handleNotifyOpen, and handleNotifyChange
 * directly with mock LSPClientState to avoid spawning real language servers.
 */

import { EventEmitter } from "node:events";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import type { MessageConnection } from "vscode-jsonrpc";
import {
	applyDynamicCapabilities,
	CLIENT_CAPABILITIES,
	clientRequestWorkspaceDiagnostics,
	clearDiagnosticsForPath,
	clientShutdown,
	clientWaitForDiagnostics,
	closeDocument,
	normalizeClientWorkspaceEdit,
	handleNotifyChange,
	navRequest,
	resolveConfigurationSection,
	runServerCommand,
	setupIncomingHandlers,
	stripDiagnosticNoiseLines,
	handleNotifyOpen,
	type LSPClientState,
	type LSPDiagnostic,
} from "../../../clients/lsp/client.js";
import { normalizeMapKey } from "../../../clients/path-utils.js";
import { hashDiagnosticContent } from "../../../clients/lsp/diagnostic-binding.js";
import { WatchedFilesQueue } from "../../../clients/lsp/watch-queue.js";
import { applyWorkspaceEdit } from "../../../clients/lsp/edits.js";

const TEST_FILE = "/project/app.ts";
const TEST_KEY = normalizeMapKey(TEST_FILE);

describe("CLIENT_CAPABILITIES (#278 regression)", () => {
	// PowerShell Editor Services (OmniSharp.Extensions.LanguageServer) NPEs during
	// `initialize` when textDocument sub-capabilities it dereferences are absent —
	// a partial object hangs the handshake. Keep the set COMPLETE so PSES (and any
	// OmniSharp-based server) initializes.
	it("advertises a complete, spec-compliant textDocument capability set", () => {
		const td = CLIENT_CAPABILITIES.textDocument as Record<string, unknown>;
		for (const key of [
			"synchronization",
			"completion",
			"hover",
			"signatureHelp",
			"definition",
			"typeDefinition",
			"implementation",
			"references",
			"documentSymbol",
			"codeAction",
			"rename",
			"publishDiagnostics",
			"diagnostic",
		]) {
			expect(td[key], `textDocument.${key} present`).toBeTypeOf("object");
		}
		// The old NON-STANDARD shape that triggered the NPE must not return:
		// didOpen/didChange are not TextDocumentSyncClientCapabilities fields.
		const sync = td.synchronization as Record<string, unknown>;
		expect(sync).not.toHaveProperty("didOpen");
		expect(sync).not.toHaveProperty("didChange");
		// Version-aware diagnostics (#240/#276) must stay advertised.
		expect(
			(CLIENT_CAPABILITIES.textDocument.publishDiagnostics as { versionSupport?: boolean })
				.versionSupport,
		).toBe(true);
		expect(CLIENT_CAPABILITIES.textDocument.diagnostic).toEqual({
			dynamicRegistration: false,
			relatedDocumentSupport: true,
		});
	});
});

describe("client workspace edit normalization", () => {
	it("normalizes a rename-then-descendant edit against virtual post-resource content", async () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-client-edit-"));
		const oldDir = path.join(root, "oldDir");
		const newDir = path.join(root, "newDir");
		const oldFile = path.join(oldDir, "file.ts");
		const newFile = path.join(newDir, "file.ts");
		fs.mkdirSync(oldDir);
		fs.writeFileSync(oldFile, "const café = 1;\n", "utf-8");
		const state = createMockState({ root, positionEncoding: "utf-8" });
		const edit = {
			documentChanges: [
				{
					kind: "rename",
					oldUri: pathToFileURL(oldDir).href,
					newUri: pathToFileURL(newDir).href,
				},
				{
					textDocument: { uri: pathToFileURL(newFile).href },
					edits: [{
						range: {
							start: { line: 0, character: 14 },
							end: { line: 0, character: 15 },
						},
						newText: "2",
					}],
				},
			],
		};

		try {
			const normalized = await normalizeClientWorkspaceEdit(state, edit);
			const textChange = (normalized.documentChanges?.[1] as { edits: Array<{ range: { start: { character: number }; end: { character: number } } }> }).edits[0];
			expect(textChange.range.start.character).toBe(13);
			expect(textChange.range.end.character).toBe(14);
			await applyWorkspaceEdit(normalized, root);
			expect(fs.readFileSync(newFile, "utf-8")).toBe("const café = 2;\n");
			expect(fs.existsSync(oldDir)).toBe(false);
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});

	it.each(["utf-8", "utf-32"] as const)(
		"preserves duplicate zero-width edits during %s normalization",
		async (positionEncoding) => {
			const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-client-edit-"));
			const filePath = path.join(root, "file.ts");
			fs.writeFileSync(filePath, "a\n", "utf-8");
			const state = createMockState({ root, positionEncoding });
			try {
				const normalized = await normalizeClientWorkspaceEdit(state, {
					documentChanges: [{
						textDocument: { uri: pathToFileURL(filePath).href },
						edits: [
							{ range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } }, newText: "x" },
							{ range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } }, newText: "x" },
						],
					}],
				});
				const textChange = normalized.documentChanges?.[0] as { edits: unknown[] };
				expect(textChange.edits).toHaveLength(2);
				await applyWorkspaceEdit(normalized, root);
				expect(fs.readFileSync(filePath, "utf-8")).toBe("xxa\n");
			} finally {
				fs.rmSync(root, { recursive: true, force: true });
			}
		},
	);

	it.each(["utf-8", "utf-32"] as const)(
		"supports delete-create-text ordering during %s normalization",
		async (positionEncoding) => {
			const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-client-edit-"));
			const filePath = path.join(root, "file.ts");
			fs.writeFileSync(filePath, "old\n", "utf-8");
			const state = createMockState({ root, positionEncoding });
			try {
				const normalized = await normalizeClientWorkspaceEdit(state, {
					documentChanges: [
						{ kind: "delete", uri: pathToFileURL(filePath).href },
						{ kind: "create", uri: pathToFileURL(filePath).href },
						{
							textDocument: { uri: pathToFileURL(filePath).href },
							edits: [{
								range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
								newText: "new\n",
							}],
						},
					],
				});
				await applyWorkspaceEdit(normalized, root);
				expect(fs.readFileSync(filePath, "utf-8")).toBe("new\n");
			} finally {
				fs.rmSync(root, { recursive: true, force: true });
			}
		},
	);

	// P1-3: the tool apply paths (rename apply:true, code-action autofix) call
	// applyWorkspaceEdit WITHOUT a documentVersions map. normalizeClientWorkspaceEdit
	// must validate the version against the live map and then STRIP it (spec null =
	// don't check), so the downstream apply succeeds for version-stamping servers
	// (gopls) instead of failing 100% on "stale text document version".
	it("strips versions after validating them so tool apply paths succeed", async () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-client-edit-"));
		const filePath = path.join(root, "file.ts");
		fs.writeFileSync(filePath, "old\n", "utf-8");
		const state = createMockState({ root, positionEncoding: "utf-16" });
		state.documentVersions.set(normalizeMapKey(filePath), 7);
		try {
			const normalized = await normalizeClientWorkspaceEdit(state, {
				documentChanges: [{
					textDocument: { uri: pathToFileURL(filePath).href, version: 7 },
					edits: [{ range: { start: { line: 0, character: 0 }, end: { line: 0, character: 3 } }, newText: "new" }],
				}],
			});
			const textDocument = (normalized.documentChanges?.[0] as { textDocument: { version: unknown } }).textDocument;
			expect(textDocument.version).toBeNull();
			// No documentVersions passed — mirrors the real tool apply sites.
			await applyWorkspaceEdit(normalized, root);
			expect(fs.readFileSync(filePath, "utf-8")).toBe("new\n");
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});

	it("still rejects a stale version at normalize time (validation intact)", async () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-client-edit-"));
		const filePath = path.join(root, "file.ts");
		fs.writeFileSync(filePath, "old\n", "utf-8");
		const state = createMockState({ root, positionEncoding: "utf-16" });
		state.documentVersions.set(normalizeMapKey(filePath), 1);
		try {
			await expect(normalizeClientWorkspaceEdit(state, {
				documentChanges: [{
					textDocument: { uri: pathToFileURL(filePath).href, version: 9 },
					edits: [{ range: { start: { line: 0, character: 0 }, end: { line: 0, character: 3 } }, newText: "new" }],
				}],
			})).rejects.toThrow(/stale workspace edit document version/);
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});

	it("rejects an invalid UTF-8 range after a virtual rename without mutation", async () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-client-edit-"));
		const oldDir = path.join(root, "oldDir");
		const newDir = path.join(root, "newDir");
		const oldFile = path.join(oldDir, "file.ts");
		const newFile = path.join(newDir, "file.ts");
		fs.mkdirSync(oldDir);
		fs.writeFileSync(oldFile, "const café = 1;\n", "utf-8");
		const state = createMockState({ root, positionEncoding: "utf-8" });

		try {
			// UTF-8 offset 10 falls in the MIDDLE of the two-byte `é` (bytes 9-10 of
			// "const café ..."), a genuinely invalid boundary that must still reject.
			// (A position merely PAST the line end now clamps per LSP 3.17 — see the
			// clamp coverage in edits.test.ts — so this exercises the boundary check,
			// not the removed past-end throw.)
			await expect(normalizeClientWorkspaceEdit(state, {
				documentChanges: [
					{ kind: "rename", oldUri: pathToFileURL(oldDir).href, newUri: pathToFileURL(newDir).href },
					{
						textDocument: { uri: pathToFileURL(newFile).href },
						edits: [{
							range: {
								start: { line: 0, character: 10 },
								end: { line: 0, character: 10 },
							},
							newText: "x",
						}],
					},
				],
			})).rejects.toThrow(/boundary/);
			expect(fs.existsSync(oldFile)).toBe(true);
			expect(fs.existsSync(newFile)).toBe(false);
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});
});

describe("solicited workspace/applyEdit observability", () => {
	it("applies and correlates solicited edits, but refuses unsolicited edits", async () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-lens-apply-edit-"));
		const filePath = path.join(root, "app.ts");
		fs.writeFileSync(filePath, "const old = 1;\n", "utf8");
		const state = createMockState({ root });
		const written: string[] = [];
		state.serverEditsAllowed = 1;
		state.activeMutationDepth = 1;
		state.activeMutationContext = {
			cwd: root,
			correlationId: "apply-edit-1",
			tool: "workspace/applyEdit",
			source: "lsp-edit",
			readGuard: { recordWritten: (file) => written.push(file) },
		};
		setupIncomingHandlers(state, {});
		const calls = vi.mocked(state.connection.onRequest).mock.calls as unknown as Array<
			[string, (...args: unknown[]) => unknown]
		>;
		const handler = calls.find((call) => call[0] === "workspace/applyEdit")?.[1];
		expect(handler).toBeDefined();
		await expect(
			handler!({
			edit: {
				changes: {
					[pathToFileURL(filePath).href]: [
						{
							range: {
								start: { line: 0, character: 6 },
								end: { line: 0, character: 9 },
							},
							newText: "new",
						},
					],
				},
			},
		}),
		).resolves.toMatchObject({ applied: true });
		expect(fs.readFileSync(filePath, "utf8")).toBe("const new = 1;\n");
		expect(written).toEqual([filePath]);
		expect(state.activeMutationContext?.summaryEmitted).toBe(true);
		expect(state.activeMutationContext?.summaryCount).toBe(1);

		// A later solicited request must retain its own terminal summary even
		// when the first request already emitted an empty/success summary.
		fs.writeFileSync(filePath, "const old = 1;\n", "utf8");
		const second = await handler!({
			edit: {
				changes: {
					[pathToFileURL(filePath).href]: [
						{
							range: {
								start: { line: 0, character: 6 },
								end: { line: 0, character: 9 },
							},
							newText: "second",
						},
					],
				},
			},
		});
		await expect(Promise.resolve(second)).resolves.toMatchObject({ applied: true });
		expect(fs.readFileSync(filePath, "utf8")).toBe("const second = 1;\n");
		expect(state.activeMutationContext?.summaryCount).toBe(2);

		fs.writeFileSync(filePath, "const old = 1;\n", "utf8");
		state.serverEditsAllowed = 0;
		const refused = await handler!({
			edit: {
				changes: {
					[pathToFileURL(filePath).href]: [],
				},
			},
		});
		expect(refused).toEqual({ applied: false, failureReason: "edit not solicited" });
		expect(fs.readFileSync(filePath, "utf8")).toBe("const old = 1;\n");
		fs.rmSync(root, { recursive: true, force: true });
	});
});

describe("workDoneProgress capability (#974)", () => {
	// pi-lens never consumes `$/progress` notifications, so advertising
	// window.workDoneProgress only invites servers to open progress tokens
	// that go nowhere — and opengrep's `--experimental` LSP mode crash-loops
	// when it can't parse pi-lens's spec-correct `{"result": null}` reply to
	// the `window/workDoneProgress/create` request that capability solicits.
	it("does not advertise window.workDoneProgress", () => {
		expect(CLIENT_CAPABILITIES.window).not.toHaveProperty("workDoneProgress");
	});

	it("still answers an unsolicited window/workDoneProgress/create request without throwing", async () => {
		const state = createMockState();
		setupIncomingHandlers(state, {});

		const onRequest = vi.mocked(state.connection.onRequest);
		const calls = onRequest.mock.calls as unknown as Array<
			[string, (...args: unknown[]) => unknown]
		>;
		const registered = calls.find(
			(c) => c[0] === "window/workDoneProgress/create",
		);
		expect(registered, "handler registered as a defensive no-op").toBeDefined();

		const handler = registered![1];
		await expect(
			handler({ token: "some-progress-token" }),
		).resolves.toBeUndefined();
	});
});

function createMockConnection(): MessageConnection {
	return {
		sendNotification: vi.fn().mockResolvedValue(undefined),
		sendRequest: vi.fn().mockResolvedValue(undefined),
		onNotification: vi.fn(),
		onRequest: vi.fn().mockResolvedValue(undefined),
		onError: vi.fn(),
		onClose: vi.fn(),
		listen: vi.fn(),
		dispose: vi.fn(),
	} as unknown as MessageConnection;
}

function createMockLspProcess() {
	return {
		pid: 12345,
		process: { killed: false, kill: vi.fn() } as unknown as NodeJS.Process,
		stdin: {
			on: vi.fn(),
			off: vi.fn(),
			write: vi.fn(),
		} as unknown as NodeJS.WritableStream,
		stdout: {
			on: vi.fn(),
			off: vi.fn(),
			pipe: vi.fn(),
		} as unknown as NodeJS.ReadableStream,
		stderr: { on: vi.fn(), off: vi.fn() } as unknown as NodeJS.ReadableStream,
	};
}

function createMockState(overrides?: Partial<LSPClientState>): LSPClientState {
	const diagnosticEmitter = new EventEmitter();
	diagnosticEmitter.setMaxListeners(50);
	const state: LSPClientState = {
		isConnected: true,
		isDestroyed: false,
		shutdownRequested: false,
		exitedAt: undefined,
		connectionDisposed: false,
		lastError: undefined,
		connection: createMockConnection(),
		pushDiagnostics: new Map(),
		pushDiagnosticTimestamps: new Map(),
		documentPullDiagnostics: new Map(),
		documentPullDiagnosticTimestamps: new Map(),
		pullFailureHistory: [],
		diagnosticComputationErrors: new Map(),
		pendingDiagnostics: new Map(),
		diagnosticPublicationCounts: new Map(),
		documentOpenedAt: new Map(),
		diagnosticEmitter,
		diagnosticsVersion: 0,
		documentVersions: new Map(),
		diagnosticDocVersions: new Map(),
		documentContentHashes: new Map(),
		versionlessBindingEligibility: new Map(),
		diagnosticBindings: new Map(),
		pullResultIds: new Map(),
		workspacePullResultCache: new Map(),
		openDocuments: new Set(),
		closedDocuments: new Set(),
		pendingOpens: new Set(),
		workspaceDiagnosticsSupport: {
			advertised: false,
			mode: "push-only",
			workspaceDiagnostics: false,
			diagnosticProviderKind: "none",
		},
		operationSupport: {
			definition: false,
			typeDefinition: false,
			declaration: false,
			references: false,
			hover: false,
			signatureHelp: false,
			documentSymbol: false,
			workspaceSymbol: false,
			codeAction: false,
			rename: false,
			implementation: false,
			callHierarchy: false,
		},
		staticDiagnosticsMode: "push-only",
		positionEncoding: "utf-16",
		dynamicRegistrations: new Map(),
		advertisedCommands: new Set(),
		serverEditsAllowed: 0,
		serverId: "test-server",
		root: "/project",
		lspProcess: createMockLspProcess() as any,
		watchQueue: undefined as unknown as WatchedFilesQueue,
		...overrides,
	};
	// #271: mirror production — the queue flushes a batched didChangeWatchedFiles
	// through the (mock) connection. Tests drive it via state.watchQueue.flush().
	if (!state.watchQueue) {
		state.watchQueue = new WatchedFilesQueue((changes) => {
			void state.connection.sendNotification(
				"workspace/didChangeWatchedFiles",
				{ changes },
			);
		});
	}
	return state;
}

describe("resolveConfigurationSection (#983)", () => {
	const initialization = {
		scan: { configuration: ["auto"], onlyGitDirty: false, jobs: 16 },
		metrics: { enabled: false },
		doHover: false,
	};

	it("returns the whole blob for an item with no section", () => {
		expect(resolveConfigurationSection(initialization, undefined)).toBe(
			initialization,
		);
	});

	it("resolves a top-level section", () => {
		expect(resolveConfigurationSection(initialization, "metrics")).toEqual({
			enabled: false,
		});
	});

	it("resolves a nested dot-path section", () => {
		expect(resolveConfigurationSection(initialization, "scan.jobs")).toBe(16);
	});

	it("returns null for an unknown section instead of the whole blob", () => {
		expect(resolveConfigurationSection(initialization, "unknown.section")).toBe(
			null,
		);
		expect(resolveConfigurationSection(initialization, "scan.nope")).toBe(null);
	});

	it("returns native empty defaults for missing CSS-family sections", () => {
		for (const section of ["css", "scss", "less"]) {
			expect(resolveConfigurationSection(undefined, section)).toEqual({});
			expect(resolveConfigurationSection({}, section)).toEqual({});
			expect(resolveConfigurationSection({ unrelated: true }, section)).toEqual({});
		}
		expect(
			resolveConfigurationSection({ css: { validate: false } }, "css"),
		).toEqual({ validate: false });
		expect(resolveConfigurationSection({}, "unknown")).toBe(null);
		expect(resolveConfigurationSection(undefined, "unknown")).toBe(null);
	});
});

describe("workspace/configuration handler (#983)", () => {
	// Per the LSP spec the response array's length MUST equal
	// params.items.length, one resolved value per requested item — not a
	// fixed single-element array duplicating the whole blob for every item.
	it("returns one resolved entry per requested item, mixing known and unknown sections", async () => {
		const initialization = {
			scan: { jobs: 16 },
			metrics: { enabled: false },
		};
		const state = createMockState();
		setupIncomingHandlers(state, initialization);

		const onRequest = vi.mocked(state.connection.onRequest);
		const calls = onRequest.mock.calls as unknown as Array<
			[string, (params: unknown) => Promise<unknown[]>]
		>;
		const registered = calls.find(
			(c) => c[0] === "workspace/configuration",
		);
		expect(registered).toBeDefined();
		const handler = registered![1];

		const result = await handler({
			items: [
				{ section: "scan" },
				{ section: "metrics.enabled" },
				{ section: "nonexistent.section" },
				{},
			],
		});

		expect(result).toEqual([
			{ jobs: 16 },
			false,
			null,
			initialization,
		]);
	});

	it("returns an empty array when the server requests zero items", async () => {
		const state = createMockState();
		setupIncomingHandlers(state, { scan: { jobs: 16 } });

		const onRequest = vi.mocked(state.connection.onRequest);
		const calls = onRequest.mock.calls as unknown as Array<
			[string, (params: unknown) => Promise<unknown[]>]
		>;
		const registered = calls.find(
			(c) => c[0] === "workspace/configuration",
		);
		const handler = registered![1];

		expect(await handler({ items: [] })).toEqual([]);
	});
});

describe("stripDiagnosticNoiseLines", () => {
	it("removes bare URL and further-information diagnostic lines", () => {
		expect(
			stripDiagnosticNoiseLines(
				"actual error\nfor further information visit https://example.test\nhttps://example.test/docs",
			),
		).toBe("actual error");
	});
});

describe("clientShutdown", () => {
	it("skips LSP protocol handshake in fast mode", async () => {
		const process = {
			killed: false,
			kill: vi.fn(() => true),
			unref: vi.fn(),
		};
		const state = createMockState({
			lspProcess: {
				...createMockLspProcess(),
				pid: 0,
				process,
			} as any,
		});

		await clientShutdown(state, { fast: true });

		expect(state.connection.sendRequest).not.toHaveBeenCalled();
		expect(state.connection.sendNotification).not.toHaveBeenCalled();
		expect(state.connection.dispose).toHaveBeenCalledTimes(1);
		expect(process.kill).toHaveBeenCalledWith("SIGTERM");
		expect(process.unref).toHaveBeenCalledTimes(1);
	});
});

describe("handleNotifyOpen", () => {
	it("sends didOpen on first open", async () => {
		const state = createMockState();
		await handleNotifyOpen(state, TEST_FILE, "const x = 1;", "typescript");

		const calls = vi.mocked(state.connection.sendNotification).mock.calls;
		const didOpenCall = calls.find((c) => c[0] === "textDocument/didOpen");
		expect(didOpenCall).toBeDefined();
		expect(state.openDocuments.has(TEST_KEY)).toBe(true);
	});

	it("suppresses didChangeWatchedFiles in silent open mode", async () => {
		const state = createMockState();
		await handleNotifyOpen(
			state,
			TEST_FILE,
			"const x = 1;",
			"typescript",
			false,
			true,
		);

		const calls = vi.mocked(state.connection.sendNotification).mock.calls;
		expect(calls.some((c) => c[0] === "workspace/didChangeWatchedFiles")).toBe(
			false,
		);
		expect(calls.some((c) => c[0] === "textDocument/didOpen")).toBe(true);
	});

	it("batches didChangeWatchedFiles via the watch queue in normal open mode (#271)", async () => {
		const state = createMockState();
		await handleNotifyOpen(state, TEST_FILE, "const x = 1;", "typescript");

		// #271: the notify is now enqueued, not sent inline — not yet on the wire.
		let calls = vi.mocked(state.connection.sendNotification).mock.calls;
		expect(calls.some((c) => c[0] === "workspace/didChangeWatchedFiles")).toBe(
			false,
		);
		expect(state.watchQueue.size).toBe(1);

		// flushing the debounce window emits a single batched notification.
		state.watchQueue.flush();
		calls = vi.mocked(state.connection.sendNotification).mock.calls;
		const watched = calls.find(
			(c) => c[0] === "workspace/didChangeWatchedFiles",
		);
		expect(watched).toBeDefined();
		expect((watched?.[1] as { changes: unknown[] }).changes).toHaveLength(1);
	});

	it("coalesces multiple file opens into ONE didChangeWatchedFiles (#271)", async () => {
		const state = createMockState();
		await handleNotifyOpen(state, TEST_FILE, "const x = 1;", "typescript");
		await handleNotifyOpen(
			state,
			`${TEST_FILE}.other.ts`,
			"const y = 2;",
			"typescript",
		);
		expect(state.watchQueue.size).toBe(2);

		state.watchQueue.flush();
		const watchedCalls = vi
			.mocked(state.connection.sendNotification)
			.mock.calls.filter((c) => c[0] === "workspace/didChangeWatchedFiles");
		// one notification for the whole burst, carrying both URIs
		expect(watchedCalls).toHaveLength(1);
		expect(
			(watchedCalls[0][1] as { changes: unknown[] }).changes,
		).toHaveLength(2);
	});

	it("sends didChange on re-open", async () => {
		const state = createMockState();
		state.openDocuments.add(TEST_KEY);
		state.documentVersions.set(TEST_KEY, 0);

		await handleNotifyOpen(state, TEST_FILE, "const y = 2;", "typescript");

		const calls = vi.mocked(state.connection.sendNotification).mock.calls;
		const didChangeCall = calls.find((c) => c[0] === "textDocument/didChange");
		expect(didChangeCall).toBeDefined();
		expect(state.documentVersions.get(TEST_KEY)).toBe(1);
	});

	it("does nothing when client is not alive", async () => {
		const state = createMockState({ isConnected: false });
		await handleNotifyOpen(state, TEST_FILE, "const x = 1;", "typescript");

		expect(state.connection.sendNotification).not.toHaveBeenCalled();
	});

	it("tracks pending opens until didOpen completes", async () => {
		const state = createMockState();
		expect(state.pendingOpens.has(TEST_KEY)).toBe(false);

		await handleNotifyOpen(state, TEST_FILE, "const x = 1;", "typescript");

		expect(state.pendingOpens.has(TEST_KEY)).toBe(false);
		expect(state.openDocuments.has(TEST_KEY)).toBe(true);
	});

	it("clears diagnostics on open", async () => {
		const state = createMockState();
		state.pushDiagnostics.set(TEST_KEY, [
			{
				severity: 1,
				message: "old",
				range: {
					start: { line: 0, character: 0 },
					end: { line: 0, character: 0 },
				},
			},
		]);

		await handleNotifyOpen(state, TEST_FILE, "const x = 1;", "typescript");

		expect(state.pushDiagnostics.has(TEST_KEY)).toBe(false);
	});
});

describe("handleNotifyChange", () => {
	it("sends didChange when document is open", async () => {
		const state = createMockState();
		state.openDocuments.add(TEST_KEY);
		state.documentVersions.set(TEST_KEY, 0);

		await handleNotifyChange(state, TEST_FILE, "const y = 2;");

		const calls = vi.mocked(state.connection.sendNotification).mock.calls;
		const didChangeCall = calls.find((c) => c[0] === "textDocument/didChange");
		expect(didChangeCall).toBeDefined();
		expect(state.documentVersions.get(TEST_KEY)).toBe(1);
	});

	it("falls back to didOpen when document not yet open", async () => {
		const state = createMockState();

		await handleNotifyChange(state, TEST_FILE, "const y = 2;");

		const calls = vi.mocked(state.connection.sendNotification).mock.calls;
		const didOpenCall = calls.find((c) => c[0] === "textDocument/didOpen");
		expect(didOpenCall).toBeDefined();
		expect(state.openDocuments.has(TEST_KEY)).toBe(true);
	});

	it("clears stale diagnostics before sending change", async () => {
		const state = createMockState();
		state.openDocuments.add(TEST_KEY);
		state.documentVersions.set(TEST_KEY, 0);
		state.pushDiagnostics.set(TEST_KEY, [
			{
				severity: 1,
				message: "old push",
				range: {
					start: { line: 0, character: 0 },
					end: { line: 0, character: 0 },
				},
			},
		]);
		state.documentPullDiagnostics.set(TEST_KEY, [
			{
				severity: 1,
				message: "old pull",
				range: {
					start: { line: 0, character: 1 },
					end: { line: 0, character: 1 },
				},
			},
		]);

		await handleNotifyChange(state, TEST_FILE, "const y = 2;");

		expect(state.pushDiagnostics.has(TEST_KEY)).toBe(false);
		expect(state.documentPullDiagnostics.has(TEST_KEY)).toBe(false);
	});

	it("does nothing when client is not alive", async () => {
		const state = createMockState({ isConnected: false });
		await handleNotifyChange(state, TEST_FILE, "const y = 2;");

		expect(state.connection.sendNotification).not.toHaveBeenCalled();
	});
});

describe("clientWaitForDiagnostics", () => {
	it("resolves immediately if diagnostics already cached", async () => {
		const state = createMockState();
		state.diagnosticsVersion = 1;
		state.pushDiagnostics.set(TEST_KEY, [
			{
				severity: 1,
				message: "error",
				range: {
					start: { line: 0, character: 0 },
					end: { line: 0, character: 0 },
				},
			},
		]);

		await clientWaitForDiagnostics(state, TEST_FILE, 1000);
		// Should resolve immediately without waiting
	});

	it("does not accept cached diagnostics at or below minVersion", async () => {
		const state = createMockState();
		state.diagnosticsVersion = 1;
		state.pushDiagnostics.set(TEST_KEY, [
			{
				severity: 1,
				message: "stale error",
				range: {
					start: { line: 0, character: 0 },
					end: { line: 0, character: 0 },
				},
			},
		]);

		const start = Date.now();
		await clientWaitForDiagnostics(state, TEST_FILE, 50, { minVersion: 1 });
		const elapsed = Date.now() - start;

		expect(elapsed).toBeGreaterThanOrEqual(40);
	});

	it("resolves when diagnostics advance past minVersion", async () => {
		const state = createMockState();
		state.diagnosticsVersion = 1;

		const waitPromise = clientWaitForDiagnostics(state, TEST_FILE, 5000, {
			minVersion: 1,
		});

		setTimeout(() => {
			state.diagnosticsVersion = 2;
			state.diagnosticEmitter.emit("diagnostics", TEST_FILE);
		}, 50);

		await waitPromise;
	});

	it("resolves when diagnostics arrive via emitter", async () => {
		const state = createMockState();

		const waitPromise = clientWaitForDiagnostics(state, TEST_FILE, 5000);

		// Simulate diagnostics arriving after a short delay
		setTimeout(() => {
			state.diagnosticEmitter.emit("diagnostics", TEST_FILE);
		}, 50);

		await waitPromise;
	});

	it("resolves after timeout if no diagnostics arrive", async () => {
		const state = createMockState();

		const start = Date.now();
		await clientWaitForDiagnostics(state, TEST_FILE, 100);
		const elapsed = Date.now() - start;

		expect(elapsed).toBeGreaterThanOrEqual(90);
	});

	it("ignores diagnostics for other files", async () => {
		const state = createMockState();

		const waitPromise = clientWaitForDiagnostics(state, TEST_FILE, 5000);

		// Emit diagnostics for a different file
		setTimeout(() => {
			state.diagnosticEmitter.emit("diagnostics", "/project/other.ts");
		}, 50);

		// Emit for the right file after a bit longer
		setTimeout(() => {
			state.diagnosticEmitter.emit("diagnostics", TEST_FILE);
		}, 100);

		await waitPromise;
	});
});

describe("publishDiagnostics handler — superseded push guard (cache-poisoning fix)", () => {
	// The handler is registered via connection.onNotification during
	// setupIncomingHandlers; the mock connection's onNotification is a vi.fn(),
	// so we capture the callback it's invoked with to drive the handler
	// directly, the same way the real vscode-jsonrpc connection would.
	type PublishDiagnosticsParams = {
		uri: string;
		diagnostics?: LSPDiagnostic[];
		version?: number;
	};

	function createCapturingState(): {
		state: LSPClientState;
		emitPublishDiagnostics: (params: PublishDiagnosticsParams) => void;
	} {
		const state = createMockState({ serverId: "test-server" });
		let handler: ((params: PublishDiagnosticsParams) => void) | undefined;
		(
			state.connection.onNotification as unknown as ReturnType<typeof vi.fn>
		).mockImplementation(
			(method: string, cb: (params: PublishDiagnosticsParams) => void) => {
				if (method === "textDocument/publishDiagnostics") handler = cb;
			},
		);
		setupIncomingHandlers(state, undefined);
		if (!handler) {
			throw new Error("publishDiagnostics handler was not registered");
		}
		return {
			state,
			emitPublishDiagnostics: (params) => handler?.(params),
		};
	}

	// "test-server" doesn't match any known strategy id, so it falls to the
	// DEFAULT_STRATEGY (seedFirstPush: false, debounceMs: 150) — the debounced
	// cache-write path exercised here is the common one across real servers.
	const DEBOUNCE_WAIT_MS = 220;

	function diagnostic(message: string, code?: string): LSPDiagnostic {
		return {
			severity: 1,
			message,
			code,
			range: {
				start: { line: 0, character: 0 },
				end: { line: 0, character: 1 },
			},
		};
	}

	it("waits for native TS7's versionless push burst to stabilize", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		Object.defineProperty(state, "serverId", { value: "typescript" });
		Object.defineProperty(state, "launchVariant", { value: "native-ts7" });
		const wait = clientWaitForDiagnostics(state, TEST_FILE, 500);

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("bogus partial-program error", "2345")],
		});
		setTimeout(() => {
			emitPublishDiagnostics({
				uri: pathToFileURL(TEST_FILE).href,
				diagnostics: [],
			});
		}, 20);

		await wait;
		expect(state.pushDiagnostics.get(TEST_KEY)).toEqual([]);
	});

	it("keeps classic TypeScript's first publication authoritative", () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		Object.defineProperty(state, "serverId", { value: "typescript" });
		Object.defineProperty(state, "launchVariant", { value: "classic" });

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("classic result", "2322")],
		});

		expect(state.pushDiagnostics.get(TEST_KEY)?.[0]?.message).toBe(
			"classic result",
		);
	});

	it("surfaces an intentional native TS7 error present across the burst", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		Object.defineProperty(state, "serverId", { value: "typescript" });
		Object.defineProperty(state, "launchVariant", { value: "native-ts7" });
		const wait = clientWaitForDiagnostics(state, TEST_FILE, 500);

		for (const delay of [0, 20]) {
			setTimeout(() => {
				emitPublishDiagnostics({
					uri: pathToFileURL(TEST_FILE).href,
					diagnostics: [diagnostic("real error", "2322")],
				});
			}, delay);
		}

		await wait;
		expect(state.pushDiagnostics.get(TEST_KEY)?.[0]?.message).toBe("real error");
	});

	it("settles a single native TS7 publication within the bounded quiet window", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		Object.defineProperty(state, "serverId", { value: "typescript" });
		Object.defineProperty(state, "launchVariant", { value: "native-ts7" });
		const startedAt = Date.now();
		const wait = clientWaitForDiagnostics(state, TEST_FILE, 500);

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("single result", "2322")],
		});
		await wait;

		expect(Date.now() - startedAt).toBeLessThan(300);
		expect(state.pushDiagnostics.get(TEST_KEY)?.[0]?.message).toBe("single result");
	});

	it("cancels a pending native TS7 quiet-window timer on clear/resync", async () => {
		// The headline #1412 safety property: a versionless publication armed
		// BEFORE a resync must never land its (stale) diagnostics AFTER the
		// document content changed. clearDiagnosticsForPath is what every
		// didChange/resync/initial-open path calls — deleting its clearTimeout
		// must turn this test red.
		const { state, emitPublishDiagnostics } = createCapturingState();
		Object.defineProperty(state, "serverId", { value: "typescript" });
		Object.defineProperty(state, "launchVariant", { value: "native-ts7" });

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("stale pre-resync error", "2345")],
		});
		expect(state.pendingDiagnostics.has(TEST_KEY)).toBe(true);

		clearDiagnosticsForPath(state, TEST_KEY);
		expect(state.pendingDiagnostics.has(TEST_KEY)).toBe(false);

		// Wait past the quiet window: the canceled timer must not fire and
		// resurrect the pre-resync diagnostics.
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));
		expect(state.pushDiagnostics.has(TEST_KEY)).toBe(false);
	});

	it("drops a late push whose version lags the current document version, without poisoning the cache", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		// Simulate two edits having already landed (didChange bumped this twice).
		state.documentVersions.set(TEST_KEY, 2);

		// A push that arrives late, still reporting analysis of the FIRST edit.
		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			version: 1,
			diagnostics: [
				{
					severity: 1,
					message: "stale diagnostic from edit #1",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});

		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		// The superseded push must never reach the cache — this is the actual
		// bug: getDiagnostics()/getAllDiagnostics()/pruneDiagnostics() read
		// pushDiagnostics directly and don't consult isVersionStale (that check
		// only gates clientWaitForDiagnostics), so a cached stale push would be
		// served as current until the next fresh push overwrites it.
		expect(state.pushDiagnostics.has(TEST_KEY)).toBe(false);
		expect(state.diagnosticDocVersions.has(TEST_KEY)).toBe(false);
	});

	it("caches a push whose version matches the current document version (no false-positive drops)", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		state.documentVersions.set(TEST_KEY, 2);

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			version: 2,
			diagnostics: [
				{
					severity: 1,
					message: "current diagnostic",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});

		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		const cached = state.pushDiagnostics.get(TEST_KEY);
		expect(cached).toBeDefined();
		expect(cached?.[0]?.message).toBe("current diagnostic");
		expect(state.diagnosticDocVersions.get(TEST_KEY)).toBe(2);
	});

	it("still caches a push when the document version is unknown (version-less servers unaffected)", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		// No entry in documentVersions for this path — server never reports one.

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			version: undefined,
			diagnostics: [
				{
					severity: 1,
					message: "version-less diagnostic",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});

		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		const cached = state.pushDiagnostics.get(TEST_KEY);
		expect(cached).toBeDefined();
		expect(cached?.[0]?.message).toBe("version-less diagnostic");
	});

	// #1095: content binding capture on the publish path.
	it("binds the stored diagnostics to the sent content fingerprint when the publish version matches (T1)", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		const content = "const x = 1;\n";
		// Mirror production: the document is open and a didChange sends version 2,
		// fingerprinting the exact payload text at send time (never a disk read).
		state.openDocuments.add(TEST_KEY);
		state.documentVersions.set(TEST_KEY, 1);
		await handleNotifyChange(state, TEST_FILE, content);
		expect(state.documentContentHashes.get(TEST_KEY)).toEqual({
			version: 2,
			hash: hashDiagnosticContent(content),
		});

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			version: 2,
			diagnostics: [
				{
					severity: 1,
					message: "current diagnostic",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		expect(state.diagnosticBindings.get(TEST_KEY)).toEqual({
			version: 2,
			contentHash: hashDiagnosticContent(content),
		});
	});

	it("records NO binding for a superseded push — server lags a didChange (T2)", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		// Two edits landed; the latest sent version is 2 with its own fingerprint.
		state.documentVersions.set(TEST_KEY, 2);
		state.documentContentHashes.set(TEST_KEY, {
			version: 2,
			hash: hashDiagnosticContent("const x = 2;\n"),
		});

		// A late push still analyzing edit #1 (version 1 < 2) — dropped before cache.
		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			version: 1,
			diagnostics: [
				{
					severity: 1,
					message: "stale diagnostic from edit #1",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		// No diagnostics cached AND no binding recorded for the superseded push.
		expect(state.pushDiagnostics.has(TEST_KEY)).toBe(false);
		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});

	it("records NO contentHash when the server omits version — version-less binding stays unknown (T3)", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		// Even with a sent fingerprint on record, a version-less publish must not
		// bind — otherwise version-less servers would change behavior.
		state.documentContentHashes.set(TEST_KEY, {
			version: 0,
			hash: hashDiagnosticContent("const x = 1;\n"),
		});

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			version: undefined,
			diagnostics: [
				{
					severity: 1,
					message: "version-less diagnostic",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		expect(state.pushDiagnostics.has(TEST_KEY)).toBe(true);
		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});

	it("binds a versionless first-open publication to the exact sent content", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		const content = "const x = 1;\n";
		await handleNotifyOpen(state, TEST_FILE, content, "typescript");

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("versionless current diagnostic")],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		expect(state.diagnosticBindings.get(TEST_KEY)).toEqual({
			version: 0,
			contentHash: hashDiagnosticContent(content),
		});
	});

	it("does not bind a versionless publication after a changed re-edit", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		await handleNotifyOpen(state, TEST_FILE, "const x = 1;\n", "typescript");
		await handleNotifyChange(state, TEST_FILE, "const x = 2;\n");

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("possibly stale diagnostic")],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});

	it("does not restore versionless eligibility when a later edit restores the first bytes", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		const firstContent = "const x = 1;\n";
		await handleNotifyOpen(state, TEST_FILE, firstContent, "typescript");
		await handleNotifyChange(state, TEST_FILE, "const x = 2;\n");
		await handleNotifyChange(state, TEST_FILE, firstContent);

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("disk-matching but ambiguous diagnostic")],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});

	it("does not bind a delayed versionless publication from before close after reopen", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		const content = "const x = 1;\n";
		await handleNotifyOpen(state, TEST_FILE, content, "typescript");
		await closeDocument(state, TEST_FILE);
		await handleNotifyOpen(state, TEST_FILE, content, "typescript");

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("delayed diagnostic from the closed generation")],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});

	it("does not bind after a versionless publication arrives before first open", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("stale pre-open diagnostic")],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));
		await handleNotifyOpen(state, TEST_FILE, "const x = 1;\n", "typescript");

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("ambiguous diagnostic")],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});

	it("keeps versionless eligibility across a duplicate same-content warmup send", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		const content = "const x = 1;\n";
		await handleNotifyOpen(state, TEST_FILE, content, "typescript");
		await handleNotifyOpen(state, TEST_FILE, content, "typescript");

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			diagnostics: [diagnostic("same-content diagnostic")],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		expect(state.diagnosticBindings.get(TEST_KEY)?.contentHash).toBe(
			hashDiagnosticContent(content),
		);
	});

	it("binds version but no contentHash when the sent fingerprint is for a different version (I3 fallback → unknown)", async () => {
		const { state, emitPublishDiagnostics } = createCapturingState();
		state.documentVersions.set(TEST_KEY, 2);
		// The only fingerprint we hold is for an OLDER version (1) — cannot bind
		// version 2's content, so contentHash is left undefined → verifier "unknown".
		state.documentContentHashes.set(TEST_KEY, {
			version: 1,
			hash: hashDiagnosticContent("old"),
		});

		emitPublishDiagnostics({
			uri: pathToFileURL(TEST_FILE).href,
			version: 2,
			diagnostics: [
				{
					severity: 1,
					message: "current diagnostic",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});
		await new Promise((resolve) => setTimeout(resolve, DEBOUNCE_WAIT_MS));

		const binding = state.diagnosticBindings.get(TEST_KEY);
		expect(binding?.version).toBe(2);
		expect(binding?.contentHash).toBeUndefined();
	});

	// #1095 (P2-3): reopenOnResync servers (opengrep) close+reopen on every
	// resync. Resetting the version to 0 each time made a late publish for an
	// EARLIER resync's content echo the SAME 0 as the current send, so the
	// superseded guard accepted it and bound STALE diagnostics to the CURRENT
	// content's fingerprint (an affirmative false-TRUE). Monotonic versions across
	// reopen make the late echo strictly older → dropped → never bound.
	it("does not bind a late publish from an earlier reopen-resync as current (monotonic reopen)", async () => {
		const state = createMockState({ serverId: "opengrep" });
		let handler: ((params: PublishDiagnosticsParams) => void) | undefined;
		(
			state.connection.onNotification as unknown as ReturnType<typeof vi.fn>
		).mockImplementation(
			(method: string, cb: (params: PublishDiagnosticsParams) => void) => {
				if (method === "textDocument/publishDiagnostics") handler = cb;
			},
		);
		setupIncomingHandlers(state, undefined);

		// The document is already open (an earlier resync established it at v3).
		state.openDocuments.add(TEST_KEY);
		state.documentVersions.set(TEST_KEY, 3);

		// Resync #1 (content_A): opengrep reopen path carries the version FORWARD.
		await handleNotifyOpen(state, TEST_FILE, "const a = 1;\n", "plaintext");
		expect(state.documentVersions.get(TEST_KEY)).toBe(4);
		// Resync #2 (content_B): version advances again — no reuse of 0.
		await handleNotifyOpen(state, TEST_FILE, "const a = 2;\n", "plaintext");
		expect(state.documentVersions.get(TEST_KEY)).toBe(5);

		// opengrep's LATE publish still analyzing resync #1 echoes the stale v4.
		handler?.({
			uri: pathToFileURL(TEST_FILE).href,
			version: 4,
			diagnostics: [
				{
					severity: 1,
					message: "stale finding from resync #1",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});
		// opengrep debounceMs is 250 — wait past it for the (dropped) timer.
		await new Promise((resolve) => setTimeout(resolve, 350));

		// v4 < current v5 → superseded → dropped: no stale diagnostics cached and,
		// critically, NO binding of resync #1's diagnostics to resync #2's content.
		expect(state.pushDiagnostics.has(TEST_KEY)).toBe(false);
		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});
});

describe("clientWaitForDiagnostics — pull mode (#240)", () => {
	// serverId "typescript" → pullRetryBudgetMs 0, so no incremental retry loop;
	// the first pull outcome is decisive. mode "pull" routes through the pull
	// branch. diagnosticProviderKind "object" = an advertised pull provider.
	const pullState = (): LSPClientState =>
		createMockState({
			serverId: "typescript",
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: false,
				diagnosticProviderKind: "object",
			},
		});

	it("resolves immediately on an authoritative empty (clean) pull report", async () => {
		const state = pullState();
		state.connection.sendRequest = vi
			.fn()
			.mockResolvedValue({ kind: "full", items: [] });

		const start = Date.now();
		await clientWaitForDiagnostics(state, TEST_FILE, 1000);
		expect(Date.now() - start).toBeLessThan(80);
	});

	it("invalidates a cached clean pull when the next computation fails", async () => {
		const state = pullState();
		state.openDocuments.add(TEST_KEY);
		let logHandler: ((params: { type: number; message: string }) => void) | undefined;
		(
			state.connection.onNotification as unknown as ReturnType<typeof vi.fn>
		).mockImplementation(
			(method: string, handler: (params: { type: number; message: string }) => void) => {
				if (method === "window/logMessage") logHandler = handler;
			},
		);
		setupIncomingHandlers(state, {});
		expect(logHandler).toBeDefined();
		state.connection.sendRequest = vi
			.fn()
			.mockResolvedValueOnce({ kind: "full", items: [] })
			.mockImplementationOnce(async () => {
				logHandler?.({
					type: 1,
					message: `Error while computing diagnostics for ${pathToFileURL(TEST_FILE).href}: validation failed`,
				});
				return { kind: "full", items: [] };
			});

		await clientWaitForDiagnostics(state, TEST_FILE, 50, { pullOnly: true });
		expect(state.documentPullDiagnostics.get(TEST_KEY)).toEqual([]);
		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(true);

		await clientWaitForDiagnostics(state, TEST_FILE, 50, { pullOnly: true });

		expect(state.documentPullDiagnostics.has(TEST_KEY)).toBe(false);
		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
		expect(state.pullFailureHistory.at(-1)?.message).toContain(
			"Error while computing diagnostics",
		);
	});

	it("ignores computation errors for documents that are not active", () => {
		const state = pullState();
		let logHandler: ((params: { type: number; message: string }) => void) | undefined;
		(
			state.connection.onNotification as unknown as ReturnType<typeof vi.fn>
		).mockImplementation(
			(method: string, handler: (params: { type: number; message: string }) => void) => {
				if (method === "window/logMessage") logHandler = handler;
			},
		);
		setupIncomingHandlers(state, {});

		logHandler?.({
			type: 1,
			message: `Error while computing diagnostics for ${pathToFileURL("/tmp/unrelated.css").href}: validation failed`,
		});

		expect(state.diagnosticComputationErrors.size).toBe(0);
	});

	it("resolves immediately when the pull returns diagnostics (found)", async () => {
		const state = pullState();
		state.connection.sendRequest = vi.fn().mockResolvedValue({
			kind: "full",
			items: [
				{
					severity: 1,
					message: "boom",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});

		const start = Date.now();
		await clientWaitForDiagnostics(state, TEST_FILE, 1000);
		expect(Date.now() - start).toBeLessThan(80);
	});

	it("does NOT treat a failed/unavailable pull as clean — waits the budget rather than short-circuiting", async () => {
		const state = pullState();
		// undefined reply → safeSendRequest returns undefined → outcome
		// "unavailable". With no minVersion baseline the OLD code returned
		// immediately via `|| hasFreshDiagnostics()` (a false clean); the fix must
		// instead fall through to the push-wait/timeout backstop.
		state.connection.sendRequest = vi.fn().mockResolvedValue(undefined);

		const start = Date.now();
		await clientWaitForDiagnostics(state, TEST_FILE, 120);
		expect(Date.now() - start).toBeGreaterThanOrEqual(100);
	});

	it("bounds a hung pull request instead of hanging forever", async () => {
		const state = pullState();
		// A pull-mode server that accepts textDocument/diagnostic but NEVER
		// replies (stream stays alive). safeSendRequest only settles on a reply or
		// a destroyed stream, so pre-fix this await never resolves and hangs the
		// whole diagnostics wait (→ pipeline → flush → lens_diagnostics). The
		// per-request withTimeout must bound it: time out → unavailable → fall
		// through to the push backstop and resolve within the caller's budget.
		state.connection.sendRequest = vi.fn(() => new Promise<never>(() => {}));

		const start = Date.now();
		await clientWaitForDiagnostics(state, TEST_FILE, 120);
		const elapsed = Date.now() - start;
		// Went through the timeout→backstop path (not a false early clean)...
		expect(elapsed).toBeGreaterThanOrEqual(100);
		// ...and did NOT hang on the never-resolving request.
		expect(elapsed).toBeLessThan(2000);
	});
});

// #1104: thread resultId + the request-time content fingerprint through the
// PULL protocol (textDocument/diagnostic + workspace/diagnostic) so pull-
// served diagnostics get the SAME content binding push-served ones have had
// since #1095, instead of reading "unknown" forever. Mirrors #1095's own
// client-internals binding tests in shape.
describe("pull-diagnostics content binding (#1104)", () => {
	const pullState = (): LSPClientState =>
		createMockState({
			serverId: "typescript",
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: false,
				diagnosticProviderKind: "object",
			},
		});

	it("binds a 'full' textDocument/diagnostic report to the sent-content fingerprint and records its resultId", async () => {
		const state = pullState();
		const content = "const x = 1;\n";
		// Mirror production: the document was opened/changed before the pull, so
		// `documentContentHashes` already holds the exact fingerprint the pull's
		// answer is presumed to describe — no extra disk read needed.
		state.openDocuments.add(TEST_KEY);
		state.documentContentHashes.set(TEST_KEY, {
			version: 1,
			hash: hashDiagnosticContent(content),
		});
		state.connection.sendRequest = vi.fn().mockResolvedValue({
			kind: "full",
			resultId: "r1",
			items: [
				{
					severity: 1,
					message: "boom",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});

		await clientWaitForDiagnostics(state, TEST_FILE, 1000, { pullOnly: true });

		expect(state.diagnosticBindings.get(TEST_KEY)).toEqual({
			contentHash: hashDiagnosticContent(content),
		});
		expect(state.pullResultIds.get(TEST_KEY)).toBe("r1");
	});

	it("an 'unchanged' report (same resultId) inherits the prior diagnostics AND binding instead of reading as clean", async () => {
		const state = pullState();
		const content = "const x = 1;\n";
		state.openDocuments.add(TEST_KEY);
		state.documentContentHashes.set(TEST_KEY, {
			version: 1,
			hash: hashDiagnosticContent(content),
		});
		const sendRequest = vi.fn().mockResolvedValueOnce({
			kind: "full",
			resultId: "r1",
			items: [
				{
					severity: 1,
					message: "boom",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 0 },
					},
				},
			],
		});
		state.connection.sendRequest = sendRequest;
		await clientWaitForDiagnostics(state, TEST_FILE, 1000, { pullOnly: true });
		const bindingAfterFull = state.diagnosticBindings.get(TEST_KEY);
		expect(bindingAfterFull?.contentHash).toBe(hashDiagnosticContent(content));

		// Second pull: server confirms nothing changed (no `items`). Pre-#1104 this
		// codepath always overwrote with `report.items ?? []` — an empty array —
		// which would WRONGLY read as a confirmed-clean touch and silently wipe
		// the still-live "boom" diagnostic (the #570/#571 false-clean shape).
		sendRequest.mockResolvedValueOnce({ kind: "unchanged", resultId: "r1" });
		await clientWaitForDiagnostics(state, TEST_FILE, 1000, { pullOnly: true });

		// The prior finding AND its binding both survived the unchanged report.
		expect(state.documentPullDiagnostics.get(TEST_KEY)?.length).toBe(1);
		expect(state.diagnosticBindings.get(TEST_KEY)).toEqual(bindingAfterFull);
		// The second request echoed the resultId from the first.
		expect(sendRequest.mock.calls[1]?.[1]).toMatchObject({
			previousResultId: "r1",
		});
	});

	it("clearDiagnosticsForPath (a resync) drops the pull resultId basis so a later pull cannot inherit stale content", async () => {
		const state = pullState();
		state.openDocuments.add(TEST_KEY);
		state.documentContentHashes.set(TEST_KEY, {
			version: 1,
			hash: hashDiagnosticContent("const x = 1;\n"),
		});
		state.connection.sendRequest = vi.fn().mockResolvedValue({
			kind: "full",
			resultId: "r1",
			items: [],
		});
		await clientWaitForDiagnostics(state, TEST_FILE, 1000, { pullOnly: true });
		expect(state.pullResultIds.get(TEST_KEY)).toBe("r1");

		// A resync (didChange) clears diagnostic state for the path.
		await handleNotifyChange(state, TEST_FILE, "const x = 2;\n");

		expect(state.pullResultIds.has(TEST_KEY)).toBe(false);
		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});
});

describe("clientRequestWorkspaceDiagnostics content binding (#1104)", () => {
	function pullSupportState(): LSPClientState {
		return createMockState({
			serverId: "typescript",
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: true,
				diagnosticProviderKind: "object",
			},
		});
	}

	it("fingerprints disk bytes at request time for a 'full' item and returns the hash", async () => {
		const state = pullSupportState();
		const filePath = path.join(os.tmpdir(), `pi-lens-1104-${Date.now()}.ts`);
		const content = "const y = 2;\n";
		fs.writeFileSync(filePath, content);
		try {
			const uri = pathToFileURL(filePath).href;
			state.connection.sendRequest = vi.fn().mockResolvedValue({
				items: [{ uri, kind: "full", resultId: "wr1", items: [] }],
			});

			const report = await clientRequestWorkspaceDiagnostics(state, 1000);

			expect(report?.[0]?.contentHash).toBe(hashDiagnosticContent(content));
		} finally {
			fs.rmSync(filePath, { force: true });
		}
	});

	it("an 'unchanged' item inherits the prior pull's diagnostics + contentHash and echoes previousResultIds on the next request", async () => {
		const state = pullSupportState();
		const filePath = path.join(os.tmpdir(), `pi-lens-1104b-${Date.now()}.ts`);
		fs.writeFileSync(filePath, "const y = 2;\n");
		try {
			const uri = pathToFileURL(filePath).href;
			const sendRequest = vi.fn().mockResolvedValueOnce({
				items: [
					{
						uri,
						kind: "full",
						resultId: "wr1",
						items: [
							{
								severity: 1,
								message: "boom",
								range: {
									start: { line: 0, character: 0 },
									end: { line: 0, character: 0 },
								},
							},
						],
					},
				],
			});
			state.connection.sendRequest = sendRequest;
			const first = await clientRequestWorkspaceDiagnostics(state, 1000);
			const firstHash = first?.[0]?.contentHash;
			expect(first?.[0]?.diagnostics.length).toBe(1);

			sendRequest.mockResolvedValueOnce({
				items: [{ uri, kind: "unchanged", resultId: "wr1" }],
			});
			const second = await clientRequestWorkspaceDiagnostics(state, 1000);

			expect(second?.[0]?.diagnostics.length).toBe(1);
			expect(second?.[0]?.contentHash).toBe(firstHash);
			expect(sendRequest.mock.calls[1]?.[1]).toMatchObject({
				previousResultIds: [{ uri, value: "wr1" }],
			});
		} finally {
			fs.rmSync(filePath, { force: true });
		}
	});
});

describe("pull fallback honesty + failure telemetry (#1292)", () => {
	it("keeps push diagnostics visible after an operational pull failure", async () => {
		const state = createMockState({
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: false,
				diagnosticProviderKind: "boolean",
			},
		});
		state.pushDiagnostics.set(TEST_KEY, [
			{
				severity: 1,
				message: "push result",
				range: {
					start: { line: 0, character: 0 },
					end: { line: 0, character: 1 },
				},
			},
		]);
		state.connection.sendRequest = vi
			.fn()
			.mockRejectedValue(Object.assign(new Error("server unavailable"), { code: 500 }));

		await clientWaitForDiagnostics(state, TEST_FILE, 50);

		expect(state.pushDiagnostics.get(TEST_KEY)?.[0]?.message).toBe("push result");
		expect(state.pullFailureHistory.length).toBeGreaterThanOrEqual(1);
		expect(state.pullFailureHistory[0]).toMatchObject({
			method: "textDocument/diagnostic",
			code: 500,
			message: "server unavailable",
		});
	});

	it.each([
		[-32601, "server-specific text"],
		[undefined, "Method not found: textDocument/diagnostic"],
	])("does not record an unsupported-method response as an operational failure (%s)", async (code, message) => {
		const state = createMockState({
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: false,
				diagnosticProviderKind: "boolean",
			},
		});
		const error = new Error(message);
		if (code !== undefined) Object.assign(error, { code });
		state.connection.sendRequest = vi.fn().mockRejectedValue(error);

		await clientWaitForDiagnostics(state, TEST_FILE, 20);

		expect(state.pullFailureHistory).toHaveLength(0);
	});

	it.each([
		[new Error("Timeout after 20ms")],
		[Object.assign(new Error("Internal error"), { code: -32603 })],
	])("records genuine operational pull failures", async (error) => {
		const state = createMockState({
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: false,
				diagnosticProviderKind: "boolean",
			},
		});
		state.connection.sendRequest = vi.fn().mockRejectedValue(error);

		await clientWaitForDiagnostics(state, TEST_FILE, 20);

		expect(state.pullFailureHistory.length).toBeGreaterThan(0);
	});
});

describe("shutdown protocol race fixture (#1292)", () => {
	it("handles dynamic registration and ignores a late publish after didClose", async () => {
		const state = createMockState();
		state.openDocuments.add(TEST_KEY);
		state.documentVersions.set(TEST_KEY, 1);
		state.diagnosticBindings.set(TEST_KEY, { version: 1, contentHash: "existing" });
		setupIncomingHandlers(state, {});
		const notifications = vi.mocked(state.connection.onNotification).mock.calls as unknown as Array<
			[string, (...args: unknown[]) => unknown]
		>;
		const publish = notifications.find(
			([method]) => method === "textDocument/publishDiagnostics",
		)?.[1] as ((params: unknown) => void) | undefined;
		const requests = vi.mocked(state.connection.onRequest).mock.calls as unknown as Array<
			[string, (...args: unknown[]) => unknown]
		>;
		const register = requests.find(
			([method]) => method === "client/registerCapability",
		)?.[1] as ((params: unknown) => Promise<void>) | undefined;
		await register?.({
			registrations: [{ id: "pull", method: "textDocument/diagnostic" }],
		});
		expect(state.workspaceDiagnosticsSupport.mode).toBe("pull");
		const folders = requests.find(
			([method]) => method === "workspace/workspaceFolders",
		)?.[1] as (() => unknown) | undefined;
		await closeDocument(state, TEST_FILE);
		expect(state.openDocuments.has(TEST_KEY)).toBe(false);
		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
		state.isDestroyed = true;
		expect(() => folders?.()).not.toThrow();

		publish?.({
			uri: pathToFileURL(TEST_FILE).href,
			version: 1,
			diagnostics: [
				{
					severity: 1,
					message: "late",
					range: {
						start: { line: 0, character: 0 },
						end: { line: 0, character: 1 },
					},
				},
			],
		});
		await Promise.resolve();
		expect(state.pushDiagnostics.has(TEST_KEY)).toBe(false);
		expect(state.diagnosticBindings.has(TEST_KEY)).toBe(false);
	});
});

describe("navRequest — per-request timeout ceiling (#365)", () => {
	// workspaceSymbol and codeAction now route through navRequest, so its
	// withTimeout ceiling is what stops a hung server (a request the server
	// accepts but never replies to — safeSendRequest only settles on a reply or
	// a destroyed stream) from hanging those tools forever.
	const TEST_FILE = "/proj/file.ts";

	it.each(["workspace/symbol", "textDocument/codeAction"])(
		"bounds a hung %s request instead of hanging forever",
		async (method) => {
			const state = createMockState();
			state.connection.sendRequest = vi.fn(() => new Promise<never>(() => {}));

			const start = Date.now();
			const result = await navRequest(state, method, {}, undefined, 120);
			const elapsed = Date.now() - start;

			expect(result).toBeUndefined();
			// Went through the timeout, not an instant error return...
			expect(elapsed).toBeGreaterThanOrEqual(100);
			// ...and did not hang on the never-resolving request.
			expect(elapsed).toBeLessThan(2000);
		},
	);

	it("returns the server result unchanged on a normal reply", async () => {
		const state = createMockState();
		const payload = [{ name: "sym", kind: 12 }];
		state.connection.sendRequest = vi.fn().mockResolvedValue(payload);

		const result = await navRequest(state, "workspace/symbol", {}, undefined, 120);
		expect(result).toEqual(payload);
	});

	it("drops a single-file result when the document version advances mid-request", async () => {
		const state = createMockState();
		const key = normalizeMapKey(TEST_FILE);
		state.documentVersions.set(key, 1);
		// An edit lands while the request is in flight → the reply is stale.
		state.connection.sendRequest = vi.fn(async () => {
			state.documentVersions.set(key, 2);
			return [{ title: "stale action" }];
		});

		const result = await navRequest(
			state,
			"textDocument/codeAction",
			{},
			TEST_FILE,
			120,
		);
		expect(result).toBeUndefined();
	});
});

describe("navRequest — $/cancelRequest on abort (#238 Item 1)", () => {
	it("does not send at all when the signal is already aborted", async () => {
		const state = createMockState();
		state.connection.sendRequest = vi.fn().mockResolvedValue([{ name: "x" }]);
		const controller = new AbortController();
		controller.abort();

		const result = await navRequest(
			state,
			"textDocument/definition",
			{},
			undefined,
			120,
			controller.signal,
		);

		expect(result).toBeUndefined();
		expect(state.connection.sendRequest).not.toHaveBeenCalled();
	});

	it("passes a CancellationToken when a signal is provided, none otherwise", async () => {
		const state = createMockState();
		state.connection.sendRequest = vi.fn().mockResolvedValue([]);

		await navRequest(state, "workspace/symbol", {}, undefined, 120);
		// No ambient signal in tests → third arg (token) is undefined.
		expect(vi.mocked(state.connection.sendRequest).mock.calls[0]?.[2]).toBeUndefined();

		await navRequest(
			state,
			"workspace/symbol",
			{},
			undefined,
			120,
			new AbortController().signal,
		);
		// Signal provided → a real CancellationToken is threaded to the server.
		const token = vi.mocked(state.connection.sendRequest).mock.calls[1]?.[2] as {
			onCancellationRequested?: unknown;
		};
		expect(token?.onCancellationRequested).toBeTypeOf("function");
	});

	it("cancels an in-flight request when the turn is abandoned mid-request", async () => {
		const state = createMockState();
		// Mock a server that only settles when its request token is cancelled —
		// exactly what vscode-jsonrpc does after emitting `$/cancelRequest`.
		state.connection.sendRequest = vi.fn(
			(_method: unknown, _params: unknown, token: any) =>
				new Promise((_resolve, reject) => {
					token?.onCancellationRequested(() => {
						const err = new Error("Request cancelled") as Error & {
							code: number;
						};
						err.code = -32800; // RequestCancelled
						reject(err);
					});
				}),
		) as unknown as typeof state.connection.sendRequest;

		const controller = new AbortController();
		const pending = navRequest(
			state,
			"textDocument/references",
			{},
			undefined,
			5000,
			controller.signal,
		);
		// Abort after the request is in flight → token cancels → server rejects.
		await new Promise((r) => setTimeout(r, 0));
		controller.abort();

		expect(await pending).toBeUndefined();
		expect(state.connection.sendRequest).toHaveBeenCalledTimes(1);
	});
});

describe("navRequest — ContentModified retry (#238 Item 2)", () => {
	const modified = (): Error => {
		const err = new Error("content modified") as Error & { code: number };
		err.code = -32801;
		return err;
	};

	it("retries once on ContentModified and returns the retried result", async () => {
		const state = createMockState();
		let calls = 0;
		state.connection.sendRequest = vi.fn(async () => {
			calls += 1;
			if (calls === 1) throw modified();
			return [{ name: "fresh" }];
		}) as unknown as typeof state.connection.sendRequest;

		const result = await navRequest(
			state,
			"textDocument/definition",
			{},
			undefined,
			500,
		);

		expect(result).toEqual([{ name: "fresh" }]);
		expect(state.connection.sendRequest).toHaveBeenCalledTimes(2);
	});

	it("returns empty (not a throw) when ContentModified persists after the retry", async () => {
		const state = createMockState();
		state.connection.sendRequest = vi.fn(async () => {
			throw modified();
		}) as unknown as typeof state.connection.sendRequest;

		const result = await navRequest(
			state,
			"textDocument/definition",
			{},
			undefined,
			500,
		);

		expect(result).toBeUndefined();
		// One retry only — not an unbounded loop.
		expect(state.connection.sendRequest).toHaveBeenCalledTimes(2);
	});

	it("does not retry a permanent RequestFailed (-32803)", async () => {
		const state = createMockState();
		state.connection.sendRequest = vi.fn(async () => {
			const err = new Error("request failed") as Error & { code: number };
			err.code = -32803;
			throw err;
		}) as unknown as typeof state.connection.sendRequest;

		await expect(
			navRequest(state, "textDocument/definition", {}, undefined, 500),
		).rejects.toThrow();
		expect(state.connection.sendRequest).toHaveBeenCalledTimes(1);
	});

	it("does not retry when the signal aborts between attempts", async () => {
		const state = createMockState();
		const controller = new AbortController();
		state.connection.sendRequest = vi.fn(async () => {
			controller.abort(); // turn abandoned exactly as the first attempt fails
			throw modified();
		}) as unknown as typeof state.connection.sendRequest;

		const result = await navRequest(
			state,
			"textDocument/definition",
			{},
			undefined,
			500,
			controller.signal,
		);

		expect(result).toBeUndefined();
		// Aborted → no second attempt.
		expect(state.connection.sendRequest).toHaveBeenCalledTimes(1);
	});
});

describe("runServerCommand — executeCommand timeout backstop (#365)", () => {
	const advertised = (): LSPClientState => {
		const state = createMockState();
		state.advertisedCommands.add("test.command");
		return state;
	};

	it("bounds a hung command with the generous backstop and surfaces it honestly", async () => {
		const state = advertised();
		state.connection.sendRequest = vi.fn(() => new Promise<never>(() => {}));

		const start = Date.now();
		const outcome = await runServerCommand(state, "test.command", [], 120);
		const elapsed = Date.now() - start;

		expect(outcome.executed).toBe(false);
		expect(outcome.reason).toMatch(/timed out.*may still be applying/i);
		expect(elapsed).toBeGreaterThanOrEqual(100);
		expect(elapsed).toBeLessThan(2000);
		// The serverEditsAllowed window must close even on timeout.
		expect(state.serverEditsAllowed).toBe(0);
	});

	it("returns the command result on a normal reply", async () => {
		const state = advertised();
		state.connection.sendRequest = vi.fn().mockResolvedValue({ applied: true });

		const outcome = await runServerCommand(state, "test.command", [], 120);
		expect(outcome).toEqual({ executed: true, result: { applied: true } });
		expect(state.serverEditsAllowed).toBe(0);
	});

	it("refuses a command the server never advertised (hardening preserved)", async () => {
		const state = createMockState(); // advertisedCommands empty
		state.connection.sendRequest = vi.fn().mockResolvedValue({ applied: true });

		const outcome = await runServerCommand(state, "evil.command", [], 120);
		expect(outcome.executed).toBe(false);
		expect(outcome.reason).toMatch(/not advertised/i);
		// Never sent, and the edit window never opened.
		expect(state.connection.sendRequest).not.toHaveBeenCalled();
		expect(state.serverEditsAllowed).toBe(0);
	});
});

describe("applyDynamicCapabilities", () => {
	it("upgrades to pull mode when textDocument/diagnostic is registered", () => {
		const state = createMockState();
		state.dynamicRegistrations.set("diag-1", "textDocument/diagnostic");

		applyDynamicCapabilities(state);

		expect(state.workspaceDiagnosticsSupport.mode).toBe("pull");
		expect(state.workspaceDiagnosticsSupport.advertised).toBe(true);
		expect(state.workspaceDiagnosticsSupport.diagnosticProviderKind).toBe(
			"dynamic",
		);
	});

	it("upgrades to pull mode when workspace/diagnostic is registered", () => {
		const state = createMockState();
		state.dynamicRegistrations.set("ws-diag-1", "workspace/diagnostic");

		applyDynamicCapabilities(state);

		expect(state.workspaceDiagnosticsSupport.mode).toBe("pull");
	});

	it("reverts to push-only when dynamic pull registration is removed", () => {
		const state = createMockState();
		state.dynamicRegistrations.set("diag-1", "textDocument/diagnostic");
		applyDynamicCapabilities(state);
		expect(state.workspaceDiagnosticsSupport.mode).toBe("pull");

		state.dynamicRegistrations.delete("diag-1");
		applyDynamicCapabilities(state);

		expect(state.workspaceDiagnosticsSupport.mode).toBe("push-only");
		expect(state.workspaceDiagnosticsSupport.advertised).toBe(false);
	});

	it("does not revert pull mode when statically advertised", () => {
		const state = createMockState({
			staticDiagnosticsMode: "pull",
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: false,
				diagnosticProviderKind: "object",
			},
		});
		// Even with no dynamic registrations, static pull should remain
		applyDynamicCapabilities(state);

		expect(state.workspaceDiagnosticsSupport.mode).toBe("pull");
		expect(state.workspaceDiagnosticsSupport.diagnosticProviderKind).toBe(
			"object",
		);
	});

	it("upgrades operation capabilities when methods are registered", () => {
		const state = createMockState();
		state.dynamicRegistrations.set("def-1", "textDocument/definition");
		state.dynamicRegistrations.set("ref-1", "textDocument/references");
		state.dynamicRegistrations.set("hover-1", "textDocument/hover");

		applyDynamicCapabilities(state);

		expect(state.operationSupport.definition).toBe(true);
		expect(state.operationSupport.references).toBe(true);
		expect(state.operationSupport.hover).toBe(true);
		expect(state.operationSupport.rename).toBe(false); // not registered
	});

	it("does not downgrade already-true operation capabilities on unregister", () => {
		const state = createMockState({
			operationSupport: {
				definition: true,
				typeDefinition: false,
				declaration: false,
				references: false,
				hover: false,
				signatureHelp: false,
				documentSymbol: false,
				workspaceSymbol: false,
				codeAction: false,
				rename: false,
				implementation: false,
				callHierarchy: false,
			},
		});
		// No dynamic registrations — definition was statically true
		applyDynamicCapabilities(state);

		expect(state.operationSupport.definition).toBe(true);
	});

	it("ignores unknown registration methods without throwing", () => {
		const state = createMockState();
		state.dynamicRegistrations.set("unknown-1", "some/unknownMethod");

		expect(() => applyDynamicCapabilities(state)).not.toThrow();
		expect(state.workspaceDiagnosticsSupport.mode).toBe("push-only");
	});
});

describe("clientRequestWorkspaceDiagnostics — real report parsing", () => {
	function reportItem(absPath: string, kind: string, diags: unknown[] = []) {
		return { uri: pathToFileURL(absPath).href, version: 1, kind, items: diags };
	}
	function diag(message: string) {
		return {
			severity: 1,
			message,
			range: {
				start: { line: 0, character: 0 },
				end: { line: 0, character: 3 },
			},
		};
	}

	it("parses a WorkspaceDiagnosticReport into per-file diagnostics", async () => {
		const state = createMockState({
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: true,
				diagnosticProviderKind: "object",
			},
		});
		vi.mocked(state.connection.sendRequest).mockResolvedValue({
			items: [
				reportItem("/project/a.ts", "full", [diag("boom"), diag("bang")]),
				reportItem("/project/b.ts", "full", []),
				// "unchanged" carries no items — must be skipped, not returned empty.
				reportItem("/project/c.ts", "unchanged"),
			],
		});

		const out = await clientRequestWorkspaceDiagnostics(state, 1000);

		expect(state.connection.sendRequest).toHaveBeenCalledWith(
			"workspace/diagnostic",
			{ previousResultIds: [] },
		);
		expect(out).toBeDefined();
		const byName = (name: string) =>
			out?.find((r) => r.filePath.split("\\").join("/").endsWith(name));
		expect(byName("a.ts")?.diagnostics).toHaveLength(2);
		expect(byName("b.ts")?.diagnostics).toHaveLength(0);
		expect(byName("c.ts")).toBeUndefined(); // unchanged → skipped
	});

	it("returns undefined without sending when the server doesn't advertise workspace pull", async () => {
		const state = createMockState(); // workspaceDiagnostics: false by default
		const out = await clientRequestWorkspaceDiagnostics(state, 1000);
		expect(out).toBeUndefined();
		expect(state.connection.sendRequest).not.toHaveBeenCalled();
	});

	it("returns undefined on a malformed report (no items array)", async () => {
		const state = createMockState({
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: true,
				diagnosticProviderKind: "object",
			},
		});
		vi.mocked(state.connection.sendRequest).mockResolvedValue({ nope: true });
		expect(await clientRequestWorkspaceDiagnostics(state, 1000)).toBeUndefined();
	});

	it("returns undefined when the request throws or yields nothing (dead/timeout)", async () => {
		const state = createMockState({
			workspaceDiagnosticsSupport: {
				advertised: true,
				mode: "pull",
				workspaceDiagnostics: true,
				diagnosticProviderKind: "object",
			},
		});
		vi.mocked(state.connection.sendRequest).mockRejectedValue(new Error("dead"));
		expect(await clientRequestWorkspaceDiagnostics(state, 1000)).toBeUndefined();
	});
});
