import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { suspendAt, waitFor } from "../interleaving-kit.js";
import { removeTempDirSync } from "../test-utils.js";

vi.mock("../../../clients/lsp/config.js", () => ({
	getServersForFileWithConfig: () => [{ id: "typescript", extensions: [".ts"], root: async () => undefined }],
	getServerInitOverride: vi.fn(),
}));
vi.mock("../../../clients/lsp/client.js", () => ({ createLSPClient: vi.fn() }));

describe("workspace sweep cancellation (#4)", () => {
	afterEach(() => vi.restoreAllMocks());

	it("does not open a document when client acquisition finishes after cancellation", async () => {
		const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "lens-preopen-cancel-")));
		const file = path.join(tmp, "a.ts");
		fs.writeFileSync(file, "const x = 1;\n");
		const { LSPService } = await import("../../../clients/lsp/index.js");
		const service = new LSPService();
		vi.spyOn(service, "ensureWarmForSweep").mockResolvedValue({ performedWarmup: false, failedServerIds: [] });
		const acquisition = vi.spyOn(service, "getClientsForFile");
		const open = vi.fn();
		const shutdown = vi.fn();
		// Only the two observable client operations matter at this suspended seam.
		const clients = [{ client: { notify: { open }, shutdown } }] as unknown as Awaited<ReturnType<typeof service.getClientsForFile>>["clients"];
		const suspension = suspendAt(acquisition, async () => ({ clients, serverCountAttempted: 1 }));
		const controller = new AbortController();
		let settled = false;
		const scan = service.runWorkspaceDiagnostics(tmp, { files: [file], signal: controller.signal }).then(result => { settled = true; return result; });
		try {
			await suspension.admitted;
			controller.abort();
			await waitFor(() => settled, Boolean, { timeoutMs: 1_000 });
			expect(await scan).toEqual([]);
			suspension.release();
			await suspension.completed;
			await new Promise<void>(resolve => setImmediate(resolve));
			expect(open).not.toHaveBeenCalled();
			expect(shutdown).not.toHaveBeenCalled();
		} finally {
			suspension.release();
			await scan;
			suspension.restore();
			removeTempDirSync(tmp);
		}
	});

	it("preserves completed findings, marks the interrupted file unconfirmed, and ignores late results", async () => {
		const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "lens-cancel-")));
		const files = ["a.ts", "b.ts", "c.ts"].map(name => path.join(tmp, name));
		for (const file of files) fs.writeFileSync(file, "const x = 1;\n");
		const { LSPService } = await import("../../../clients/lsp/index.js");
		const service = new LSPService();
		vi.spyOn(service, "ensureWarmForSweep").mockResolvedValue({ performedWarmup: false, failedServerIds: [] });
		vi.spyOn(service, "getClientsForFile").mockResolvedValue({ clients: [], serverCountAttempted: 0 });
		const diagnostic = { severity: 1 as const, message: "existing blocker", range: { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } } };
		const touch = vi.spyOn(service, "touchFile");
		const suspension = suspendAt(touch, async () => ({ diags: [diagnostic] }));
		touch.mockResolvedValueOnce({ diags: [diagnostic] });
		const controller = new AbortController();
		const progress = vi.fn();
		let settled = false;
		const scan = service.runWorkspaceDiagnostics(tmp, { files, signal: controller.signal, onProgress: progress }).then(result => { settled = true; return result; });
		try {
			await suspension.admitted;
			controller.abort();
			await waitFor(() => settled, Boolean, { timeoutMs: 1_000 });
			const results = await scan;
			expect(results).toHaveLength(2);
			expect(results[0]).toMatchObject({ filePath: files[0], diagnostics: [diagnostic], timedOut: false });
			expect(results[1]).toMatchObject({ filePath: files[1], diagnostics: [], timedOut: true });
			const snapshot = JSON.stringify(results);
			const progressCount = progress.mock.calls.length;
			suspension.release();
			await suspension.completed;
			await new Promise<void>(resolve => setImmediate(resolve));
			expect(JSON.stringify(results)).toBe(snapshot);
			expect(progress).toHaveBeenCalledTimes(progressCount);
			expect(touch).toHaveBeenCalledTimes(2);
		} finally {
			suspension.release();
			await scan;
			suspension.restore();
			removeTempDirSync(tmp);
		}
	});
});
