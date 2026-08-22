import { describe, expect, it, vi } from "vitest";
import { inSessionDiagnosticsEnabled } from "../../clients/session-diagnostics.js";
import { diagnosticsExitCode } from "../../mcp/diagnostics-cli.js";
import { createPiMock } from "../support/pi-mock.js";

describe("fleet diagnostics execution", () => {
	it("keeps interactive diagnostics off unless explicitly enabled", () => {
		expect(inSessionDiagnosticsEnabled({})).toBe(false);
		expect(
			inSessionDiagnosticsEnabled({ PI_LENS_IN_SESSION_DIAGNOSTICS: "1" }),
		).toBe(true);
	});

	it("does not register diagnostic tools in interactive sessions", async () => {
		const previous = process.env.PI_LENS_IN_SESSION_DIAGNOSTICS;
		process.env.PI_LENS_IN_SESSION_DIAGNOSTICS = "0";
		vi.resetModules();
		try {
			const { default: extension } = await import("../../index.js");
			const pi = createPiMock();
			extension(pi.asExtensionAPI());
			for (const name of [
				"lens_diagnostics",
				"lsp_diagnostics",
				"lsp_navigation",
				"lens_diagnostic_mark",
			]) {
				expect(pi.tools.has(name), name).toBe(false);
			}
			expect(pi.tools.has("symbol_search")).toBe(true);
		} finally {
			if (previous === undefined)
				delete process.env.PI_LENS_IN_SESSION_DIAGNOSTICS;
			else process.env.PI_LENS_IN_SESSION_DIAGNOSTICS = previous;
		}
	});

	it("uses distinct clean, blocker, and incomplete exit codes", () => {
		expect(diagnosticsExitCode({ totalBlocking: 0 })).toBe(0);
		expect(diagnosticsExitCode({ totalBlocking: 1 })).toBe(1);
		expect(diagnosticsExitCode({ lspFilesUnconfirmed: 1 })).toBe(2);
		expect(diagnosticsExitCode({ lspFilesUnconfirmed: 1 }, false, true)).toBe(0);
		expect(
			diagnosticsExitCode(
				{ lspFilesUnconfirmed: 1, totalBlocking: 1 },
				false,
				true,
			),
		).toBe(1);
		expect(diagnosticsExitCode({ failedAnalyzers: [{ id: "knip" }] })).toBe(2);
		expect(
			diagnosticsExitCode(
				{ failedAnalyzers: [{ id: "knip" }] },
				false,
				true,
			),
		).toBe(2);
	});
});
