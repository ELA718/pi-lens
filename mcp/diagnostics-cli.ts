import { CacheManager } from "../clients/cache-manager.js";
import { resetLSPService } from "../clients/lsp/index.js";
import { createLensDiagnosticsTool } from "../tools/lens-diagnostics.js";

export interface DiagnosticsCliResult {
	text: string;
	details: Record<string, unknown>;
	exitCode: 0 | 1 | 2;
}

export function diagnosticsExitCode(
	details: Record<string, unknown>,
	isError = false,
	allowUnconfirmedLsp = false,
): 0 | 1 | 2 {
	const incomplete =
		isError ||
		details.partial === true ||
		details.timedOut === true ||
		details.lspUnavailable === true ||
		(!allowUnconfirmedLsp && Number(details.lspFilesUnconfirmed ?? 0) > 0) ||
		(Array.isArray(details.failedAnalyzers) &&
			details.failedAnalyzers.length > 0) ||
		details.analyzersAborted === true ||
		details.analyzersUnsafeRoot === true ||
		details.projectWalkUnsafeRoot === true ||
		details.projectScanTruncated === true;
	if (incomplete) return 2;
	return Number(details.totalBlocking ?? 0) > 0 ? 1 : 0;
}

export async function runDiagnostics(
	cwd: string,
	options: {
		maxLspFiles?: number;
		maxProjectFiles?: number;
		allowUnconfirmedLsp?: boolean;
	} = {},
): Promise<DiagnosticsCliResult> {
	const tool = createLensDiagnosticsTool(new CacheManager(), () => cwd);
	try {
		const result = (await tool.execute(
			"cli",
			{
				mode: "full",
				refreshRunners: "all",
				maxLspFiles: options.maxLspFiles,
				maxProjectFiles: options.maxProjectFiles,
			},
			new AbortController().signal,
			undefined,
			{ cwd },
		)) as {
			content: Array<{ type: "text"; text: string }>;
			details?: Record<string, unknown>;
			isError?: boolean;
		};
		const details = result.details ?? {};
		return {
			text: result.content.map((item) => item.text).join("\n"),
			details,
			exitCode: diagnosticsExitCode(
				details,
				result.isError === true,
				options.allowUnconfirmedLsp,
			),
		};
	} finally {
		await resetLSPService({ reason: "ci_diagnostics" });
	}
}
