export function inSessionDiagnosticsEnabled(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	return env.PI_LENS_IN_SESSION_DIAGNOSTICS === "1";
}
