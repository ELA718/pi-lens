import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { parseGitleaksReport } from "../../clients/gitleaks-client.js";
import { setupTestEnvironment } from "./test-utils.js";

const cleanups: (() => void)[] = [];
afterEach(() => { for (const cleanup of cleanups.splice(0)) cleanup(); });

function scan(source: string, match: string, secret: string, extension = "ts", setup?: (cwd: string) => void) {
	const env = setupTestEnvironment("gitleaks-metadata-"); cleanups.push(env.cleanup);
	setup?.(env.tmpDir);
	const file = path.join(env.tmpDir, `metadata.${extension}`); fs.writeFileSync(file, source);
	const offset = source.indexOf(match);
	const line = source.slice(0, offset).split("\n").length;
	const raw = JSON.stringify([{ RuleID: "generic-api-key", File: file, StartLine: line, EndLine: line + match.split("\n").length - 1, Match: match, Secret: secret }]);
	return (parseGitleaksReport as (raw: string, cwd?: string) => ReturnType<typeof parseGitleaksReport>)(raw, env.tmpDir);
}

describe("secret-detector metadata provenance", () => {
	it("does not treat a following JSON property name as the preceding prose's secret", () => {
		const match = `key"',\n  '"E2E_ALLOW_DESTRUCTIVE"`;
		expect(scan(`const expected = ['"API_KEY": "approved public key"',\n  '"E2E_ALLOW_DESTRUCTIVE": "false"'];`, match, "E2E_ALLOW_DESTRUCTIVE")).toEqual([]);
	});
	it("retains an uppercase credential when it is a value", () => {
		const match = `key: "PRIVATE_CREDENTIAL_VALUE"`;
		expect(scan(`const ${match};`, match, "PRIVATE_CREDENTIAL_VALUE")).toHaveLength(1);
	});
	it("accepts an artifact fingerprint only when it equals the actual file hash", () => {
		const sql = "select 1;";
		const digest = createHash("sha256").update(sql).digest("hex");
		const name = "20260101000000_update_keys.sql";
		const match = `${name}',\n '${digest}'`;
		const source = `const expected = ['${match}];`;
		const setup = (cwd: string) => { fs.mkdirSync(path.join(cwd, "supabase/migrations"), { recursive: true }); fs.writeFileSync(path.join(cwd, "supabase/migrations", name), sql); };
		expect(scan(source, match, digest, "ts", setup)).toEqual([]);
		expect(scan(source, match, digest)).toHaveLength(1);
	});
	it.each(["expected_policy_sha256", "api_key"])("uses the actual SQL value column (%s)", column => {
		const digest = "a".repeat(64);
		const match = `authenticated', '${digest}'`;
		const source = `CREATE TEMP TABLE inventory (\n role_name text,\n ${column} text\n) ON COMMIT DROP;\nINSERT INTO inventory VALUES\n ('${match});`;
		expect(scan(source, match, digest, "sql")).toHaveLength(column.endsWith("_sha256") ? 0 : 1);
	});
});
