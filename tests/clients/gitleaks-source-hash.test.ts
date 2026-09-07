import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { parseGitleaksReport, parseGitleaksReportWithProvenance } from "../../clients/gitleaks-client.js";
import { setupTestEnvironment } from "./test-utils.js";

function commitFixture(cwd: string, sourcePath: string): string {
	execFileSync("git", ["init", "-q"], { cwd });
	execFileSync("git", ["config", "user.email", "test@example.com"], { cwd });
	execFileSync("git", ["config", "user.name", "Test"], { cwd });
	execFileSync("git", ["add", "--", sourcePath], { cwd });
	execFileSync("git", ["commit", "-qm", "fixture"], { cwd });
	return execFileSync("git", ["rev-parse", "HEAD"], { cwd, encoding: "utf-8" }).trim();
}

const cleanups: (() => void)[] = [];
afterEach(() => { for (const cleanup of cleanups.splice(0)) cleanup(); });

function fixture(source = "export const value = 1;\n") {
	const env = setupTestEnvironment("gitleaks-source-hash-");
	cleanups.push(env.cleanup);
	const sourcePath = "src/auth/token.test.ts";
	const fullSourcePath = path.join(env.tmpDir, sourcePath);
	fs.mkdirSync(path.dirname(fullSourcePath), { recursive: true });
	fs.writeFileSync(fullSourcePath, source);
	const digest = createHash("sha256").update(source).digest("hex");
	return { ...env, sourcePath, fullSourcePath, digest };
}

function finding(file: string, match: string, secret: string, startLine: number, rule = "generic-api-key") {
	return { RuleID: rule, File: file, StartLine: startLine, EndLine: startLine + match.split("\n").length - 1, Match: match, Secret: secret };
}

function scan(cwd: string, file: string, match: string, secret: string, startLine: number, rule?: string) {
	return parseGitleaksReport(JSON.stringify([finding(file, match, secret, startLine, rule)]), cwd);
}

function historicalScan(cwd: string, file: string, match: string, secret: string, startLine: number, rule?: string, signal?: AbortSignal) {
	return parseGitleaksReportWithProvenance(JSON.stringify([finding(file, match, secret, startLine, rule)]), cwd, signal);
}

function writeAudit(cwd: string, sourcePath: string, digest: string, extra = "") {
	const file = path.join(cwd, "audit.json");
	const text = `{\n  "tbBaseCommit": "abc123",\n  "sourceSha256": {\n    ${JSON.stringify(sourcePath)}: ${JSON.stringify(digest)}${extra}\n  }\n}\n`;
	fs.writeFileSync(file, text);
	const match = `${path.basename(sourcePath)}\": \"${digest}\"`;
	return { file, text, match, line: 4 };
}

describe("generic-api-key source hash provenance", () => {
	it("removes only the digest of the exact current source bytes", () => {
		const env = fixture();
		const audit = writeAudit(env.tmpDir, env.sourcePath, env.digest);
		expect(scan(env.tmpDir, audit.file, audit.match, env.digest, audit.line)).toEqual([]);

		fs.appendFileSync(env.fullSourcePath, "// changed\n");
		expect(scan(env.tmpDir, audit.file, audit.match, env.digest, audit.line)).toHaveLength(1);
	});

	it("retains a wrong digest and an opaque value outside the source hash map", () => {
		const env = fixture();
		const wrong = "a".repeat(64);
		const audit = writeAudit(env.tmpDir, env.sourcePath, wrong);
		expect(scan(env.tmpDir, audit.file, audit.match, wrong, audit.line)).toHaveLength(1);

		const opaqueFile = path.join(env.tmpDir, "opaque.json");
		const opaque = `{\n  "apiKeySha256": "${env.digest}"\n}\n`;
		fs.writeFileSync(opaqueFile, opaque);
		expect(scan(env.tmpDir, opaqueFile, `apiKeySha256\": \"${env.digest}\"`, env.digest, 2)).toHaveLength(1);
	});

	it("retains provider-specific rules and findings at the wrong location", () => {
		const env = fixture();
		const audit = writeAudit(env.tmpDir, env.sourcePath, env.digest);
		expect(scan(env.tmpDir, audit.file, audit.match, env.digest, audit.line, "github-pat")).toHaveLength(1);
		expect(scan(env.tmpDir, audit.file, audit.match, env.digest, audit.line + 1)).toHaveLength(1);
	});

	it("retains traversal and symlink escapes", () => {
		const env = fixture();
		const outside = path.join(env.tmpDir, "..", `${path.basename(env.tmpDir)}-outside-token.test.ts`);
		cleanups.push(() => fs.rmSync(outside, { force: true }));
		fs.writeFileSync(outside, "outside\n");
		const digest = createHash("sha256").update("outside\n").digest("hex");
		const traversal = writeAudit(env.tmpDir, `../${path.basename(outside)}`, digest);
		expect(scan(env.tmpDir, traversal.file, traversal.match, digest, traversal.line)).toHaveLength(1);

		const link = path.join(env.tmpDir, "linked-token.test.ts");
		fs.symlinkSync(outside, link);
		const symlink = writeAudit(env.tmpDir, path.basename(link), digest);
		expect(scan(env.tmpDir, symlink.file, symlink.match, digest, symlink.line)).toHaveLength(1);
	});

	it("removes a historical digest proven by its envelope commit", async () => {
		const env = fixture();
		const commit = commitFixture(env.tmpDir, env.sourcePath);
		fs.writeFileSync(env.fullSourcePath, "changed after evidence\n");
		const file = path.join(env.tmpDir, "historical-proven.json");
		fs.writeFileSync(file, `{"priorRecounts":[{"verifiedSourceCommit":"${commit}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${env.digest}"}}]}\n`);
		expect(await historicalScan(env.tmpDir, file, `token.test.ts\":\"${env.digest}`, env.digest, 1)).toEqual([]);
	});

	it("retains hostile historical proof payloads", async () => {
		const env = fixture();
		const commit = commitFixture(env.tmpDir, env.sourcePath);
		fs.writeFileSync(env.fullSourcePath, "changed after evidence\n");
		const blobId = execFileSync("git", ["rev-parse", `${commit}:${env.sourcePath}`], { cwd: env.tmpDir, encoding: "utf-8" }).trim();
		const cases = [
			[`{"verifiedSourceCommit":"${"a".repeat(40)}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${env.digest}"}}`, "token.test.ts", env.digest],
			[`{"verifiedSourceCommit":"${blobId}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${env.digest}"}}`, "token.test.ts", env.digest],
			[`{"verifiedSourceCommit":"${commit}","sourceSha256":{"../escape.ts":"${env.digest}"}}`, "escape.ts", env.digest],
			[`{"verifiedSourceCommit":"${commit}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${"a".repeat(64)}"}}`, "token.test.ts", "a".repeat(64)],
			[`{"verifiedSourceCommit":"${commit}"},{"sourceSha256":{${JSON.stringify(env.sourcePath)}:"${env.digest}"}}`, "token.test.ts", env.digest],
			[`{"verifiedSourceCommit":"${commit}","verifiedSourceCommit":"${commit}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${env.digest}"}}`, "token.test.ts", env.digest],
			[`{"verifiedSourceCommit":"${commit}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${env.digest}",${JSON.stringify(env.sourcePath)}:"${env.digest}"}}`, "token.test.ts", env.digest],
		] as const;
		for (const [index, [body, matchedPath, secret]] of cases.entries()) {
			const file = path.join(env.tmpDir, `hostile-${index}.json`);
			fs.writeFileSync(file, `{"priorRecounts":[${body}]}\n`);
			expect(await historicalScan(env.tmpDir, file, `${matchedPath}\":\"${secret}`, secret, 1)).toHaveLength(1);
		}
		const replacement = "replacement object bytes\n";
		fs.writeFileSync(env.fullSourcePath, replacement);
		execFileSync("git", ["add", "--", env.sourcePath], { cwd: env.tmpDir });
		execFileSync("git", ["commit", "-qm", "replacement"], { cwd: env.tmpDir });
		const replacementCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: env.tmpDir, encoding: "utf-8" }).trim();
		execFileSync("git", ["replace", commit, replacementCommit], { cwd: env.tmpDir });
		const replacementDigest = createHash("sha256").update(replacement).digest("hex");
		const file = path.join(env.tmpDir, "replacement.json");
		fs.writeFileSync(file, `{"priorRecounts":[{"verifiedSourceCommit":"${commit}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${replacementDigest}"}}]}\n`);
		expect(await historicalScan(env.tmpDir, file, `token.test.ts\":\"${replacementDigest}`, replacementDigest, 1)).toHaveLength(1);
	});

	it("retains duplicate reports, provider rules, cancellation, symlinks, and oversized blobs", async () => {
		const env = fixture();
		const commit = commitFixture(env.tmpDir, env.sourcePath);
		fs.writeFileSync(env.fullSourcePath, "changed after evidence\n");
		const file = path.join(env.tmpDir, "proof.json");
		fs.writeFileSync(file, `{"verifiedSourceCommit":"${commit}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${env.digest}"}}\n`);
		const match = `token.test.ts\":\"${env.digest}`;
		const duplicate = finding(file, match, env.digest, 1);
		expect(await parseGitleaksReportWithProvenance(JSON.stringify([duplicate, duplicate]), env.tmpDir)).toHaveLength(2);
		expect(await historicalScan(env.tmpDir, file, match, env.digest, 1, "github-pat")).toHaveLength(1);
		const controller = new AbortController(); controller.abort();
		expect(await historicalScan(env.tmpDir, file, match, env.digest, 1, undefined, controller.signal)).toHaveLength(1);

		const linkPath = "linked-token.test.ts";
		fs.symlinkSync(env.sourcePath, path.join(env.tmpDir, linkPath));
		execFileSync("git", ["add", "--", linkPath], { cwd: env.tmpDir });
		execFileSync("git", ["commit", "-qm", "link"], { cwd: env.tmpDir });
		const linkCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: env.tmpDir, encoding: "utf-8" }).trim();
		const linkFile = path.join(env.tmpDir, "link-proof.json");
		fs.writeFileSync(linkFile, `{"verifiedSourceCommit":"${linkCommit}","sourceSha256":{"${linkPath}":"${env.digest}"}}\n`);
		expect(await historicalScan(env.tmpDir, linkFile, `linked-token.test.ts\":\"${env.digest}`, env.digest, 1)).toHaveLength(1);

		const bigPath = "big.test.ts";
		const big = Buffer.alloc(1_048_577, 120);
		fs.writeFileSync(path.join(env.tmpDir, bigPath), big);
		execFileSync("git", ["add", "--", bigPath], { cwd: env.tmpDir });
		execFileSync("git", ["commit", "-qm", "big"], { cwd: env.tmpDir });
		const bigCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: env.tmpDir, encoding: "utf-8" }).trim();
		const bigDigest = createHash("sha256").update(big).digest("hex");
		const bigFile = path.join(env.tmpDir, "big-proof.json");
		fs.writeFileSync(bigFile, `{"verifiedSourceCommit":"${bigCommit}","sourceSha256":{"${bigPath}":"${bigDigest}"}}\n`);
		expect(await historicalScan(env.tmpDir, bigFile, `big.test.ts\":\"${bigDigest}`, bigDigest, 1)).toHaveLength(1);
	});

	it("retains proof when local Git times out", async () => {
		const env = fixture();
		const commit = commitFixture(env.tmpDir, env.sourcePath);
		fs.writeFileSync(env.fullSourcePath, "changed after evidence\n");
		const file = path.join(env.tmpDir, "timeout-proof.json");
		fs.writeFileSync(file, `{"verifiedSourceCommit":"${commit}","sourceSha256":{${JSON.stringify(env.sourcePath)}:"${env.digest}"}}\n`);
		const fakeBin = path.join(env.tmpDir, "fake-bin");
		fs.mkdirSync(fakeBin);
		fs.writeFileSync(path.join(fakeBin, "git"), `#!${process.execPath}\nsetInterval(() => {}, 1000);\n`, { mode: 0o755 });
		const savedPath = process.env.PATH;
		process.env.PATH = `${fakeBin}${path.delimiter}${savedPath ?? ""}`;
		try {
			expect(await historicalScan(env.tmpDir, file, `token.test.ts\":\"${env.digest}`, env.digest, 1)).toHaveLength(1);
		} finally { process.env.PATH = savedPath; }
	}, 4_000);

	it("retains historical, duplicate, and malformed metadata", async () => {
		const env = fixture();
		const historicalFile = path.join(env.tmpDir, "historical.json");
		const historical = `{\n  "priorRecounts": [{\n    "verifiedSourceCommit": "deadbeef",\n    "sourceSha256": { ${JSON.stringify(env.sourcePath)}: "${env.digest}" }\n  }]\n}\n`;
		fs.writeFileSync(historicalFile, historical);
		expect(await historicalScan(env.tmpDir, historicalFile, `token.test.ts\": \"${env.digest}\"`, env.digest, 4)).toHaveLength(1);

		const duplicateFile = path.join(env.tmpDir, "duplicate.json");
		const duplicate = `{\n  "sourceSha256": {\n    ${JSON.stringify(env.sourcePath)}: "${env.digest}",\n    ${JSON.stringify(env.sourcePath)}: "${env.digest}"\n  }\n}\n`;
		fs.writeFileSync(duplicateFile, duplicate);
		expect(await historicalScan(env.tmpDir, duplicateFile, `token.test.ts\": \"${env.digest}\"`, env.digest, 3)).toHaveLength(1);

		const malformedFile = path.join(env.tmpDir, "malformed.json");
		fs.writeFileSync(malformedFile, `{ "sourceSha256": { ${JSON.stringify(env.sourcePath)}: "${env.digest}"`);
		expect(await historicalScan(env.tmpDir, malformedFile, `token.test.ts\": \"${env.digest}`, env.digest, 1)).toHaveLength(1);
	});

	it.skipIf(process.platform === "win32")("retains a nonregular source without blocking", () => {
		const env = fixture();
		const fifoPath = path.join(env.tmpDir, "fifo-token.test.ts");
		execFileSync("mkfifo", [fifoPath]);
		const digest = "a".repeat(64);
		const audit = writeAudit(env.tmpDir, path.basename(fifoPath), digest);
		const raw = JSON.stringify([finding(audit.file, audit.match, digest, audit.line)]);
		const moduleUrl = pathToFileURL(path.resolve("clients/gitleaks-client.js")).href;
		const script = `import { parseGitleaksReport } from ${JSON.stringify(moduleUrl)}; if (parseGitleaksReport(${JSON.stringify(raw)}, ${JSON.stringify(env.tmpDir)}).length !== 1) process.exit(2);`;
		const result = spawnSync(process.execPath, ["--input-type=module", "--eval", script], { timeout: 1_000 });
		expect(result.error).toBeUndefined();
		expect(result.status).toBe(0);
	});

	it("retains proof that exceeds bounded metadata or source reads", () => {
		const env = fixture("x".repeat(1_048_577));
		const sourceAudit = writeAudit(env.tmpDir, env.sourcePath, env.digest);
		expect(scan(env.tmpDir, sourceAudit.file, sourceAudit.match, env.digest, sourceAudit.line)).toHaveLength(1);

		const small = fixture();
		const metadataAudit = writeAudit(small.tmpDir, small.sourcePath, small.digest, `,\n    "padding": "${"x".repeat(1_048_577)}"`);
		expect(scan(small.tmpDir, metadataAudit.file, metadataAudit.match, small.digest, metadataAudit.line)).toHaveLength(1);
	});
});
