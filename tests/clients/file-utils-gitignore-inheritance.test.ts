import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { getProjectIgnoreMatcher } from "../../clients/file-utils.js";

const root = fs.mkdtempSync(
	path.join(os.tmpdir(), "pi-lens-ignore-inheritance-"),
);

function writeAt(
	repo: string,
	relativePath: string,
	content = "fixture\n",
): string {
	const target = path.join(repo, relativePath);
	fs.mkdirSync(path.dirname(target), { recursive: true });
	fs.writeFileSync(target, content);
	return target;
}

function write(relativePath: string, content = "fixture\n"): string {
	return writeAt(root, relativePath, content);
}

execFileSync("git", ["init", "-q"], { cwd: root });
write(
	".gitignore",
	[
		"/root-only",
		"generated",
		"!generated",
		"generated/*.tmp",
		"blocked/",
		"!blocked/child.txt",
		"blocked-nested/",
		"/cache/",
		"",
	].join("\n"),
);
write("apps/android/.gitignore", "app/src/main/assets/public\n");
write("pkg/.gitignore", "/cache/*\n!/cache/keep.txt\n");
write("blocked-nested/.gitignore", "!child.txt\n");

const paths = [
	"apps/android/app/src/main/assets/public/assets/index.js",
	"root-only/child.js",
	"generated/drop.tmp",
	"generated/keep.ts",
	"pkg/cache/drop.txt",
	"pkg/cache/keep.txt",
	"blocked/child.txt",
	"blocked-nested/child.txt",
	"cache/drop.txt",
	"other/cache/keep.txt",
] as const;
for (const relativePath of paths) write(relativePath);

function gitIgnored(repo: string, relativePath: string): boolean {
	const result = spawnSync("git", ["check-ignore", "-q", "--", relativePath], {
		cwd: repo,
	});
	expect(result.status, relativePath).toBeOneOf([0, 1]);
	return result.status === 0;
}

afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

describe("gitignore ignored-directory inheritance", () => {
	it("matches git check-ignore for descendants, negations, roots, and nested rules", () => {
		const matcher = getProjectIgnoreMatcher(root);
		for (const relativePath of paths) {
			expect(
				matcher.isIgnored(path.join(root, relativePath), false),
				relativePath,
			).toBe(gitIgnored(root, relativePath));
		}
		expect(
			matcher.isIgnored(
				path.join(root, "apps/android/app/src/main/assets/public"),
				true,
			),
		).toBe(true);
	});

	it("invalidates warm ancestor verdicts after a nested ignore edit", () => {
		const warmRoot = fs.mkdtempSync(
			path.join(os.tmpdir(), "pi-lens-ignore-warm-"),
		);
		try {
			execFileSync("git", ["init", "-q"], { cwd: warmRoot });
			const nestedIgnore = writeAt(warmRoot, "nested/.gitignore", "old/\n");
			for (const relativePath of [
				"nested/old/a.ts",
				"nested/old/z.ts",
				"nested/new-name/b.ts",
			])
				writeAt(warmRoot, relativePath);
			const matcher = getProjectIgnoreMatcher(warmRoot);
			expect(
				matcher.isIgnored(path.join(warmRoot, "nested/old/a.ts"), false),
			).toBe(true);
			const pinned = fs.statSync(nestedIgnore).mtime;
			fs.writeFileSync(nestedIgnore, "new-name/\n");
			fs.utimesSync(nestedIgnore, pinned, pinned);
			for (const relativePath of ["nested/old/z.ts", "nested/new-name/b.ts"])
				expect(
					matcher.isIgnored(path.join(warmRoot, relativePath), false),
					relativePath,
				).toBe(gitIgnored(warmRoot, relativePath));
		} finally {
			fs.rmSync(warmRoot, { recursive: true, force: true });
		}
	});
});
