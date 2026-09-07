import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { getProjectIgnoreMatcher } from "../../clients/file-utils.js";

const root = fs.mkdtempSync(
	path.join(os.tmpdir(), "pi-lens-ignore-inheritance-"),
);

function write(relativePath: string, content = "fixture\n"): string {
	const target = path.join(root, relativePath);
	fs.mkdirSync(path.dirname(target), { recursive: true });
	fs.writeFileSync(target, content);
	return target;
}

execFileSync("git", ["init", "-q"], { cwd: root });
write(
	".gitignore",
	["/root-only", "generated", "!generated", "generated/*.tmp", ""].join("\n"),
);
write("apps/android/.gitignore", "app/src/main/assets/public\n");
write("pkg/.gitignore", "/cache/*\n!/cache/keep.txt\n");

const paths = [
	"apps/android/app/src/main/assets/public/assets/index.js",
	"root-only/child.js",
	"generated/drop.tmp",
	"generated/keep.ts",
	"pkg/cache/drop.txt",
	"pkg/cache/keep.txt",
] as const;
for (const relativePath of paths) write(relativePath);

afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

describe("gitignore ignored-directory inheritance", () => {
	it("matches git check-ignore for descendants, negations, roots, and nested rules", () => {
		const matcher = getProjectIgnoreMatcher(root);
		for (const relativePath of paths) {
			const git = spawnSync("git", ["check-ignore", "-q", "--", relativePath], {
				cwd: root,
			});
			expect(git.status, relativePath).toBeOneOf([0, 1]);
			expect(
				matcher.isIgnored(path.join(root, relativePath), false),
				relativePath,
			).toBe(git.status === 0);
		}
		expect(
			matcher.isIgnored(
				path.join(root, "apps/android/app/src/main/assets/public"),
				true,
			),
		).toBe(true);
	});
});
