import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import {
	findLocalToolConfig,
	findNearestContaining,
	findNearestMarkerRoot,
	isFullyQualified,
	isFullyQualifiedPosix,
	isFullyQualifiedWin32,
	isAtOrAboveHomeDir,
	isExternalOrVendorFile,
	normalizeEphemeralMapKey,
	normalizeFilePath,
	normalizeMapKey,
	normalizePhysicalMapKey,
	pathToUri,
	splitPathSegments,
	toPosix,
	toProjectRelativePath,
	uriToPath,
	walkUpDirs,
} from "../../clients/path-utils.js";
import { setupTestEnvironment } from "./test-utils.js";

describe.skipIf(process.platform !== "darwin")("macOS physical path identity", () => {
	it("resolves existing aliases without changing display keys or missing-name case", () => {
		const env = setupTestEnvironment("pi-lens-physical-path-");
		try {
			const file = path.join(env.tmpDir, "MixedCase.ts");
			fs.writeFileSync(file, "");
			const alias = path.join(env.tmpDir, "alias.ts");
			fs.symlinkSync(file, alias);
			expect(normalizePhysicalMapKey(alias)).toBe(normalizePhysicalMapKey(file));
			expect(normalizeMapKey(file)).toBe(file);
			if (fs.existsSync(file.toUpperCase())) {
				expect(normalizePhysicalMapKey(file.toUpperCase())).toBe(normalizePhysicalMapKey(file));
			}
			const missing = path.join(env.tmpDir, "NewDir", "NewFile.ts");
			expect(normalizePhysicalMapKey(missing)).toBe(path.join(fs.realpathSync.native(env.tmpDir), "NewDir", "NewFile.ts"));
			expect(isExternalOrVendorFile(missing, env.tmpDir)).toBe(false);
		} finally { env.cleanup(); }
	});

	it("keeps symlink escapes and vendor aliases outside the pipeline", () => {
		const env = setupTestEnvironment("pi-lens-physical-boundary-");
		try {
			const root = path.join(env.tmpDir, "project");
			fs.mkdirSync(path.join(root, "node_modules"), { recursive: true });
			const outside = path.join(env.tmpDir, "outside.ts");
			fs.writeFileSync(outside, "");
			const vendor = path.join(root, "node_modules", "vendor.ts");
			fs.writeFileSync(vendor, "");
			for (const [name, target] of [["escape.ts", outside], ["vendor-alias.ts", vendor]]) {
				const alias = path.join(root, name);
				fs.symlinkSync(target, alias);
				expect(isExternalOrVendorFile(alias, root)).toBe(true);
			}
		} finally { env.cleanup(); }
	});
});

describe("isWindowsPath (#1213 review pins)", () => {
	it("matches drive-prefixed and UNC shapes only", async () => {
		const { isWindowsPath } = await import("../../clients/path-utils.js");
		expect(isWindowsPath("C:\foo")).toBe(true);
		expect(isWindowsPath("D:relative")).toBe(true);
		expect(isWindowsPath("\\server\share")).toBe(true);
		expect(isWindowsPath("/path/to/file")).toBe(false);
		// Backslashes are legal in POSIX filenames — embedded ones must not
		// classify a path as Windows-shaped (the Linux CI regression).
		expect(isWindowsPath("/ordinary\name")).toBe(false);
	});
});

describe("isFullyQualified matrix additions (#1213 review pins)", () => {
	it("classifies long-path and embedded-backslash forms", async () => {
		const { isFullyQualifiedWin32, isFullyQualifiedPosix } = await import(
			"../../clients/path-utils.js"
		);
		expect(isFullyQualifiedWin32("\\\\?\\C:\\very\\long\\path")).toBe(true);
		expect(isFullyQualifiedPosix("/ordinary\\name")).toBe(true);
	});
});

describe("path-utils", () => {
	const fullyQualifiedMatrix = [
		["Windows drive-relative", "C:foo", false, false],
		["Windows rooted-relative", "\\foo", false, false],
		["Windows drive-absolute", "C:\\foo", false, true],
		["Windows UNC", "\\\\server\\share", false, true],
		["POSIX root", "/", true, false],
		["POSIX absolute", "/abs/path", true, false],
		["relative", "rel/path", false, false],
		["dot-relative", "./rel", false, false],
	] as const;
	it.each(fullyQualifiedMatrix)("isFullyQualifiedPosix: %s", (_label, value, expected) => {
		expect(isFullyQualifiedPosix(value)).toBe(expected);
	});
	it.each(fullyQualifiedMatrix)("isFullyQualifiedWin32: %s", (_label, value, _posix, expected) => {
		expect(isFullyQualifiedWin32(value)).toBe(expected);
	});
	it("classifies /foo according to explicit platform semantics", () => {
		expect(isFullyQualifiedWin32(path.posix.join(path.posix.sep, "foo"))).toBe(false);
		expect(isFullyQualifiedPosix(path.posix.join(path.posix.sep, "foo"))).toBe(true);
	});
	it("classifies ordinary host-native paths through the ambient helper", () => {
		const hostNative = path.join(path.parse(process.cwd()).root, "ordinary", "host-native");
		expect(isFullyQualified(hostNative)).toBe(true);
		if (process.platform === "win32") {
			expect(isFullyQualifiedWin32(hostNative)).toBe(true);
		} else {
			expect(isFullyQualifiedPosix(hostNative)).toBe(true);
		}
	});
	it("uriToPath decodes URL-encoded file URIs", () => {
		const uri = "file:///C:/Users/Test%20User/project/file.ts";
		const resolved = uriToPath(uri);

		expect(resolved.includes("%20")).toBe(false);
		expect(resolved.toLowerCase()).toContain("test user");
	});

	it("pathToUri + uriToPath round-trips an existing file", () => {
		const { tmpDir, cleanup } = setupTestEnvironment("pi-lens-path-");
		try {
			const filePath = path.join(tmpDir, "src", "main.ts");
			fs.mkdirSync(path.dirname(filePath), { recursive: true });
			fs.writeFileSync(filePath, "export const x = 1;\n");

			const uri = pathToUri(filePath);
			const back = uriToPath(uri);

			expect(back.endsWith("/src/main.ts")).toBe(true);
		} finally {
			cleanup();
		}
	});
});

describe("normalizeFilePath: Windows-shaped path is OS-coherent (refs #1150, class #1024)", () => {
	// A drive-letter/UNC-shaped path enters normalizeFilePath's win32 branch on
	// ANY OS (isWindowsPath classifies by shape, not platform). Before #1150 the
	// win32-committed resolveNonExisting fallback used the platform-default
	// `dirname`: POSIX on Linux, which finds no separator in a win32-resolved
	// "C:\..." path, collapses to ".", stops the upward walk at cwd, and mangles
	// the key to `<cwd>/file.ts`. On Windows the same input keyed correctly, so
	// a test hardcoding a drive-letter literal passed on Windows and failed on
	// Linux CI (#1139). This test is meaningful on BOTH OSes: native win32 path
	// on Windows, shape-committed win32 branch on Linux.
	//
	// Path is guaranteed non-existent so the fallback (not realpathSync.native)
	// runs on both OSes.
	const nonExistent = "C:/__pi_lens_1150_nonexistent__/sub/file.ts";
	const nonExistentBack = "C:\\__pi_lens_1150_nonexistent__\\sub\\file.ts";
	const structuralTail = "/__pi_lens_1150_nonexistent__/sub/file.ts";

	it("forward-slash and backslash forms normalize to the same key (coherence)", () => {
		expect(normalizeFilePath(nonExistent)).toBe(normalizeFilePath(nonExistentBack));
	});

	it("preserves the path structure and drive-letter shape — never collapses to a cwd-relative key", () => {
		const key = normalizeFilePath(nonExistent);
		// Structure preserved: full literal tail survives (drive-letter case may
		// differ — uppercase on Windows, lowercased by the Linux fallback — so
		// compare case-insensitively). PRE-FIX on Linux this was `<cwd>/file.ts`,
		// dropping "__pi_lens_1150_nonexistent__/sub" entirely.
		expect(key.toLowerCase().endsWith(structuralTail.toLowerCase())).toBe(true);
		// Retains drive-letter shape, i.e. is NOT rooted at the POSIX cwd. PRE-FIX
		// on Linux the mangled key started with the process cwd ("/home/..."),
		// which has no drive letter.
		expect(/^[A-Za-z]:/.test(key)).toBe(true);
		// Explicitly cwd-independent: the process working directory must not
		// appear in the key.
		expect(key.toLowerCase()).not.toContain(process.cwd().replace(/\\/g, "/").toLowerCase());
	});

	it("normalizeMapKey (the map-key entry point) yields the same stable key", () => {
		expect(normalizeMapKey(nonExistent)).toBe(normalizeFilePath(nonExistent));
		expect(normalizeMapKey(nonExistentBack)).toBe(normalizeMapKey(nonExistent));
	});
});

describe("toProjectRelativePath: Windows-shaped path relativizes on ANY OS (refs #1163, class #1150/#1024)", () => {
	// A drive-letter-shaped filePath UNDER a drive-letter-shaped projectRoot must
	// relativize by win32 semantics on any OS — the shape decides the parser, not
	// `process.platform`. PRE-FIX on Linux, the host-default `path.isAbsolute`
	// returns false for a "C:\..." path (no POSIX leading slash), so the function
	// short-circuited and returned the whole absolute path instead of the
	// project-relative one. On Windows the same input relativized correctly, so a
	// Linux CI run diverged from a green Windows run (the #1024 class). Inputs are
	// fed as literals; the expectation is derived structurally, not hardcoded to a
	// normalized key (the #1139/#1150 vacuous-fixture trap).
	it("backslash form under a backslash root → forward-slashed project-relative path", () => {
		expect(
			toProjectRelativePath("C:\\repo\\src\\x.ts", "C:\\repo"),
		).toBe("src/x.ts");
	});

	it("forward-slash win32 form under a win32 root → project-relative path", () => {
		expect(
			toProjectRelativePath("C:/repo/src/nested/y.ts", "C:/repo"),
		).toBe("src/nested/y.ts");
	});

	it("UNC-shaped path under a UNC root relativizes rather than returning the whole path", () => {
		const rel = toProjectRelativePath(
			"\\\\host\\share\\proj\\src\\z.ts",
			"\\\\host\\share\\proj",
		);
		expect(rel).toBe("src/z.ts");
	});

	it("a win32 file OUTSIDE the win32 root keeps the (slash-folded) absolute path", () => {
		// Not under the root → not relativized; must stay the full path, never a
		// "../"-prefixed escape.
		expect(
			toProjectRelativePath("C:\\other\\a.ts", "C:\\repo"),
		).toBe("C:/other/a.ts");
	});
});

describe("normalizeEphemeralMapKey (refs #191)", () => {
	it("folds backslash and forward-slash forms to the same key", () => {
		const forward = "C:/Users/foo/src/plan.js";
		const back = "C:\\Users\\foo\\src\\plan.js";

		expect(normalizeEphemeralMapKey(forward)).toBe(
			normalizeEphemeralMapKey(back),
		);
	});

	it("does not touch the filesystem (never throws for a nonexistent path, no realpath resolution)", () => {
		const nonExistent = "C:\\definitely\\not\\a\\real\\path\\file.ts";
		expect(() => normalizeEphemeralMapKey(nonExistent)).not.toThrow();
		// Purely syntactic: slash-folded (+ lowercased on win32), not
		// realpath-resolved, so it must not depend on the path existing.
		expect(normalizeEphemeralMapKey(nonExistent)).toContain(
			"/definitely/not/a/real/path/file.ts",
		);
	});

	it("is case-insensitive on win32 semantics (matches this suite's Windows CI target)", () => {
		if (process.platform !== "win32") return;
		expect(normalizeEphemeralMapKey("C:\\Foo\\BAR.TS")).toBe(
			normalizeEphemeralMapKey("c:\\foo\\bar.ts"),
		);
	});
});

describe("walkUpDirs / findNearestContaining (#122)", () => {
	it("walkUpDirs yields every directory from startDir up to the filesystem root and stops", () => {
		const env = setupTestEnvironment("pi-lens-walkup-");
		try {
			const startDir = path.join(env.tmpDir, "a", "b", "c");
			fs.mkdirSync(startDir, { recursive: true });

			const visited = [...walkUpDirs(startDir)];
			expect(visited[0]).toBe(path.resolve(startDir));
			// Must include the chain a/b, a, and the tmp root.
			expect(visited).toContain(path.resolve(env.tmpDir, "a", "b"));
			expect(visited).toContain(path.resolve(env.tmpDir, "a"));
			expect(visited).toContain(path.resolve(env.tmpDir));
			// Last entry must be the filesystem root (no further dirname change).
			const last = visited[visited.length - 1];
			expect(path.dirname(last)).toBe(last);
		} finally {
			env.cleanup();
		}
	});

	it("findNearestContaining returns the nearest containing directory, not a higher one", () => {
		const env = setupTestEnvironment("pi-lens-find-nearest-");
		try {
			const inner = path.join(env.tmpDir, "outer", "inner");
			fs.mkdirSync(inner, { recursive: true });
			// Put a marker at BOTH levels. Nearest wins.
			fs.writeFileSync(path.join(env.tmpDir, "outer", "package.json"), "{}");
			fs.writeFileSync(path.join(env.tmpDir, "outer", "inner", "package.json"), "{}");

			const startDir = path.join(inner, "src");
			fs.mkdirSync(startDir, { recursive: true });
			const found = findNearestContaining(startDir, ["package.json"]);
			expect(found && path.resolve(found)).toBe(path.resolve(inner));
		} finally {
			env.cleanup();
		}
	});

	it("findNearestContaining matches the first candidate filename that exists", () => {
		const env = setupTestEnvironment("pi-lens-find-multi-");
		try {
			fs.writeFileSync(path.join(env.tmpDir, "Cargo.toml"), "[package]");
			const startDir = path.join(env.tmpDir, "src");
			fs.mkdirSync(startDir, { recursive: true });
			const found = findNearestContaining(startDir, [
				"package.json",
				"Cargo.toml",
				"go.mod",
			]);
			expect(found && path.resolve(found)).toBe(path.resolve(env.tmpDir));
		} finally {
			env.cleanup();
		}
	});

	it("findNearestContaining returns undefined when no candidate is found anywhere", () => {
		const env = setupTestEnvironment("pi-lens-find-none-");
		try {
			const startDir = path.join(env.tmpDir, "src");
			fs.mkdirSync(startDir, { recursive: true });
			// No marker file anywhere under env.tmpDir, and the walk terminates
			// at the filesystem root where the candidate also doesn't exist.
			const found = findNearestContaining(startDir, [
				"this-marker-name-will-not-collide-with-anything-XYZZY-pi-lens",
			]);
			expect(found).toBeUndefined();
		} finally {
			env.cleanup();
		}
	});
});

describe("findLocalToolConfig (refs #680)", () => {
	it("returns the matched FILE path, not just the containing directory", () => {
		const env = setupTestEnvironment("pi-lens-find-tool-config-");
		try {
			const startDir = path.join(env.tmpDir, "src");
			fs.mkdirSync(startDir, { recursive: true });
			fs.writeFileSync(path.join(env.tmpDir, "typos.toml"), "");

			const found = findLocalToolConfig(startDir, [
				"typos.toml",
				"_typos.toml",
				".typos.toml",
			]);
			expect(found && path.resolve(found)).toBe(
				path.resolve(env.tmpDir, "typos.toml"),
			);
		} finally {
			env.cleanup();
		}
	});

	it("prefers the nearest directory over a match higher up the tree", () => {
		const env = setupTestEnvironment("pi-lens-find-tool-config-nearest-");
		try {
			const inner = path.join(env.tmpDir, "outer", "inner");
			fs.mkdirSync(inner, { recursive: true });
			fs.writeFileSync(path.join(env.tmpDir, "outer", "sgconfig.yml"), "");
			fs.writeFileSync(path.join(inner, "sgconfig.yml"), "");

			const startDir = path.join(inner, "src");
			fs.mkdirSync(startDir, { recursive: true });
			const found = findLocalToolConfig(startDir, [
				"sgconfig.yml",
				"sgconfig.yaml",
			]);
			expect(found && path.resolve(found)).toBe(
				path.resolve(inner, "sgconfig.yml"),
			);
		} finally {
			env.cleanup();
		}
	});

	it("within a single directory, matches candidate names in list order", () => {
		const env = setupTestEnvironment("pi-lens-find-tool-config-order-");
		try {
			fs.writeFileSync(path.join(env.tmpDir, "zizmor.yaml"), "");
			fs.writeFileSync(path.join(env.tmpDir, "zizmor.yml"), "");
			const startDir = path.join(env.tmpDir, "src");
			fs.mkdirSync(startDir, { recursive: true });

			const found = findLocalToolConfig(startDir, [
				"zizmor.yml",
				"zizmor.yaml",
			]);
			expect(found && path.resolve(found)).toBe(
				path.resolve(env.tmpDir, "zizmor.yml"),
			);
		} finally {
			env.cleanup();
		}
	});

	it("returns undefined when no candidate name is found anywhere up the tree", () => {
		const env = setupTestEnvironment("pi-lens-find-tool-config-none-");
		try {
			const startDir = path.join(env.tmpDir, "src");
			fs.mkdirSync(startDir, { recursive: true });
			const found = findLocalToolConfig(startDir, [
				"this-config-name-will-not-collide-XYZZY-pi-lens.toml",
			]);
			expect(found).toBeUndefined();
		} finally {
			env.cleanup();
		}
	});

	it("falls back to process.cwd() when startDir is empty, matching prior per-tool behavior", () => {
		const found = findLocalToolConfig("", [
			"this-config-name-will-not-collide-XYZZY-pi-lens.toml",
		]);
		expect(found).toBeUndefined();
	});
});

describe("findNearestMarkerRoot (refs #625)", () => {
	it("resolves the nearest directory containing a marker", () => {
		const env = setupTestEnvironment("pi-lens-marker-root-");
		try {
			fs.writeFileSync(path.join(env.tmpDir, "package.json"), "{}");
			const nested = path.join(env.tmpDir, "src", "pkg");
			fs.mkdirSync(nested, { recursive: true });

			expect(findNearestMarkerRoot(nested, ["package.json"])).toBe(
				path.resolve(env.tmpDir),
			);
		} finally {
			env.cleanup();
		}
	});

	it("never resolves at or above the given home dir", () => {
		const env = setupTestEnvironment("pi-lens-marker-root-home-");
		try {
			const ancestor = path.join(env.tmpDir, "ancestor");
			const home = path.join(ancestor, "home");
			const nested = path.join(home, "empty-folder");
			fs.mkdirSync(nested, { recursive: true });
			fs.writeFileSync(path.join(ancestor, "package.json"), "{}");

			expect(
				findNearestMarkerRoot(nested, ["package.json"], { homeDir: home }),
			).toBeNull();
			// The home dir itself is also at-or-above home.
			fs.writeFileSync(path.join(home, "package.json"), "{}");
			expect(
				findNearestMarkerRoot(home, ["package.json"], { homeDir: home }),
			).toBeNull();
		} finally {
			env.cleanup();
		}
	});

	it("stops at a boundary marker found before any project marker", () => {
		const env = setupTestEnvironment("pi-lens-marker-root-boundary-");
		try {
			fs.writeFileSync(path.join(env.tmpDir, "package.json"), "{}");
			const repoRoot = path.join(env.tmpDir, "sub-repo");
			const nested = path.join(repoRoot, "src");
			fs.mkdirSync(path.join(repoRoot, ".git"), { recursive: true });
			fs.mkdirSync(nested, { recursive: true });

			expect(
				findNearestMarkerRoot(nested, ["package.json"], {
					boundaries: [".git", ".hg", ".svn"],
				}),
			).toBeNull();
		} finally {
			env.cleanup();
		}
	});

	it("does not stop at a boundary that coincides with the marker directory itself", () => {
		const env = setupTestEnvironment("pi-lens-marker-root-boundary-same-");
		try {
			const repoRoot = path.join(env.tmpDir, "repo");
			const nested = path.join(repoRoot, "src");
			fs.mkdirSync(path.join(repoRoot, ".git"), { recursive: true });
			fs.writeFileSync(path.join(repoRoot, "package.json"), "{}");
			fs.mkdirSync(nested, { recursive: true });

			// Marker check happens before the boundary check at each directory, so
			// a marker co-located with the boundary still resolves.
			expect(
				findNearestMarkerRoot(nested, ["package.json"], {
					boundaries: [".git"],
				}),
			).toBe(path.resolve(repoRoot));
		} finally {
			env.cleanup();
		}
	});

	it("returns null (never startDir) when nothing matches up to the filesystem root", () => {
		const env = setupTestEnvironment("pi-lens-marker-root-none-");
		try {
			const nested = path.join(env.tmpDir, "deep", "nowhere");
			fs.mkdirSync(nested, { recursive: true });

			const found = findNearestMarkerRoot(nested, [
				"this-marker-will-not-collide-XYZZY-pi-lens",
			]);
			expect(found).not.toBe(nested);
		} finally {
			env.cleanup();
		}
	});
});

describe("isAtOrAboveHomeDir (#253)", () => {
	// Use a synthetic home so the assertions are platform-stable.
	const home = path.resolve(path.join("tmp-home", "user"));

	it("treats the home directory itself as at-or-above home", () => {
		expect(isAtOrAboveHomeDir(home, home)).toBe(true);
	});

	it("treats an ancestor of home as at-or-above home (the #253 escape)", () => {
		const ancestor = path.dirname(home); // …/tmp-home
		const grandAncestor = path.dirname(ancestor);
		expect(isAtOrAboveHomeDir(ancestor, home)).toBe(true);
		expect(isAtOrAboveHomeDir(grandAncestor, home)).toBe(true);
	});

	it("treats the filesystem root as at-or-above home", () => {
		const { root } = path.parse(home);
		expect(isAtOrAboveHomeDir(root, home)).toBe(true);
	});

	it("treats a project UNDER home as not at-or-above home", () => {
		expect(isAtOrAboveHomeDir(path.join(home, "code", "app"), home)).toBe(
			false,
		);
		expect(isAtOrAboveHomeDir(path.join(home, "proj"), home)).toBe(false);
	});

	it("treats a sibling/unrelated tree as not at-or-above home", () => {
		const sibling = path.join(path.dirname(home), "someone-else", "proj");
		expect(isAtOrAboveHomeDir(sibling, home)).toBe(false);
	});

	it("normalizes unresolved paths before comparing", () => {
		expect(isAtOrAboveHomeDir(path.join(home, "x", ".."), home)).toBe(true);
		expect(isAtOrAboveHomeDir(path.join(home, "a", "..", "b"), home)).toBe(
			false,
		);
	});
});

describe("isExternalOrVendorFile", () => {
	const root = "/home/user/project";

	it("returns false for a normal source file", () => {
		expect(isExternalOrVendorFile(`${root}/src/main.ts`, root)).toBe(false);
	});

	it("returns true for a file outside the project root", () => {
		expect(isExternalOrVendorFile("/home/user/other-project/foo.ts", root)).toBe(true);
	});

	it("returns true for node_modules", () => {
		expect(isExternalOrVendorFile(`${root}/node_modules/lodash/index.js`, root)).toBe(true);
	});

	it("returns true for vendor/", () => {
		expect(isExternalOrVendorFile(`${root}/vendor/dep/file.go`, root)).toBe(true);
	});

	it("returns true for vendors/", () => {
		expect(isExternalOrVendorFile(`${root}/vendors/lib.py`, root)).toBe(true);
	});

	it("returns true for third_party/", () => {
		expect(isExternalOrVendorFile(`${root}/third_party/sherpa/api.h`, root)).toBe(true);
	});

	it("returns true for third-party/", () => {
		expect(isExternalOrVendorFile(`${root}/third-party/lib/src.cpp`, root)).toBe(true);
	});

	it("returns false for a dir that merely contains 'vendor' as a substring", () => {
		expect(isExternalOrVendorFile(`${root}/src/vendor_utils/helper.ts`, root)).toBe(false);
	});
});

describe("toPosix (refs #1193)", () => {
	it("folds backslashes to forward slashes", () => {
		expect(toPosix("C:\\repo\\src\\x.ts")).toBe("C:/repo/src/x.ts");
		expect(toPosix("\\\\host\\share\\a.ts")).toBe("//host/share/a.ts");
	});

	it("is a no-op on an already-forward-slashed path", () => {
		expect(toPosix("/home/u/x.ts")).toBe("/home/u/x.ts");
		expect(toPosix("src/x.ts")).toBe("src/x.ts");
	});

	it("is exactly the inline idiom it replaces (does NOT collapse, resolve, or lowercase)", () => {
		const p = "C:\\Repo\\\\src\\.\\x.ts";
		// Pure separator fold — same as `p.replace(/\\/g, "/")`, no other change.
		expect(toPosix(p)).toBe(p.replace(/\\/g, "/"));
		expect(toPosix(p)).toBe("C:/Repo//src/./x.ts"); // doubled slash + `.` + case preserved
	});

	it("handles empty string", () => {
		expect(toPosix("")).toBe("");
	});
});

describe("splitPathSegments (refs #1193, #1161/#1163)", () => {
	it("splits on EITHER separator regardless of host, dropping empties", () => {
		expect(splitPathSegments("C:\\repo\\src\\x.ts")).toEqual(["C:", "repo", "src", "x.ts"]);
		expect(splitPathSegments("/home/u/x.ts")).toEqual(["home", "u", "x.ts"]);
		expect(splitPathSegments("a/b\\c")).toEqual(["a", "b", "c"]); // mixed separators
	});

	it("collapses doubled separators and drops leading/trailing empties", () => {
		expect(splitPathSegments("//host\\\\share//a")).toEqual(["host", "share", "a"]);
		expect(splitPathSegments("src/")).toEqual(["src"]);
	});

	it("returns [] for empty or separator-only input", () => {
		expect(splitPathSegments("")).toEqual([]);
		expect(splitPathSegments("///")).toEqual([]);
	});
});
