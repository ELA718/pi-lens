import { describe, expect, it } from "vitest";
import { getLanguageId } from "../../../clients/lsp/language.js";

describe("lsp language mapping", () => {
	it("resolves extension-based language ids", () => {
		expect(getLanguageId("src/main.ts")).toBe("typescript");
		expect(getLanguageId("src/script.sh")).toBe("shellscript");
		expect(getLanguageId("src/config.fish")).toBe("fish");
		expect(getLanguageId("cmake/helpers.cmake")).toBe("cmake");
	});

	it("resolves basename-only language ids", () => {
		expect(getLanguageId("Dockerfile")).toBe("dockerfile");
		expect(getLanguageId("infra/Dockerfile")).toBe("dockerfile");
		expect(getLanguageId("CMakeLists.txt")).toBe("cmake");
		expect(getLanguageId("src/CMakeLists.txt")).toBe("cmake");
	});

	it.each([
		"tsconfig.json", "tsconfig.app.json", "tsconfig.build.strict.json",
		"jsconfig.json", "jsconfig.test.json", "config/tsconfig.node.json",
		"config\\tsconfig.node.json", "config/TSCONFIG.APP.JSON",
	])("opens compiler config %s as JSONC", (filePath) => {
		expect(getLanguageId(filePath)).toBe("jsonc");
	});

	it.each([
		"package.json", "data.json", "tsconfig-data.json", "mytsconfig.json",
		"tsconfig.json/data.json", "config\\tsconfig.json\\data.json",
		"tsconfig.json.template", "tsconfig.app.json.ts",
	])("does not relax unrelated file %s to JSONC", (filePath) => {
		expect(getLanguageId(filePath)).not.toBe("jsonc");
	});

	it("keeps explicit JSONC extension support", () => {
		expect(getLanguageId("settings.jsonc")).toBe("jsonc");
	});

	it("returns undefined when no mapping exists", () => {
		expect(getLanguageId("README")).toBeUndefined();
	});
});
