import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import {
	assertGrammarAvailable,
	makeRealRunnerEnv,
} from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();

beforeAll(async () => {
	await assertGrammarAvailable("typescript");
	await loader.loadQueries(process.cwd());
});
afterAll(() => env.cleanup());

async function findings(code: string) {
	const { filePath } = env.addFile("map-receiver.ts", code);
	const query = loader.getQueryById("ts-ssrf");
	if (!query) throw new Error("SSRF rule missing");
	return getSharedTreeSitterClient()!.runQueryOnFile(
		query,
		filePath,
		"typescript",
	);
}

describe("SSRF native Map and Set receiver provenance", () => {
	it.each([
		[
			"Samsara cache lookup",
			`const liveVehiclesCache = new Map<string, object>();
			 function cacheKey(includeDrivers: boolean) { return String(includeDrivers); }
			 function read(includeDrivers: boolean) { return liveVehiclesCache.get(cacheKey(includeDrivers)); }`,
		],
		[
			"route preview lookup",
			`const selectedStopsByKey = new Map(selectedStops.map((stop) => [getStopKey(stop), stop]));
			 for (const stop of optimizedRouteStops) selectedStopsByKey.get(getStopKey(stop));`,
		],
		[
			"idempotency key lookup",
			`const stableIdempotencyKeys = new Map<string, string>();
			 stableIdempotencyKeys.get(buildFingerprint(input));`,
		],
		[
			"business acronym lookup",
			`const BUSINESS_NAME_ACRONYMS = new Map([["co", "Co"]]);
			 BUSINESS_NAME_ACRONYMS.get(token.toLowerCase());`,
		],
		[
			"import header count lookup",
			`const selectedHeaderCounts = new Map<string, number>();
			 selectedHeaderCounts.set(normalizedHeader, 1);
			 selectedHeaderCounts.get(normalizeImportHeader(candidate));`,
		],
		[
			"native Set deletion",
			`const pendingKeys = new Set<string>();
			 pendingKeys.delete(buildKey(input));`,
		],
		[
			"migration identity deletion",
			`async function parseMigrations() {
			   const byIdentity = new Map<string, object>();
			   byIdentity.set("known", {});
			   byIdentity.delete(identityKey(reference.schema, reference.name, reference.signature));
			 }`,
		],
	])("removes the $0 false positive", async (_label, code) => {
		expect(await findings(code)).toHaveLength(0);
	});

	it.each([
		["real fetch", `fetch(new URL("/print", gatewayUrl));`],
		["HTTP get", `axios.get(buildUrl(request));`],
		["HTTP delete", `requestClient.delete(buildUrl(request));`],
		[
			"request-supplied object",
			`const { cache } = request; cache.get(buildKey(request));`,
		],
		[
			"typed parameter only",
			`function read(cache: Map<string, string>) { return cache.get(buildKey()); }`,
		],
		[
			"hook result",
			`const { laneInfo } = useWarehouseLanes(); laneInfo.get(parseInt(lane));`,
		],
		[
			"shadowed constructor",
			`class Map<K, V> { get(_key: K): V { return request.url; } } const cache = new Map<string, string>(); cache.get(buildKey());`,
		],
		[
			"replaced constructor",
			`Map = request.Map; const cache = new Map(); cache.get(buildKey());`,
		],
		[
			"prototype override",
			`Map.prototype.get = request.get; const cache = new Map(); cache.get(buildKey());`,
		],
		[
			"computed globalThis prototype override",
			`globalThis["Map"].prototype.get = request.get; const cache = new Map(); cache.get(buildKey(request));`,
		],
		[
			"window prototype override",
			`window.Map.prototype.get = request.get; const cache = new Map(); cache.get(buildKey(request));`,
		],
		[
			"destructured global constructor override",
			`const { Map: M } = globalThis; M.prototype.get = request.get; const cache = new Map(); cache.get(buildKey(request));`,
		],
		[
			"acquired native prototype override",
			`Object.getPrototypeOf(new Map()).get = request.get; const cache = new Map(); cache.get(buildKey(request));`,
		],
		[
			"instance override",
			`const cache = new Map(); cache.get = request.get; cache.get(buildKey());`,
		],
		[
			"Map.set result escape",
			`const cache = new Map(); consume(cache.set("key", "value")); cache.get(buildKey(request));`,
		],
		[
			"Map.set chained receiver override",
			`const cache = new Map(); cache.set("key", "value").get = request.get; cache.get(buildKey(request));`,
		],
		[
			"Set.add result escape",
			`const cache = new Set(); consume(cache.add("key")); cache.delete(buildKey(request));`,
		],
		[
			"Set.add chained receiver override",
			`const cache = new Set(); cache.add("key").delete = request.delete; cache.delete(buildKey(request));`,
		],
		[
			"iterator result escape",
			`const cache = new Map(); const entries = cache.entries(); consume(entries); cache.get(buildKey(request));`,
		],
		[
			"iterator prototype access",
			`const cache = new Map(); Object.getPrototypeOf(cache.entries()).next = request.next; cache.get(buildKey(request));`,
		],
		[
			"escaped receiver",
			`const cache = new Map(); mutate(cache); cache.get(buildKey());`,
		],
		[
			"subclass",
			`class RequestMap extends Map {} const cache = new RequestMap(); cache.get(buildKey());`,
		],
		[
			"import ambiguity",
			`import { Map } from "./request-map"; const cache = new Map(); cache.get(buildKey());`,
		],
	])("retains $0", async (_label, code) => {
		expect((await findings(code)).length).toBeGreaterThan(0);
	});
});
