import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TreeSitterQueryLoader } from "../../clients/tree-sitter-query-loader.js";
import { getSharedTreeSitterClient } from "../../clients/tree-sitter-shared.js";
import { assertGrammarAvailable, makeRealRunnerEnv } from "../support/real-runner-ctx.js";

const env = makeRealRunnerEnv();
const loader = new TreeSitterQueryLoader();

beforeAll(async () => {
	await assertGrammarAvailable("typescript");
	await loader.loadQueries(process.cwd());
	env.addFile("package.json", '{"name":"sql-callable-fixture"}');
	env.addFile("tsconfig.json", '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}');
});
afterAll(() => env.cleanup());

async function sqlFunctionCaptures(relPath: string, code: string) {
	const { filePath } = env.addFile(relPath, code);
	const query = loader.getQueryById("sql-injection");
	if (!query) throw new Error("SQL rule missing");
	return (
		await getSharedTreeSitterClient()!.runQueryOnFile(
			query,
			filePath,
			relPath.endsWith(".tsx") ? "tsx" : "typescript",
		)
	).map(match => match.captures.SQL_FUNC);
}

function installRpcBoundary() {
	env.addFile("src/lib/rpc-mutation.ts", `const RPC_MUTATION_NAME_SET = new Set(["fixed_rpc"]);
import { typedRpc } from "./typed-rpc";
export function rpcMutation(config) {
	return async (input) => {
		if (!RPC_MUTATION_NAME_SET.has(config.rpcName)) throw new Error("unlisted RPC");
		const params = config.buildRpcParams(input);
		return typedRpc(config.rpcName, params);
	};
}`);
	env.addFile("src/lib/typed-rpc.ts", `import { supabase } from "./supabase-client";
export function typedRpc(name, params) { return supabase.rpc(name, params); }`);
	env.addFile("src/lib/supabase-client.ts", `import { createClient } from "@supabase/supabase-js";
export const supabase = createClient("https://example.invalid", "public-key");`);
}

function installMutationHook(name: string) {
	env.addFile("src/hooks.ts", `import { useMutation } from "@tanstack/react-query";
import { rpcMutation } from "@/lib/rpc-mutation";
export function ${name}() {
	return useMutation({ mutationFn: rpcMutation({
		rpcName: "fixed_rpc",
		buildRpcParams: input => ({ id: input.id }),
	}) });
}`);
}

describe("SQL callable producer and caller provenance", () => {
	it("accepts an immutable callable returned by a resolved fixed producer", async () => {
		installRpcBoundary();
		expect(await sqlFunctionCaptures("src/rpc-consumer.ts", `import { rpcMutation } from "@/lib/rpc-mutation";
const execute = rpcMutation({ rpcName: "fixed_rpc", buildRpcParams: payload => ({ id: payload.id }) });
execute(input);`)).toEqual([]);
	});

	it("accepts local per-id callbacks only after proving every caller", async () => {
		installRpcBoundary();
		installMutationHook("useFixedMutation");
		expect(await sqlFunctionCaptures("src/bulk.tsx", `import { useCallback } from "react";
import { useFixedMutation } from "./hooks";
function Screen() {
	const approveMutation = useFixedMutation();
	const cancelMutation = useFixedMutation();
	const settle = useCallback(async (ids, run) => Promise.all(ids.map(id => run(id))), []);
	const approve = useCallback(() => settle(ids, id => approveMutation.mutateAsync({ id })), [settle]);
	const cancel = () => settle(ids, id => cancelMutation.mutateAsync({ id, reason: "bulk" }));
	return <button onClick={approve}>Approve</button>;
}`)).toEqual([]);
	});

	it("accepts execute from a resolved immutable registry", async () => {
		env.addFile("src/sdk-client.ts", `import { createClient } from "@supabase/supabase-js";
export const supabase = createClient("https://example.invalid", "public-key");`);
		env.addFile("src/empty-operations.ts", "export const EMPTY_OPERATIONS = {};");
		env.addFile("src/operation-types.ts", `import { supabase } from "./sdk-client";
import { EMPTY_OPERATIONS } from "./empty-operations";
export const OPERATION_CONFIGS = {
	LOG_EVENT: { execute: async payload => supabase.rpc("log_event", payload) },
	...EMPTY_OPERATIONS,
};
export function getOperationConfig(operationType) { return OPERATION_CONFIGS[operationType]; }`);
		expect(await sqlFunctionCaptures("src/sync.ts", `import { getOperationConfig } from "./operation-types";
async function sync(operation) {
	const config = getOperationConfig(operation.type);
	if (!config) return;
	await config.execute(operation.payload, operation.id);
}`)).toEqual([]);
	});

	it.each([
		["unsafe resolved producer", "export function makeRunner() { return sql => db.query(sql); }"],
		["innocently named member forwarding tainted data", "export function makeRunner() { return value => client.safeSend(value); }"],
	])("retains %s", async (_name, producer) => {
		env.addFile("src/producer.ts", producer);
		expect(await sqlFunctionCaptures("src/unsafe-producer-consumer.ts", `import { makeRunner } from "./producer";
const execute = makeRunner({ rpcName: "fixed_rpc", buildRpcParams: value => value });
execute(input);`)).toContain("execute");
	});

	it("retains a producer with an extra tainted SQL call", async () => {
		env.addFile("src/lib/rpc-mutation.ts", `const RPC_MUTATION_NAME_SET = new Set(["fixed_rpc"]);
import { typedRpc } from "./typed-rpc";
export function rpcMutation(config) { return input => { const params = config.buildRpcParams(input); db.execute(params.sql); return typedRpc(config.rpcName, params); }; }`);
		env.addFile("src/lib/typed-rpc.ts", `import { supabase } from "./supabase-client"; export function typedRpc(name, params) { return supabase.rpc(name, params); }`);
		env.addFile("src/lib/supabase-client.ts", `import { createClient } from "@supabase/supabase-js"; export const supabase = createClient("url", "key");`);
		expect(await sqlFunctionCaptures("src/extra-call.ts", `import { rpcMutation } from "@/lib/rpc-mutation";
const execute = rpcMutation({ rpcName: "fixed_rpc", buildRpcParams: value => ({ sql: value }) }); execute(input);`)).toContain("execute");
	});

	it.each([
		["an unrelated SDK receiver", `import { supabase } from "./supabase-client";
export function typedRpc(name, params, client = evil) { supabase.rpc(name, params); return client.rpc(name, params); }`],
		["an extra SQL call", `import { supabase } from "./supabase-client";
export function typedRpc(name, params) { db.execute(params.sql); return supabase.rpc(name, params); }`],
	])("retains a fixed producer whose typed boundary has %s", async (_name, typedRpc) => {
		installRpcBoundary();
		env.addFile("src/lib/typed-rpc.ts", typedRpc);
		expect(await sqlFunctionCaptures("src/unsafe-typed-boundary.ts", `import { rpcMutation } from "@/lib/rpc-mutation";
const execute = rpcMutation({ rpcName: "fixed_rpc", buildRpcParams: value => ({ value }) }); execute(input);`)).toContain("execute");
	});

	it("retains a reassigned producer result", async () => {
		env.addFile("src/producer.ts", "export function makeRunner() { return value => transport.send(value); }");
		expect(await sqlFunctionCaptures("src/reassigned-consumer.ts", `import { makeRunner } from "./producer";
let execute = makeRunner(); execute = runSql; execute(input);`)).toContain("execute");
	});

	it.each([
		["computed SQL member", "id => db[\"query\"](id)"],
		["Reflect.apply", "id => Reflect.apply(db.query, db, [id])"],
		["aliased SQL callable", "id => { const q = db.query; return q(id); }"],
		["bare SQL callable", "id => runSql(id)"],
	])("retains a local helper with an unsafe caller: %s", async (_name, callback) => {
		installRpcBoundary();
		installMutationHook("useFixedMutation");
		expect(await sqlFunctionCaptures("src/unsafe-bulk.ts", `import { useFixedMutation } from "./hooks";
const mutation = useFixedMutation();
function settle(ids, run) { return Promise.all(ids.map(id => run(id))); }
settle(ids, id => mutation.mutateAsync({ id }));
settle(ids, ${callback});`)).toContain("run");
	});

	it("retains nested tainted calls inside mutateAsync arguments", async () => {
		installRpcBoundary();
		installMutationHook("useFixedMutation");
		expect(await sqlFunctionCaptures("src/nested-bulk.ts", `import { useFixedMutation } from "./hooks";
const mutation = useFixedMutation();
function settle(ids, run) { return ids.map(id => run(id)); }
settle(ids, id => mutation.mutateAsync(db.execute(id)));`)).toContain("run");
	});

	it("retains an unknown object member even when its name looks safe", async () => {
		expect(await sqlFunctionCaptures("src/unknown-member.ts", `function settle(ids, run) { return ids.map(id => run(id)); }
settle(ids, id => unknown.safeSend(id));`)).toContain("run");
	});

	it("retains closure shadowing and an escaped helper", async () => {
		installRpcBoundary();
		installMutationHook("useFixedMutation");
		expect(await sqlFunctionCaptures("src/shadowed-bulk.ts", `import { useFixedMutation } from "./hooks";
const mutation = useFixedMutation();
function settle(ids, run) { return ids.map(id => run(id)); }
consume(settle);
function shadow(run) { return run(request.body.sql); }
settle(ids, id => mutation.mutateAsync({ id }));`)).toContain("run");
	});

	it("does not accept an SDK-looking export unrelated to createClient", async () => {
		env.addFile("src/deceptive-sdk.ts", `import { createClient } from "@supabase/supabase-js";
export const supabase = { rpc(_name, params) { return db.execute(params.sql); } };`);
		env.addFile("src/deceptive-operation-types.ts", `import { supabase } from "./deceptive-sdk";
const OPERATION_CONFIGS = { SAFE: { execute: payload => supabase.rpc("fixed", payload) } };
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		expect(await sqlFunctionCaptures("src/deceptive-sync.ts", `import { getOperationConfig } from "./deceptive-operation-types";
const config = getOperationConfig(operation.type); if (config) config.execute(operation.payload);`)).toContain("execute");
	});

	it("retains shadowed producer imports", async () => {
		installRpcBoundary();
		expect(await sqlFunctionCaptures("src/shadowed-producer.ts", `import { rpcMutation } from "@/lib/rpc-mutation";
function build(rpcMutation) { const execute = rpcMutation({ rpcName: "fixed_rpc", buildRpcParams: value => value }); return execute(input); }`)).toContain("execute");
	});

	it("rejects shadowed createClient bindings", async () => {
		env.addFile("src/shadowed-sdk.ts", `import { createClient } from "@supabase/supabase-js";
function build(createClient) { return createClient("url", "key"); }
export const supabase = build(evil);`);
		env.addFile("src/shadowed-sdk-operation-types.ts", `import { supabase } from "./shadowed-sdk";
const OPERATION_CONFIGS = { SAFE: { execute: payload => supabase.rpc("fixed", payload) } };
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		expect(await sqlFunctionCaptures("src/shadowed-sdk-sync.ts", `import { getOperationConfig } from "./shadowed-sdk-operation-types";
const config = getOperationConfig(operation.type); if (config) config.execute(operation.payload);`)).toContain("execute");
	});

	it("rejects arbitrary every calls in registry parameter builders", async () => {
		env.addFile("src/sdk-client.ts", `import { createClient } from "@supabase/supabase-js"; export const supabase = createClient("url", "key");`);
		env.addFile("src/every-operation-types.ts", `import { supabase } from "./sdk-client";
function sanitize(payload) { return payload.every(value => value); }
const OPERATION_CONFIGS = { SAFE: { execute: payload => supabase.rpc("fixed", sanitize(payload)) } };
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		expect(await sqlFunctionCaptures("src/every-sync.ts", `import { getOperationConfig } from "./every-operation-types";
const config = getOperationConfig(operation.type); if (config) config.execute(operation.payload);`)).toContain("execute");
	});

	it("retains execute from a registry with a dynamic entry", async () => {
		env.addFile("src/dynamic-operation-types.ts", `const OPERATION_CONFIGS = { SAFE: { execute: payload => sdk.rpc("fixed", payload) }, ...getConfigs() };
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		expect(await sqlFunctionCaptures("src/dynamic-sync.ts", `import { getOperationConfig } from "./dynamic-operation-types";
const config = getOperationConfig(operation.type);
if (config) config.execute(operation.payload);`)).toContain("execute");
	});

	it("retains execute from a mutated or escaped registry", async () => {
		env.addFile("src/escaped-operation-types.ts", `const OPERATION_CONFIGS = { SAFE: { execute: payload => sdk.rpc("fixed", payload) } };
consume(OPERATION_CONFIGS);
OPERATION_CONFIGS.SAFE = unsafe;
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		expect(await sqlFunctionCaptures("src/escaped-sync.ts", `import { getOperationConfig } from "./escaped-operation-types";
const config = getOperationConfig(operation.type);
if (config) config.execute(operation.payload);`)).toContain("execute");
	});

	it("retains a concrete registry result that is mutated by its caller", async () => {
		env.addFile("src/sdk-client.ts", `import { createClient } from "@supabase/supabase-js"; export const supabase = createClient("url", "key");`);
		env.addFile("src/mutable-result-operation-types.ts", `import { supabase } from "./sdk-client";
const OPERATION_CONFIGS = { SAFE: { execute: payload => supabase.rpc("fixed", payload) } };
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		expect(await sqlFunctionCaptures("src/mutable-result-sync.ts", `import { getOperationConfig } from "./mutable-result-operation-types";
const config = getOperationConfig(operation.type); config.execute = runSql; config.execute(operation.payload);`)).toContain("execute");
	});

	it("retains a mutable imported spread registry", async () => {
		env.addFile("src/sdk-client.ts", `import { createClient } from "@supabase/supabase-js"; export const supabase = createClient("url", "key");`);
		env.addFile("src/mutable-spread.ts", `export const EXTRA = {}; export const escaped = EXTRA;`);
		env.addFile("src/mutable-spread-operation-types.ts", `import { supabase } from "./sdk-client"; import { EXTRA } from "./mutable-spread";
const OPERATION_CONFIGS = { SAFE: { execute: payload => supabase.rpc("fixed", payload) }, ...EXTRA };
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		expect(await sqlFunctionCaptures("src/mutable-spread-sync.ts", `import { getOperationConfig } from "./mutable-spread-operation-types";
const config = getOperationConfig(operation.type); if (config) config.execute(operation.payload);`)).toContain("execute");
	});

	it("retains an exported registry alias that escapes", async () => {
		env.addFile("src/sdk-client.ts", `import { createClient } from "@supabase/supabase-js"; export const supabase = createClient("url", "key");`);
		env.addFile("src/aliased-operation-types.ts", `import { supabase } from "./sdk-client";
export const OPERATION_CONFIGS = { SAFE: { execute: payload => supabase.rpc("fixed", payload) } };
export const escaped = OPERATION_CONFIGS;
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		expect(await sqlFunctionCaptures("src/aliased-sync.ts", `import { getOperationConfig } from "./aliased-operation-types";
const config = getOperationConfig(operation.type); if (config) config.execute(operation.payload);`)).toContain("execute");
	});

	it("rechecks imported SDK content instead of trusting its path", async () => {
		env.addFile("src/content-sdk.ts", `import { createClient } from "@supabase/supabase-js"; export const supabase = createClient("url", "key");`);
		env.addFile("src/content-operation-types.ts", `import { supabase } from "./content-sdk";
const OPERATION_CONFIGS = { SAFE: { execute: payload => supabase.rpc("fixed", payload) } };
export function getOperationConfig(type) { return OPERATION_CONFIGS[type]; }`);
		const consumer = `import { getOperationConfig } from "./content-operation-types";
const config = getOperationConfig(operation.type); if (config) config.execute(operation.payload);`;
		expect(await sqlFunctionCaptures("src/content-sync.ts", consumer)).toEqual([]);
		env.addFile("src/content-sdk.ts", `import { createClient } from "@supabase/supabase-js";
export const supabase = { rpc(_name, params) { return db.execute(params.sql); } };`);
		expect(await sqlFunctionCaptures("src/content-sync.ts", consumer)).toContain("execute");
	});

	it("rechecks imported producer content instead of trusting its path", async () => {
		installRpcBoundary();
		const consumer = `import { rpcMutation } from "@/lib/rpc-mutation";
const execute = rpcMutation({ rpcName: "fixed_rpc", buildRpcParams: value => ({ value }) });
execute(input);`;
		expect(await sqlFunctionCaptures("src/content-bound.ts", consumer)).toEqual([]);
		env.addFile("src/lib/rpc-mutation.ts", "export function rpcMutation() { return value => db.query(value); }");
		expect(await sqlFunctionCaptures("src/content-bound.ts", consumer)).toContain("execute");
	});
});
