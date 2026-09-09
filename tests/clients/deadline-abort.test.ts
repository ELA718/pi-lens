import { getEventListeners } from "node:events";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import { withDeadline } from "../../clients/deadline-utils.js";

describe("deadline cancellation (#4)", () => {
	afterEach(() => vi.useRealTimers());

	it("settles on abort and releases its timer and listener before the producer finishes", async () => {
		vi.useFakeTimers();
		const controller = new AbortController();
		let rejectProducer!: (error: Error) => void;
		const producer = new Promise<void>((_, reject) => { rejectProducer = reject; });
		const options = { ms: 15_000, onTimeout: "undefined" as const, signal: controller.signal };
		const result = withDeadline(producer, options);
		controller.abort();
		await vi.advanceTimersByTimeAsync(0);
		expect(vi.getTimerCount()).toBe(0);
		await expect(result).resolves.toBeUndefined();
		expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
		rejectProducer(new Error("late producer rejection"));
		await vi.advanceTimersByTimeAsync(0);
	});

	it("removes the abort listener after normal completion and timeout", async () => {
		vi.useFakeTimers();
		const controller = new AbortController();
		const options = { ms: 10, signal: controller.signal };
		await expect(withDeadline(Promise.resolve(42), options)).resolves.toBe(42);
		expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
		const result = withDeadline(new Promise<void>(() => {}), { ...options, onTimeout: "undefined" });
		await vi.advanceTimersByTimeAsync(10);
		await expect(result).resolves.toBeUndefined();
		expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
		expect(vi.getTimerCount()).toBe(0);
	});

	it("rejects with the caller's reason and handles a late rejection after pre-abort", async () => {
		vi.useFakeTimers();
		const controller = new AbortController();
		const reason = new Error("caller cancelled");
		controller.abort(reason);
		const result = withDeadline(Promise.reject(new Error("producer failed")), { ms: 10, signal: controller.signal });
		await expect(result).rejects.toBe(reason);
		expect(vi.getTimerCount()).toBe(0);
		expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
	});

	it("does not leave a process alive for the original deadline after cancellation", async () => {
		const moduleUrl = new URL("../../clients/deadline-utils.js", import.meta.url).href;
		const script = `
			import { withDeadline } from ${JSON.stringify(moduleUrl)};
			const controller = new AbortController();
			const result = withDeadline(new Promise(() => {}), {
				ms: 15000, signal: controller.signal, onTimeout: "undefined"
			});
			controller.abort();
			await result;
			process.stdout.write("settled");
		`;
		const { stdout } = await promisify(execFile)(process.execPath, ["--input-type=module", "-e", script], { timeout: 3_000 });
		expect(stdout).toBe("settled");
	});

	it("observes a producer rejection even when the deadline was already expired", async () => {
		await expect(withDeadline(Promise.reject(new Error("late rejection")), { ms: 0, onTimeout: "undefined" })).resolves.toBeUndefined();
		await new Promise<void>(resolve => setImmediate(resolve));
	});

	it("keeps the shared producer available to another consumer after caller cancellation", async () => {
		const controller = new AbortController();
		let finish!: (value: number) => void;
		const producer = new Promise<number>(resolve => { finish = resolve; });
		const wait = withDeadline(producer, { ms: 15_000, signal: controller.signal, onTimeout: "undefined" });
		controller.abort();
		await expect(wait).resolves.toBeUndefined();
		finish(42);
		await expect(producer).resolves.toBe(42);
	});
});
