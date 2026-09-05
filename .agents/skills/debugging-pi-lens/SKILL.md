---
name: debugging-pi-lens
description: "Diagnose and change pi-lens repository source, builds, tests, package resources and host adapters. Use for local source development or reproducing a pi-lens defect. Not for generic installed Pi operation or user-facing ast-grep/LSP tasks; the four package-shipped pi-lens skills retain those workflows."
---

# Debugging pi-lens source

Read AGENTS.md and CONTRIBUTING.md from the current worktree. AGENTS.md owns
source invariants, contribution requirements, review and release rules. Use
this helper as a navigation and verification router, not a replacement for
that contract.

## Ownership and first evidence

Record branch, source commit and installed package version separately. Working
source, generated JavaScript, dist packaging and the installed host can differ.
Reproduce against the intended surface before attributing a failure to source.

The four namespaced skills under `skills/` are package resources. Keep them
there. This repository helper belongs under `.agents/skills/` and must not be
added to package.json's published files or pi.skills array.

- `index.ts`: Pi host entry and extension registration.
- `clients/lens-engine.ts`: shared engine; `mcp/` owns the MCP host adapter.
- `clients/` and `tools/`: shared behavior and tool implementations; use the
  detailed source map and domain invariants in AGENTS.md for the changed seam.
- `tests/packaging.test.ts`: package contents and skill resolution contracts.
- `tests/support/pi-mock.ts`: extension wiring harness.
- `tests/clients/interleaving-kit.ts`: deterministic concurrency test controls.
- `scripts/with-test-lock.mjs`: serialized test entrypoint used by npm test.

## Setup and checks

From a freshly fetched task worktree, use the repository's documented
`npm install`. Its prepare lifecycle builds dist and downloads core grammars.
Inspect any resulting tracked diff before editing; do not silently include
install-generated package metadata in an unrelated task.

Run `npm run check:lockfile` as the smallest manifest check. It validates
configured dependency parity, not a complete build, test or runtime guarantee.

Choose checks for the changed surface:

```sh
npm run build
npm test -- tests/packaging.test.ts
npm run lint
```

The example selects packaging tests through the repository lock wrapper; choose
the actual related test paths for a source change. Follow AGENTS.md's full-suite
and lint requirements before committing logic changes or pushing.

`npm run build` excludes tests. `npm run build:dist` uses --noCheck and produces
the shipped bundle; it is not typecheck proof. `npm run lint` checks the strict
source/test configuration. Tests enforce in-place JavaScript freshness, so
rebuild after TypeScript edits when those artifacts can be stale. Edit source
TypeScript, never generated JavaScript or dist output.

## Diagnosis and validation scope

Check package resource resolution with the actual entry point and packaging
tests. package.json currently points pi.skills at ../../skills for the compiled
entry; do not move those resources into dist or normalize that path by intuition.
Changing discovery depth requires loader and packaging proof.

Use the shared test harnesses for host wiring and deterministic race cases.
For runtime behavior, distinguish environment mocks from mocks that replace the
behavior under test. Preserve current capture provenance, path normalization,
lease ownership and delivery invariants from AGENTS.md.

Do not load this worktree as the installed extension or run release/install
scripts merely to verify documentation. Live tool smoke commands can install
tools or mutate fixtures and are separate from the focused local checks.
Report observed command exits, tested surfaces and remaining host/OS/runtime
coverage. Documentation-only changes have no rendered output.
