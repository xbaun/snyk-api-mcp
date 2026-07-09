# AGENTS.md

## Read this first

Start with [`CODING.md`](CODING.md).

`CODING.md` is the foundation for how code should feel in this repository:

- consistent with local patterns
- simple over clever
- KISS and YAGNI by default
- minimal abstraction unless there is a real, repeated need

This file builds on that foundation. Use `AGENTS.md` for repository-specific product intent, MCP contract rules, workflow expectations, and agent operating guidance.

## Document split

Use the repository docs like this:

- `CODING.md` — codebase consistency and implementation judgment
- `AGENTS.md` — agent-facing repository rules and MCP contract guidance
- `README.md` — user-facing setup, usage, and contribution entry points

Do not duplicate the full coding guidance across all three files.

## Repository purpose

This repository builds a small, agent-friendly MCP layer around Snyk.

The goal is **not** to model every part of Snyk or invent a generic query system. The goal is to expose the few workflows that agents actually need in a way that is:

- easy to discover
- easy to call correctly
- hard to misuse accidentally
- stable in response shape

## What “agent-friendly” means here

In this repository, “agent-friendly” does **not** mean permissive or fuzzy.

It means the contract is:

- **narrow** — each tool has one clear job
- **explicit** — required inputs are truly required
- **strict** — identifiers and formats are not interchangeable
- **predictable** — responses keep a stable, readable structure
- **honest** — invalid input should fail clearly instead of being guessed or silently corrected

When in doubt, prefer a smaller and stricter interface over a more flexible one.

## Core rules for coding agents

### 1. Keep the MCP surface narrow

Prefer a focused tool such as `snyk_get_project_issues` over a generic catch-all query tool.

Add a new tool only when all of the following are true:

- it serves a real repeated workflow
- existing tools cannot express that workflow cleanly
- the contract can stay narrow and obvious
- the output can stay stable and readable

If the change only saves one internal call but makes the public surface more confusing, do not add it.

### 2. Be strict about identifiers

Do not blur these concepts:

- `orgId`
- `projectId`
- `restIssueId`
- `vulnerabilityId`
- `issueKey`

They are **not interchangeable**.

If a workflow needs one specific identifier, require that exact field and name it exactly.

### 3. Validate early and fail clearly

Validate inputs at the MCP boundary.

Prefer:

- exact field names
- exact enums where possible
- explicit required fields
- descriptive validation errors

Do **not** add fuzzy matching, heuristic coercion, or silent fallbacks.

### 4. Keep response shapes stable

Response payloads should be easy for an agent to scan and reuse.

Prefer:

- stable top-level fields
- normalized naming
- explicit arrays and objects
- summary fields when they improve usability

Avoid:

- shape changes based on edge cases
- deeply nested wrappers without value
- mixing unrelated result types in one response

### 5. Hide backend quirks, not domain meaning

This server may bridge Snyk REST and Snyk API v1 where necessary.

That is good only when it simplifies the workflow for the caller. Do not leak unnecessary transport details into the MCP contract, but do not flatten away important Snyk domain meaning just to look simple.

### 6. Prefer explicit workflow over magical convenience

This project intentionally favors a clear multi-step flow:

1. resolve org
2. discover target or project
3. list issues
4. fetch detail, paths, or analysis

That is better than a “smart” tool that guesses too much from partial input.

## Expected workflows

### Issue investigation

1. `snyk_onboarding`
2. `snyk_resolve_org_id`
3. `snyk_get_targets`
4. one of:
   - `snyk_get_target_ledger_seed`
   - `snyk_get_projects`
   - `snyk_get_project_ledger_seed`
5. `snyk_get_project_issues`
6. one of:
   - `snyk_get_issue_detail`
   - `snyk_get_project_issue_paths`
   - `snyk_get_project_package_vulnerability_analysis`

### Session and remediation intake

Use:

- `snyk_get_target_ledger_seed` for target-wide intake
- `snyk_get_project_ledger_seed` for single-project intake

Persist returned seed documents unchanged. The current contract is intentional.

## Change guidance

### Parameters

Prefer narrower parameters.

Good:

- `orgId`
- `projectId`
- `restIssueId`
- `severity: "low" | "medium" | "high" | "critical"`

Bad:

- `id` when multiple ID types exist
- freeform filter blobs when a few explicit fields are enough
- parameters that mean different things in different modes

### Naming

If the public contract already uses a field name, keep using it.

Do not rename public fields casually. If a rename is truly necessary, treat it as a contract change and update documentation consistently.

### Helpers and abstractions

- keep helpers private unless there is a clear shared need
- do not extract abstractions just to make code look more generic
- prefer straightforward code over framework-like internal architecture

### Dependencies

Add dependencies sparingly. A new dependency should remove meaningful complexity, not add indirection.

### Documentation

Keep docs operational.

Tool descriptions and README examples should help an agent choose the correct next step quickly. Prefer concrete wording such as:

- what the tool requires
- what identifier it returns
- what the next likely tool is

## Repository map

- `src/index.ts` — MCP server bootstrap and tool registration
- `src/tools/` — MCP tool definitions grouped by workflow
- `src/snyk/client.ts` — Snyk API access layer
- `src/utils/` — focused utilities, not a dumping ground
- `layout/` — bundled agent and skill definitions for downstream repos
- `README.md` — user-facing usage and setup

## Non-goals

This project is not trying to be:

- a full Snyk SDK
- a generic Snyk query engine
- a compatibility layer for every possible input style
- a place for speculative abstraction

## Agent self-check before finishing a change

Before merging or handing back a change, ask:

1. Did I follow `CODING.md` first?
2. Does this make the MCP surface easier for an agent to understand?
3. Does it reduce ambiguity rather than hide it?
4. Is the input contract clearer, not looser?
5. Is the output more predictable, not more clever?
6. Would a new user understand the intended workflow from the tool names and docs alone?

If the answer is no, the change is probably too complex.
