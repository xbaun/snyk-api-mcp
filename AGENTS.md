# AGENTS.md

## Codebase Consistency

Read ./CODING.md

## Purpose

This repository builds a small, agent-friendly MCP layer around Snyk.

The goal is **not** to create a clever abstraction over every part of Snyk. The goal is to expose the few workflows that agents actually need in a way that is:

- easy to discover
- easy to call correctly
- hard to misuse accidentally
- stable in response shape

This project follows **YAGNI** and **KISS** aggressively.

## What “agent-friendly” means here

In this repository, “agent-friendly” does **not** mean permissive or fuzzy.

It means the contract is:

- **narrow** — each tool has one clear job
- **explicit** — required inputs are truly required
- **strict** — identifiers and formats are not interchangeable
- **predictable** — responses keep a stable, readable structure
- **honest** — invalid input should fail clearly instead of being guessed or silently corrected

When in doubt, prefer a smaller and stricter interface over a flexible one.

## Design principles

### 1. One tool, one clear responsibility

Prefer a focused tool such as `snyk_get_project_issues` over a generic catch-all query tool.

A tool should answer a specific user intent, not expose raw backend complexity.

### 2. Do not invent abstraction layers without a real need

If a helper, option, or tool does not simplify a real agent workflow today, do not add it.

This especially applies to:

- generic search/query tools
- overloaded parameters
- multi-mode tools with unrelated behaviors
- "maybe useful later" output fields

### 3. Be strict about identifiers

The identifier model is intentional and must stay explicit.

Do not blur these concepts:

- `orgId`
- `projectId`
- `restIssueId`
- `vulnerabilityId`
- `issueKey`

They are **not interchangeable**.

If a workflow needs one specific identifier, require that exact field and name it exactly.

### 4. Validate early and fail clearly

Use schema validation to reject malformed or ambiguous input at the boundary.

Prefer:

- exact field names
- exact enums where possible
- explicit required fields
- descriptive validation errors

Do **not** add fuzzy matching, heuristic coercion, or silent fallbacks just to be forgiving.

### 5. Keep response shapes stable

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

### 6. Hide backend quirks, not domain meaning

This server may bridge Snyk REST and Snyk API v1 where necessary.

That is good **only** when it simplifies the workflow for the caller.

Do not leak unnecessary transport or backend details into the MCP contract. But also do not flatten away important domain meaning just to look simple.

### 7. Prefer explicit workflow over magical convenience

This project intentionally favors a clear multi-step flow:

1. resolve org
2. discover target or project
3. list issues
4. fetch detail, paths, or analysis

That is better than a “smart” tool that guesses too much from partial input.

## Expected user workflow

A normal issue investigation flow looks like this:

1. `snyk_onboarding`
2. `snyk_resolve_org_id`
3. `snyk_get_targets`
4. target-scoped intake via `snyk_get_target_ledger_seed`, project-scoped intake via `snyk_get_project_ledger_seed`, or project discovery via `snyk_get_projects`
5. `snyk_get_project_issues`
6. one of:
   - `snyk_get_issue_detail`
   - `snyk_get_project_issue_paths`
   - `snyk_get_project_package_vulnerability_analysis`

New tools should fit this style: explicit, stepwise, and understandable without hidden state.

## Change rules for contributors and agents

When changing this repository, follow these rules.

### Add a new tool only if all of this is true

- it serves a real repeated workflow
- existing tools cannot express that workflow cleanly
- the new tool can have a narrow, obvious contract
- the output can stay stable and readable

If the change only saves one internal call but makes the public surface more confusing, do not add it.

### Prefer narrower parameters

Good:

- `orgId`
- `projectId`
- `restIssueId`
- `severity: "low" | "medium" | "high" | "critical"`

Bad:

- `id` when multiple ID types exist
- freeform filter blobs when a few explicit fields are enough
- parameters that mean different things in different modes

### Prefer clear errors over tolerant behavior

Good:

- “`restIssueId` must be a UUID”
- “`orgSlug` must match the exact Snyk org slug”
- “Provide `projectId` when requesting project issue paths”

Bad:

- accepting multiple unrelated identifier formats in the same field
- guessing whether an input is a slug, UUID, or display name
- silently defaulting to behavior the caller did not request

### Preserve naming consistency

If the public contract already uses a field name, keep using it.

Do not rename public fields casually. If a rename is truly necessary, treat it as a contract change and update documentation consistently.

### Keep docs operational

Tool descriptions and README examples should help an agent choose the correct next step quickly.

Prefer concrete wording like:

- what the tool requires
- what identifier it returns
- what the next likely tool is

## Implementation guidance

### Validation

- Validate inputs at the MCP boundary.
- Use strict schemas.
- Make error messages specific and actionable.

### Output modeling

- Return the most useful normalized data first.
- Include raw upstream payloads only when they materially help debugging or follow-up analysis.
- Do not make callers dig through raw payloads for the main answer.

### Internal helpers

- Keep helpers private unless they support a real shared need.
- Do not extract abstractions just to make code look more generic.
- Prefer straightforward code over framework-like internal architecture.

### Dependencies

- Add dependencies sparingly.
- A new dependency should remove meaningful complexity, not add indirection.

## Repository map

- `src/index.ts` — MCP server bootstrap and tool registration
- `src/tools/` — MCP tool definitions grouped by workflow
- `src/snyk/client.ts` — Snyk API access layer
- `src/utils/` — focused utilities, not a dumping ground
- `README.md` — user-facing usage and workflow documentation

## Non-goals

This project is not trying to be:

- a full Snyk SDK
- a generic Snyk query engine
- a compatibility layer for every possible input style
- a place for speculative abstraction

## Practical test for changes

Before merging a change, ask:

1. Does this make the MCP surface easier for an agent to understand?
2. Does it reduce ambiguity rather than hide it?
3. Is the input contract clearer, not looser?
4. Is the output more predictable, not more clever?
5. Would a new user understand the intended workflow from the tool names and docs alone?

If the answer is no, the change is probably too complex.
