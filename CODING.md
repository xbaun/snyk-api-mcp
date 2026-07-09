## Codebase Consistency

Do not blindly replicate patterns, structures, naming conventions, abstractions, or architectural decisions from other repositories, including website-monorepo.

Before introducing new code, evaluate how the surrounding code within the current codebase is structured and integrate consistently with local conventions.

Favor homogeneity over heterogeneity.

A solution that aligns with established patterns in the current codebase is generally preferable to introducing a new style, abstraction, naming scheme, or architectural variation solely for theoretical improvements.

Goals:
- Minimize fragmentation.
- Reduce redundant patterns.
- Preserve conceptual consistency.
- Improve predictability and maintainability.

When deciding between multiple valid implementations:

1. Prefer the solution that feels most natural within the existing codebase.
2. Prefer extending an existing pattern over introducing a competing one.
3. Prefer consistency over personal preference.
4. Prefer simplicity over cleverness.
5. Prefer proven local conventions over external inspiration.

Do not introduce abstractions, layers, utilities, or generic solutions unless there is a demonstrated need.

Apply:
- KISS (Keep It Simple, Stupid)
- YAGNI (You Aren't Gonna Need It)

A small amount of duplication is often preferable to premature abstraction.

The objective is not to maximize elegance in isolation, but to maximize coherence of the overall system.
`